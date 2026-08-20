"""
Relatório de APIs com pouca ou nenhuma utilização (APIM v4).

Script SOMENTE-LEITURA. Gera um CSV com uma linha por par (API, ambiente onde
está deployada), com a contagem de chamadas nas janelas de 7, 30 e 90 dias:

    apiId,apiName,apiUrl,environmentId,environmentName,qtdeChamadas7d,qtdeChamadas30d,qtdeChamadas90d

Ordenado por qtdeChamadas90d crescente, para que as APIs com menos uso
apareçam no topo.

## Fontes de dados (confirmadas empiricamente contra um tenant de testes)

1. Manager API (GET /apis + GET /apis/{id}) -- inventário de todas as APIs do
   tenant e, para cada uma, os ambientes reais onde está deployada
   (id, name, inboundUrl). O campo `environments` na LISTAGEM (/apis) vem
   sempre vazio; só o detalhe (/apis/{id}) traz os ambientes reais -- por
   isso o script faz 1 chamada de detalhe por API (com cache local em
   api_inventory.jsonl, reaproveitado entre execuções).

   IDs negativos em /apis (ex: -1 "API Manager", -2 "API Metrics") são APIs
   internas da plataforma, não do cliente -- são excluídas automaticamente.

   Deployments em environmentId -1 ("Internal Environment") também são
   excluídos, mesmo quando a API em si (apiId) é de cliente -- é um ambiente
   interno da plataforma, não um ambiente de cliente. Na teoria nenhum
   usuário comum consegue listar isso pela UI, mas o filtro fica por defesa
   em profundidade.

2. Sensedia Analytics API (POST /analytics/v1/products/api-gateway/calls/query)
   -- mesmo host e mesma autenticação (Sensedia-Auth/userId/XSRF) do Manager,
   mas o endpoint só responde (200) se o app do access-token tiver o plano
   "Sensedia Analytics API" associado, além do "API Manager Front" usual.
   Sem esse plano associado, a chamada devolve 401 com a MESMA mensagem de
   token inválido do Manager -- o que pode enganar (parece um problema de
   token, mas é de plano). Se você tomar esse 401, associe o plano ao app no
   Access Control antes de continuar (ver README.md).

   O endpoint expõe uma Query DSL do OpenSearch. Este script faz UMA única
   query de agregação (filters + terms aninhados por sensedia.api.id e
   sensedia.environment.id) cobrindo as três janelas de uma vez -- ao invés
   de somar contagens diárias via Manager API (abordagem descartada: exigiria
   1 chamada HTTP por dia por par API/ambiente, ~90x mais caro, e dois outros
   endpoints candidatos do Manager -- /calls e /metrics/calls -- não
   respeitavam nenhum filtro de data testado nesta investigação).

   Os buckets de agregação (`terms`) têm `size` alto (10000 para API, 100
   para ambiente) para evitar corte; o script verifica `sum_other_doc_count`
   e avisa se algum tenant realmente ultrapassar isso.

   Uma API/ambiente sem NENHUMA chamada no período não aparece na agregação
   (não existe documento para agregar) -- por isso a contagem final vem do
   LEFT JOIN entre o inventário (passo 1, sempre completo) e a agregação
   (passo 2, só cobre quem teve alguma chamada); ausência = 0.

   As janelas são calculadas em UTC via date math do OpenSearch
   (`now-Nd/d`, arredondado para início do dia), incluindo o dia de hoje
   (parcial) como parte da janela.

Resumível: o inventário de APIs (api_inventory.jsonl) é cacheado entre
execuções; use --refresh-inventory para forçar a rebusca completa.

Uso:
    python3 scripts/report_low_usage_apis.py --env-file .env
    python3 scripts/report_low_usage_apis.py --env-file .env --api-ids 123,456
    python3 scripts/report_low_usage_apis.py --env-file .env --limit 20   # smoke test do inventário
"""
import argparse
import csv
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
REPORT_FIELDS = [
    "apiId", "apiName", "apiUrl", "environmentId", "environmentName",
    "qtdeChamadas7d", "qtdeChamadas30d", "qtdeChamadas90d",
]

# APIs internas da plataforma observadas com id negativo neste tenant
# (ex: -1 "API Manager", -2 "API Metrics") -- nunca são APIs de cliente.
PLATFORM_INTERNAL_ID_THRESHOLD = 0

# environmentId -1 ("Internal Environment") é um ambiente interno da
# plataforma, não um ambiente de cliente -- deployments nele são excluídos
# do relatório mesmo que a API em si (apiId) seja de cliente (ex: uma API de
# cliente também pode ter uma cópia interna deployada aí). Na teoria nenhum
# usuário comum consegue listar isso pela UI, mas o filtro fica aqui por
# defesa em profundidade.
INTERNAL_ENVIRONMENT_ID = -1

ANALYTICS_PRODUCT = "api-gateway"
ANALYTICS_PATH = f"/v1/products/{ANALYTICS_PRODUCT}/calls/query"
WINDOWS = [("window_7d", "qtdeChamadas7d", 7), ("window_30d", "qtdeChamadas30d", 30), ("window_90d", "qtdeChamadas90d", 90)]
TERMS_SIZE_API = 10000
TERMS_SIZE_ENV = 100


def join_url(inbound_url, base_path):
    """Concatena inboundUrl + basePath sem duplicar/faltar a barra entre eles.
    Confirmado contra uma chamada real (campo http.url da Analytics API):
    inboundUrl='https://host/' + basePath='/x/y' -> 'https://host/x/y'."""
    inbound_url = (inbound_url or "").rstrip("/")
    base_path = "/" + (base_path or "").lstrip("/")
    return f"{inbound_url}{base_path}"


def load_inventory_cache(cache_file):
    cache = {}
    if not os.path.exists(cache_file):
        return cache
    with open(cache_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            cache[entry["id"]] = entry
    return cache


_inventory_write_lock = threading.Lock()


def append_inventory(cache_file, entry):
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    with _inventory_write_lock:
        with open(cache_file, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def fetch_apis_list(client):
    resp = client.get("/apis")
    if resp.status_code != 200:
        raise SystemExit(f"GET /apis falhou: HTTP {resp.status_code} - {resp.text[:300]}")
    apis = resp.json()
    if not isinstance(apis, list):
        raise SystemExit(f"GET /apis devolveu um formato inesperado (esperava uma lista): {str(apis)[:300]}")
    return apis


def fetch_api_detail(client, api_id):
    """Busca o detalhe de uma API e extrai só os campos usados no relatório
    (o payload completo inclui visibility/roles/permissions aninhados que não
    interessam aqui)."""
    resp = client.get(f"/apis/{api_id}")
    if resp.status_code != 200:
        return None, f"GET /apis/{api_id} falhou: HTTP {resp.status_code} - {resp.text[:300]}"
    detail = resp.json()
    environments = [
        {"id": e.get("id"), "name": e.get("name") or "", "inboundUrl": e.get("inboundUrl") or ""}
        for e in (detail.get("environments") or [])
        if e.get("id") is not None
    ]
    entry = {
        "id": detail.get("id"),
        "name": detail.get("name") or "",
        "basePath": detail.get("basePath") or "",
        "environments": environments,
    }
    return entry, None


def build_inventory(client, apis, cache_file, refresh, sleep_ms, concurrency, verbose):
    """Busca o detalhe (/apis/{id}) de cada API que ainda não está em cache,
    em paralelo (o gargalo é latência por chamada no servidor, não CPU local
    -- concorrência ajuda bastante; alguns segundos por chamada foram
    observados empiricamente contra um tenant de testes, então rodar
    sequencialmente para centenas de APIs pode levar dezenas de minutos)."""
    cache = {} if refresh else load_inventory_cache(cache_file)
    pending = [a for a in apis if a.get("id") not in cache]
    total_all = len(apis)
    total_pending = len(pending)
    print(
        f"  inventário: {total_all - total_pending}/{total_all} já em cache "
        f"(reaproveitado de execuções anteriores); buscando {total_pending} agora "
        f"(concorrência={concurrency})"
    )
    if not pending:
        return cache

    def task(api):
        if sleep_ms:
            time.sleep(sleep_ms / 1000)
        api_id = api.get("id")
        try:
            return fetch_api_detail(client, api_id)
        except Exception as e:  # noqa: BLE001 -- falha de rede em 1 API não pode derrubar o lote inteiro
            return None, f"GET /apis/{api_id} falhou: {e}"

    done = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(task, api): api for api in pending}
        for future in as_completed(futures):
            api = futures[future]
            api_id = api.get("id")
            entry, error = future.result()
            done += 1
            if error:
                print(f"aviso: {error} -- API ignorada no inventário")
                continue
            append_inventory(cache_file, entry)
            cache[api_id] = entry
            if verbose or done % 25 == 0 or done == total_pending:
                print(f"  inventário de APIs: {done}/{total_pending} buscadas nesta execução")
    return cache


def build_rows(apis, inventory):
    rows = []
    for api in apis:
        api_id = api.get("id")
        entry = inventory.get(api_id)
        if entry is None:
            continue
        for env in entry["environments"]:
            if env["id"] == INTERNAL_ENVIRONMENT_ID:
                continue
            rows.append({
                "apiId": api_id,
                "apiName": entry["name"],
                "apiUrl": join_url(env["inboundUrl"], entry["basePath"]),
                "environmentId": env["id"],
                "environmentName": env["name"],
            })
    return rows


def build_aggregation_query():
    windows_agg = {}
    for window_key, _, days in WINDOWS:
        windows_agg[window_key] = {
            "filter": {"range": {"@timestamp": {"gte": f"now-{days}d/d"}}},
            "aggs": {
                "by_api": {
                    "terms": {"field": "sensedia.api.id", "size": TERMS_SIZE_API},
                    "aggs": {
                        "by_env": {"terms": {"field": "sensedia.environment.id", "size": TERMS_SIZE_ENV}},
                    },
                },
            },
        }
    max_days = max(days for _, _, days in WINDOWS)
    return {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{max_days}d/d"}}},
        "aggs": windows_agg,
    }


def fetch_call_counts(client):
    """Faz a query de agregação única na Analytics API e devolve
    counts[field][(apiId, environmentId)] = qtde de chamadas na janela."""
    body = build_aggregation_query()
    resp = client.post_analytics(ANALYTICS_PATH, json=body)
    if resp.status_code != 200:
        hint = ""
        if resp.status_code == 401:
            hint = (
                "\nDica: esse 401 pode ser porque o app do access-token não tem o plano "
                "\"Sensedia Analytics API\" associado (além do \"API Manager Front\" usual) -- "
                "ver README.md."
            )
        raise SystemExit(
            f"POST {ANALYTICS_PATH} falhou: HTTP {resp.status_code} - {resp.text[:400]}{hint}"
        )
    data = resp.json()

    counts = {}
    for window_key, field, _ in WINDOWS:
        window_counts = {}
        by_api = data.get("aggregations", {}).get(window_key, {}).get("by_api", {})
        if by_api.get("sum_other_doc_count"):
            print(
                f"aviso: agregação por API truncada em {window_key} "
                f"(sum_other_doc_count={by_api['sum_other_doc_count']}) -- aumente TERMS_SIZE_API"
            )
        for api_bucket in by_api.get("buckets", []):
            api_id = api_bucket["key"]
            by_env = api_bucket.get("by_env", {})
            if by_env.get("sum_other_doc_count"):
                print(
                    f"aviso: agregação por ambiente truncada em {window_key} para apiId={api_id} "
                    f"(sum_other_doc_count={by_env['sum_other_doc_count']}) -- aumente TERMS_SIZE_ENV"
                )
            for env_bucket in by_env.get("buckets", []):
                window_counts[(api_id, env_bucket["key"])] = env_bucket["doc_count"]
        counts[field] = window_counts
    return counts


def write_csv(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in REPORT_FIELDS})


def parse_id_list(raw):
    if not raw:
        return None
    return {int(chunk.strip()) for chunk in raw.split(",") if chunk.strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--output-dir", default=os.path.join(ROOT, "output"))
    parser.add_argument("--api-ids", default=None, help="restringe o inventário a estes apiIds (separados por vírgula)")
    parser.add_argument("--limit", type=int, default=None, help="processa só as N primeiras APIs do inventário -- útil para smoke test")
    parser.add_argument("--refresh-inventory", action="store_true", help="ignora o cache de inventário (api_inventory.jsonl) e rebusca /apis/{id} para todas as APIs")
    parser.add_argument("--concurrency", type=int, default=8, help="chamadas HTTP concorrentes na montagem do inventário (GET /apis/{id}) -- padrão: 8")
    parser.add_argument("--sleep-ms", type=int, default=20, help="pausa por chamada dentro de cada worker, em milissegundos (padrão: 20)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    inventory_cache_file = os.path.join(args.output_dir, "api_inventory.jsonl")
    report_file = os.path.join(args.output_dir, "report.csv")
    wanted_api_ids = parse_id_list(args.api_ids)

    client = ApiClient(args.env_file, verbose=args.verbose)

    print("Listando APIs do tenant...")
    apis = fetch_apis_list(client)
    apis = [a for a in apis if (a.get("id") or 0) > PLATFORM_INTERNAL_ID_THRESHOLD]
    if wanted_api_ids is not None:
        apis = [a for a in apis if a.get("id") in wanted_api_ids]
    if args.limit:
        apis = apis[: args.limit]
    print(f"APIs de cliente a considerar: {len(apis)}")

    print("Montando inventário de ambientes por API (GET /apis/{id})...")
    inventory = build_inventory(
        client, apis, inventory_cache_file, args.refresh_inventory,
        args.sleep_ms, args.concurrency, args.verbose,
    )

    rows = build_rows(apis, inventory)
    print(f"Pares (API, ambiente) encontrados: {len(rows)}")

    print(f"Consultando contagem de chamadas na Analytics API ({ANALYTICS_PATH})...")
    counts = fetch_call_counts(client)

    for row in rows:
        key = (row["apiId"], row["environmentId"])
        for _, field, _ in WINDOWS:
            row[field] = counts[field].get(key, 0)

    rows.sort(key=lambda r: r["qtdeChamadas90d"])
    write_csv(report_file, rows)

    zero_90d = sum(1 for r in rows if r["qtdeChamadas90d"] == 0)
    print(f"\n{zero_90d}/{len(rows)} par(es) API/ambiente sem NENHUMA chamada nos últimos 90 dias.")
    print(f"Relatório completo em: {report_file}")


if __name__ == "__main__":
    main()
