#!/usr/bin/env python3
"""
Identificacao de variaveis de ambiente nao utilizadas (API Manager v5).

Script SOMENTE-LEITURA e AUTOSSUFICIENTE. Nao depende de nenhuma lista externa
de candidatas: ele proprio descobre todos os ambientes e todas as variaveis do
tenant, e classifica cada uma como em uso ou sem uso, cruzando com:

  1. Interceptors JavaScript (embutidos em revisions e custom-interceptors
     reutilizaveis), procurando o padrao  $call.environmentVariables.get('CHAVE')
  2. destination (URLs) de componentes REVISION/RESOURCE/OPERATION de cada
     revision, procurando o padrao  $CHAVE

A API do api-manager v5 (validateVariableInUseConnector) so bloqueia a
exclusao de uma variavel se ela estiver em uso por um Connector -- nao cobre
uso via interceptor ou destination. Esta identificacao existe para cobrir essa
lacuna antes que o script de exclusao (script irmao deste, no mesmo
repositorio) exclua qualquer variavel.

Saida (em --output-dir):
  - confirmado_seguro_deletar.csv     -> variaveis sem nenhuma referencia
    encontrada. E o input do script de exclusao.
  - identificacao_variaveis_report.csv -> uma linha por variavel encontrada em
    qualquer ambiente varrido, com o status (em uso / sem uso) e a evidencia
    do uso quando houver.
  - duplicidade_variaveis.csv          -> variaveis com a mesma key aparecendo
    mais de uma vez no mesmo ambiente.

LIMITACAO IMPORTANTE: interceptors customizados em JAVA nao fazem parte desta
varredura automatica (so JS). Ver README.md.

Uso basico:
    python3 identify_unused_variables.py
    python3 identify_unused_variables.py --environment-ids 6,7,10,12,14
    python3 identify_unused_variables.py --verbose

Veja o README.md para o passo a passo completo (credenciais, .env, como ler
os relatorios gerados).
"""
import argparse
import csv
import hashlib
import os
import re
import sys
import time

try:
    import requests
except ImportError:
    sys.exit(
        "Falta a biblioteca 'requests'. Instale as dependencias primeiro:\n"
        "    pip install -r requirements.txt"
    )

ROOT = os.path.dirname(os.path.abspath(__file__))
REQUEST_TIMEOUT = 60

# Colunas do CSV final -- mesmo formato esperado pelo script de exclusao.
OUTPUT_COLUMNS = [
    "environmentId", "environmentName", "mapId", "mapName",
    "variableId", "variableKey", "classification",
]
REPORT_FIELDS = OUTPUT_COLUMNS + ["status", "evidence", "timestamp"]
DUPLICATE_FIELDS = ["environmentId", "environmentName", "variableKey", "occurrences", "locations"]
# 'valueFingerprint' e um hash curto do valor, NUNCA o valor em si -- ver
# find_duplicate_values() e a flag --check-duplicate-values.
VALUE_DUPLICATE_FIELDS = ["environmentId", "environmentName", "valueFingerprint", "occurrences", "keys", "locations"]

# Status finais de uma variavel nesta identificacao.
STATUS_SAFE = "confirmado_seguro_para_deletar"
STATUS_STILL_USED_INTERCEPTOR = "ainda_usada_interceptor_js"
STATUS_STILL_USED_DESTINATION = "ainda_usada_destination"

# Valor gravado na coluna 'classification' das variaveis sem uso -- mesma
# convencao usada na analise manual original que precedeu este script.
CLASSIFICATION_UNUSED = "nao_usada"

# Padrao de uso em interceptors JavaScript: $call.environmentVariables.get('CHAVE')
INTERCEPTOR_RE = re.compile(r"\$call\.environmentVariables\.get\(\s*['\"]([^'\"]+)['\"]\s*\)")
# Padrao de uso em destination: $CHAVE
DESTINATION_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_.\-]*)")


def load_dotenv(path):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            env[key.strip()] = value
    return env


def load_config(env_path):
    # BASE_URL e TOKEN_URL ja vem com o default documentado para tenants v5
    # padrao (platform-production.sensedia.com) em .env.example -- so
    # CLIENT_ID/CLIENT_SECRET sao obrigatoriamente preenchidos pelo cliente.
    env = dict(os.environ)
    env.update(load_dotenv(env_path))
    required = ["BASE_URL", "TOKEN_URL", "CLIENT_ID", "CLIENT_SECRET"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise SystemExit(
            f"Configuracao incompleta em '{env_path}': faltam ou nao foram preenchidos "
            f"{', '.join(missing)}. Copie .env.example para .env e preencha os valores "
            "do seu tenant antes de rodar o script."
        )
    # Escopo do token OAuth2 -- confirmado empiricamente que 'apis/all' e o
    # escopo retornado/aceito pelo endpoint de Credencial de Seguranca.
    env.setdefault("SCOPE", "apis/all")
    return env


class AuthError(Exception):
    pass


class ApiClient:
    """Cliente OAuth2 client_credentials para a API Manager v5, somente leitura
    (usa apenas GET). Autentica via Credencial de Seguranca (endpoint
    /user-management/v1/oauth2/token -- ver README.md secao 2). Renova o
    token automaticamente perto do vencimento ou se uma chamada devolver 401."""

    def __init__(self, cfg, verbose=False):
        self.cfg = cfg
        self.base_url = cfg["BASE_URL"].rstrip("/")
        self.verbose = verbose
        self._token = None
        self._token_expires_at = 0
        self._refresh_token()

    def _refresh_token(self):
        auth = (self.cfg["CLIENT_ID"], self.cfg["CLIENT_SECRET"])
        payload = {"grantType": "client_credentials", "scope": self.cfg["SCOPE"]}

        try:
            resp = requests.post(
                self.cfg["TOKEN_URL"], json=payload, auth=auth, timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
        except requests.exceptions.RequestException as e:
            raise AuthError(f"Falha de rede ao gerar o token em TOKEN_URL: {e}")

        if resp.status_code == 401:
            raise AuthError(
                f"Falha ao gerar token OAuth2 (401): {resp.text[:400]}\n"
                "O endpoint de token rejeitou a credencial (CLIENT_ID/CLIENT_SECRET). Cheque:\n"
                "  1. Se TOKEN_URL aponta para o endpoint de Credencial de Seguranca "
                "(/user-management/v1/oauth2/token) e nao para o endpoint antigo de Client App "
                "(/access-control/api/v1/oauth2/token) -- sao registros diferentes, uma credencial "
                "de um nao e reconhecida pelo endpoint do outro.\n"
                "  2. Se CLIENT_ID/CLIENT_SECRET foram copiados exatamente (sem espacos/quebras "
                "de linha) -- o Client Secret so e exibido uma vez, erro de copia e a causa mais comum.\n"
                "  3. Se essa credencial ainda aparece ativa em My Account Settings -> Credentials.\n"
                "  4. Se persistir, revogue e gere uma credencial nova."
            )
        if resp.status_code != 200:
            raise AuthError(
                f"Falha ao gerar token OAuth2 ({resp.status_code}): {resp.text[:400]}\n"
                "Verifique TOKEN_URL, CLIENT_ID e CLIENT_SECRET no .env."
            )
        try:
            body = resp.json()
            token = body["access_token"]
        except (ValueError, KeyError):
            raise AuthError(
                f"Resposta do TOKEN_URL nao trouxe 'access_token' em JSON: {resp.text[:400]}"
            )

        # expires_in vem como string ("86400") na resposta deste endpoint.
        expires_in = int(body.get("expires_in", 86400))
        self._token = token
        self._token_expires_at = time.time() + max(expires_in - 300, 60)
        if self.verbose:
            print(f"[verbose] token OAuth2 renovado, expira em ~{expires_in}s")

    def _ensure_token(self):
        if time.time() >= self._token_expires_at:
            self._refresh_token()

    def _headers(self):
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    # Erros 5xx entre servicos do backend (ex: CommunicationException ao
    # falar com o Access Control) podem ser intermitentes -- tenta de novo
    # algumas vezes com backoff exponencial antes de desistir.
    MAX_5XX_RETRIES = 3
    RETRY_BACKOFF_SECONDS = 1.0

    def get(self, path, params=None):
        self._ensure_token()
        reauthenticated = False
        attempt_5xx = 0
        while True:
            resp = requests.get(
                f"{self.base_url}{path}", headers=self._headers(), params=params,
                timeout=REQUEST_TIMEOUT,
            )
            if self.verbose:
                print(f"[verbose] GET {path} params={params} -> {resp.status_code}")

            if resp.status_code == 401 and not reauthenticated:
                reauthenticated = True
                self._refresh_token()
                continue

            if 500 <= resp.status_code < 600 and attempt_5xx < self.MAX_5XX_RETRIES:
                attempt_5xx += 1
                wait = self.RETRY_BACKOFF_SECONDS * (2 ** (attempt_5xx - 1))
                print(
                    f"aviso: {path} respondeu HTTP {resp.status_code} -- tentativa "
                    f"{attempt_5xx}/{self.MAX_5XX_RETRIES}, nova tentativa em {wait:.0f}s "
                    f"(pode ser comunicacao intermitente entre servicos do backend: "
                    f"{resp.text[:200]})"
                )
                time.sleep(wait)
                continue

            return resp


def paginated_get(client, path, list_keys=("content", "items", "data", "results"),
                   page_size=100, max_pages=2000, verbose=False, label=""):
    """Percorre um endpoint paginado da API Manager v5 e devolve todos os itens.

    A API expoe paginacao via 'actualPage'/'pageSize'. Aceita tanto uma
    resposta que e diretamente uma lista quanto uma resposta embrulhada num
    dos campos em list_keys. Se a forma da resposta nao puder ser reconhecida,
    falha alto (SystemExit) em vez de seguir silenciosamente com uma lista
    vazia -- um scan vazio por engano marcaria variaveis em uso como
    "seguras para deletar", o que e inaceitavel aqui.
    """
    items = []
    page = 1
    while page <= max_pages:
        resp = client.get(path, params={"actualPage": page, "pageSize": page_size})
        if resp.status_code != 200:
            raise SystemExit(
                f"Falha ao listar '{label or path}' (pagina {page}): "
                f"HTTP {resp.status_code} - {resp.text[:300]}"
            )
        body = resp.json()
        if isinstance(body, list):
            page_items = body
            items.extend(page_items)
            break  # resposta nao paginada, ja veio tudo de uma vez
        if isinstance(body, dict):
            page_items = None
            for k in list_keys:
                if isinstance(body.get(k), list):
                    page_items = body[k]
                    break
            if page_items is None:
                raise SystemExit(
                    f"Nao foi possivel reconhecer o formato de paginacao de '{label or path}'. "
                    f"Resposta recebida: {str(body)[:300]}. "
                    "Ajuste 'list_keys' em paginated_get() para o formato real da sua instalacao."
                )
            items.extend(page_items)
            if len(page_items) < page_size:
                break
            page += 1
            continue
        raise SystemExit(
            f"Resposta inesperada (nem lista nem objeto) ao listar '{label or path}': {str(body)[:300]}"
        )
    if verbose:
        print(f"[verbose] {label or path}: {len(items)} item(ns) em {page} pagina(s)")
    return items


def walk_strings(obj, path=""):
    """Percorre recursivamente um JSON (dict/list) e devolve (path, texto)
    para cada valor string encontrado. Nao assumimos nomes de campo -- a API
    Manager v5 nao documenta em detalhe o formato interno de destination/
    interceptor, entao escanear todo texto do payload e a forma mais segura
    de nao deixar passar um uso real por causa de um nome de campo errado."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub_path = f"{path}.{k}" if path else str(k)
            for item in walk_strings(v, sub_path):
                yield item
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            sub_path = f"{path}[{i}]"
            for item in walk_strings(v, sub_path):
                yield item
    elif isinstance(obj, str) and obj:
        yield path, obj


def scan_json_for_usage(obj, source_label, env_id, interceptor_hits, destination_hits):
    """Escaneia um JSON (revision detail ou custom-interceptor detail) e
    registra toda ocorrencia dos dois padroes de uso. env_id=None significa
    'aplica-se a qualquer ambiente' (fallback conservador quando nao foi
    possivel identificar a qual ambiente aquele objeto pertence)."""
    for path, text in walk_strings(obj):
        for m in INTERCEPTOR_RE.finditer(text):
            key = m.group(1)
            interceptor_hits.setdefault(key, []).append(
                (env_id, f"{source_label} campo={path}")
            )
        for m in DESTINATION_RE.finditer(text):
            key = m.group(1)
            trecho = text if len(text) <= 120 else text[:117] + "..."
            destination_hits.setdefault(key, []).append(
                (env_id, f"{source_label} campo={path} trecho={trecho!r}")
            )


def extract_deployed_environment_ids(revision_detail):
    """Identifica em quais ambientes esta revision esta deployada.

    Confirmado empiricamente (2026-07-30): a revision NAO carrega o
    environmentId diretamente. Em vez disso, o detalhe completo da revision
    inclui um campo 'api' com 'api.environments[]' -- cada ambiente da API
    tem um 'revisionDeployed' apontando para a revision atualmente deployada
    nele. Cruzamos revisionDeployed.revisionId com o id desta revision para
    saber em quais ambientes ela esta ativa (pode ser mais de um, ou nenhum
    se for uma revision nao deployada/rascunho).

    Devolve um set de environmentIds; vazio se nao deployada em nenhum --
    nesse caso o chamador trata como 'uso em qualquer ambiente' (env_id=None),
    por seguranca."""
    rev_id = revision_detail.get("id")
    api = revision_detail.get("api") or {}
    env_ids = set()
    for env in api.get("environments") or []:
        deployed = env.get("revisionDeployed") or {}
        if deployed.get("revisionId") == rev_id and env.get("id") is not None:
            env_ids.add(env["id"])
    return env_ids


def scan_tenant_usage(client, sleep_ms, verbose, allow_empty_scan):
    """Varre todas as APIs/revisions e custom-interceptors do tenant, montando
    os indices de uso (por interceptor JS e por destination)."""
    interceptor_hits = {}
    destination_hits = {}

    apis = paginated_get(client, "/apis", verbose=verbose, label="/apis")
    if not apis and not allow_empty_scan:
        raise SystemExit(
            "GET /apis nao retornou nenhuma API neste tenant. Isso normalmente indica um "
            "problema de credenciais/permissoes ou de conectividade, nao um tenant "
            "genuinamente vazio -- prosseguir geraria um CSV 'seguro para deletar' baseado "
            "num scan de uso vazio, o que e perigoso. Se voce tem certeza de que o tenant "
            "realmente nao tem nenhuma API, rode novamente com --allow-empty-scan."
        )
    print(f"APIs encontradas no tenant: {len(apis)}")

    total_revisions = 0
    for i, api in enumerate(apis, start=1):
        api_id = api.get("id")
        if api_id is None:
            continue

        resp = client.get(f"/apis/{api_id}/revisions")
        if resp.status_code != 200:
            print(
                f"aviso: GET /apis/{api_id}/revisions falhou ({resp.status_code}) "
                "-- API ignorada na varredura de uso"
            )
            continue
        body = resp.json()
        # Confirmado empiricamente (2026-07-30): este endpoint devolve o
        # objeto UNICO da revision atual (nao uma lista), ja com
        # destination/interceptors completos -- diferente do que a
        # documentacao publica da API sugere. Aceita tambem uma lista, para o
        # caso de outras instalacoes/versoes devolverem multiplas revisions.
        revision_stubs = body if isinstance(body, list) else [body] if isinstance(body, dict) else []

        for stub in revision_stubs:
            rev_id = stub.get("id")
            if rev_id is None:
                continue
            # Se o item ja veio com o detalhe completo (resources/interceptors
            # presentes), usa direto -- evita uma segunda chamada por revision.
            if "resources" in stub or "interceptors" in stub:
                detail = stub
            else:
                detail_resp = client.get(f"/revisions/{rev_id}")
                if detail_resp.status_code != 200:
                    print(
                        f"aviso: GET /revisions/{rev_id} (api={api_id}) falhou "
                        f"({detail_resp.status_code}) -- revision ignorada na varredura de uso"
                    )
                    continue
                detail = detail_resp.json()

            env_ids = extract_deployed_environment_ids(detail) or {None}
            for env_id in env_ids:
                scan_json_for_usage(
                    detail, f"api={api_id} revision={rev_id}", env_id,
                    interceptor_hits, destination_hits,
                )
            total_revisions += 1
            if sleep_ms:
                time.sleep(sleep_ms / 1000)
        if verbose or i % 25 == 0 or i == len(apis):
            print(f"  varredura de APIs: {i}/{len(apis)} (revisions ate agora: {total_revisions})")

    custom_interceptors = paginated_get(
        client, "/custom-interceptors", verbose=verbose, label="/custom-interceptors",
    )
    print(f"Custom interceptors encontrados no tenant: {len(custom_interceptors)}")
    for ci in custom_interceptors:
        ci_id = ci.get("id")
        if ci_id is None:
            continue
        resp = client.get(f"/custom-interceptors/{ci_id}")
        if resp.status_code != 200:
            print(
                f"aviso: GET /custom-interceptors/{ci_id} falhou ({resp.status_code}) "
                "-- interceptor ignorado na varredura de uso"
            )
            continue
        detail = resp.json()
        # custom interceptors sao reutilizaveis entre APIs -> tratado como uso
        # em qualquer ambiente (env_id=None), por seguranca.
        scan_json_for_usage(detail, f"custom-interceptor={ci_id}", None, interceptor_hits, destination_hits)
        if sleep_ms:
            time.sleep(sleep_ms / 1000)

    return interceptor_hits, destination_hits, len(apis), total_revisions, len(custom_interceptors)


def hits_for(key, env_id, hits):
    return [ev for (e, ev) in hits.get(key, []) if e is None or e == env_id]


def fetch_all_environments(client, verbose):
    """Lista todos os ambientes do tenant via GET /environments (paginado)."""
    items = paginated_get(client, "/environments", verbose=verbose, label="/environments")
    environments = []
    for it in items:
        eid = it.get("id")
        if eid is None:
            continue
        environments.append({"id": int(eid), "name": it.get("name") or ""})
    return environments


def resolve_map_name(map_obj):
    """A API Manager v5 nao documenta o campo exato do nome do map dentro de
    mapVars[] -- tenta os nomes mais comuns antes de cair num fallback legivel."""
    for field in ("name", "mapName", "label"):
        value = map_obj.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return f"map-{map_obj.get('id')}"


def build_variable_rows(environment, env_id, env_name):
    """Enumera todas as variaveis de um ambiente a partir do seu detalhe
    completo (mapVars[].vars[]), sem depender de nenhuma lista externa."""
    rows = []
    for m in environment.get("mapVars") or []:
        map_id = m.get("id")
        map_name = resolve_map_name(m)
        for v in m.get("vars") or []:
            var_id = v.get("id")
            key = v.get("key")
            if var_id is None or key is None:
                continue
            rows.append({
                "environmentId": env_id,
                "environmentName": env_name,
                "mapId": map_id,
                "mapName": map_name,
                "variableId": var_id,
                "variableKey": key,
            })
    return rows


def find_duplicate_keys(environment):
    """Agrupa todas as variaveis do ambiente por key; devolve so as keys que
    aparecem mais de uma vez (em qualquer map)."""
    seen = {}
    for m in environment.get("mapVars") or []:
        for v in m.get("vars") or []:
            key = v.get("key")
            if key is None:
                continue
            seen.setdefault(key, []).append((m.get("id"), v.get("id")))
    return {k: locs for k, locs in seen.items() if len(locs) > 1}


def looks_masked(value):
    """Heuristica para valores que parecem ter vindo mascarados (nao o
    segredo real) numa resposta de GET -- mesma logica usada no script de
    exclusao (script irmao deste) para variaveis SECURED."""
    if value is None or value == "":
        return True
    if set(value) <= {"*", "•", "x", "X"}:
        return True
    return False


def value_fingerprint(value):
    """Hash curto e nao reversivel do valor, usado so para agrupar
    ocorrencias no relatorio -- o valor real nunca e escrito em disco."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def find_duplicate_values(environment):
    """Agrupa variaveis do ambiente por VALOR (nao por key), para achar
    chaves DISTINTAS que compartilham o mesmo valor -- candidatas a
    consolidacao manual, NUNCA a exclusao direta: qualquer API ainda pode
    depender especificamente de uma das chaves duplicadas, e so seria seguro
    remover uma delas depois de ajustar quem a usa para apontar para a outra.

    Exclui variaveis SECURED e valores que parecam mascarados (looks_masked)
    -- caso contrario, varios segredos reais e diferentes que a API devolve
    mascarados (ex: todos como '***') apareceriam como 'o mesmo valor' por
    engano, gerando falso positivo em massa.

    So conta como duplicidade de valor quando ha mais de uma KEY DISTINTA
    envolvida -- a mesma key repetida com o mesmo valor em mais de um map ja
    e coberta por find_duplicate_keys(), e listar aqui de novo seria ruido."""
    seen = {}
    for m in environment.get("mapVars") or []:
        for v in m.get("vars") or []:
            key = v.get("key")
            value = v.get("value")
            if key is None or v.get("variableType") == "SECURED" or looks_masked(value):
                continue
            seen.setdefault(value, []).append((m.get("id"), v.get("id"), key))
    return {
        value: locs for value, locs in seen.items()
        if len({key for _, _, key in locs}) > 1
    }


def classify_variable(env_id, key, interceptor_hits, destination_hits):
    interceptor_evidence = hits_for(key, env_id, interceptor_hits)
    if interceptor_evidence:
        return STATUS_STILL_USED_INTERCEPTOR, "; ".join(interceptor_evidence[:3])

    destination_evidence = hits_for(key, env_id, destination_hits)
    if destination_evidence:
        return STATUS_STILL_USED_DESTINATION, "; ".join(destination_evidence[:3])

    return STATUS_SAFE, ""


def write_csv(path, fieldnames, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def parse_environment_ids(raw):
    if not raw:
        return None
    ids = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        ids.add(int(chunk))
    return ids


# Endpoints minimos para diagnosticar rapidamente qual parte da API esta
# acessivel com as credenciais atuais, sem rodar a varredura completa (que
# pode demorar minutos e falhar tarde caso so um endpoint esteja com
# problema). Inclui endpoints de controle que normalmente funcionam (para
# provar que as credenciais/conectividade em si estao OK) junto com os dois
# usados na varredura de uso que ja se mostraram problematicos em testes
# reais (/apis e /custom-interceptors -- ver README.md, secao de solucao de
# problemas).
PROBE_ENDPOINTS = ["/environments", "/variables/values", "/apps", "/apis", "/custom-interceptors"]

# Endpoints cuja falha isolada (com os demais respondendo 200) aponta para
# uma causa raiz conhecida e ja diagnosticada (ver README.md), nao um
# problema geral de credenciais -- confirmado empiricamente em testes reais:
# /environments, /variables/values e /apps funcionam normalmente com o
# mesmo Client ID que falha nestes dois.
KNOWN_PROBLEMATIC_ENDPOINTS = {"/apis", "/custom-interceptors"}


def probe_endpoints(client):
    """Testa cada endpoint principal uma unica vez (pageSize=1) e imprime o
    resultado -- usado para descobrir se uma falha e especifica de um
    endpoint (ex: permissao/escopo do Client ID para aquele recurso) ou
    generalizada (ex: problema de credenciais/conectividade que afeta tudo).
    Nunca imprime o corpo de uma resposta 200 (endpoints como
    /variables/values retornam valores reais de variaveis, inclusive
    potencialmente sensiveis)."""
    print("Testando conectividade com os principais endpoints (uma chamada cada, sem a varredura completa)...\n")
    results = {}
    for path in PROBE_ENDPOINTS:
        resp = client.get(path, params={"actualPage": 1, "pageSize": 1})
        results[path] = resp.status_code
        print(f"{path:<25} -> HTTP {resp.status_code}")
        if resp.status_code != 200:
            print(f"    corpo: {resp.text[:300]}")
    print()
    ok = [p for p, s in results.items() if s == 200]
    failed = [p for p, s in results.items() if s != 200]
    if not failed:
        print("Todos os endpoints testados responderam 200 -- conectividade OK.")
    elif ok and set(failed) <= KNOWN_PROBLEMATIC_ENDPOINTS:
        print(
            f"Endpoint(s) com falha: {failed}. Como {ok} respondeu(ram) 200 com o MESMO Client ID, "
            "isso descarta um problema geral de credenciais/conectividade. Esta e uma causa raiz "
            "conhecida: um token OAuth2 client_credentials gerado como Client App (Account "
            "Settings -> Credentials) nao tem usuario associado, e o api-manager exige um "
            "usuario para resolver grupos/RBAC nesses dois endpoints especificos -- NAO e um "
            "problema de escopo/permissao ajustavel no Access Control. Solucao: gere uma "
            "Credencial de Seguranca (My Account Settings -> Credentials, usuario Super Admin "
            "sem SSO/MFA) e use esse Client ID/Secret no .env. Ver README.md secao 2 e "
            "docs.sensedia.com/pt-BR/docs/access-control/users/security-credentials."
        )
    elif failed and ok:
        print(
            f"Endpoint(s) com falha: {failed}. Como {ok} respondeu(ram) 200, o problema parece "
            "ser especifico desse(s) endpoint(s) -- provavel falta de permissao/escopo do Client ID "
            "para esse recurso especifico (confirme com o Super Admin que gerou as credenciais)."
        )
    else:
        print(
            f"Todos os endpoints testados falharam: {failed}. Isso sugere um problema mais amplo "
            "(credenciais sem nenhuma permissao, ou uma instabilidade generalizada do backend) -- "
            "vale contatar o suporte Sensedia com esse resultado."
        )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", default=os.path.join(ROOT, ".env"))
    parser.add_argument("--output-dir", default=os.path.join(ROOT, "output"))
    parser.add_argument(
        "--environment-ids", default=None,
        help="restringe a identificacao a estes environmentIds (separados por virgula, ex: 6,7,10,12,14). "
             "Por padrao, mapeia TODOS os ambientes do tenant.",
    )
    parser.add_argument("--sleep-ms", type=int, default=100, help="pausa entre chamadas HTTP na varredura, em milissegundos (padrao: 100)")
    parser.add_argument(
        "--allow-empty-scan", action="store_true",
        help="permite prosseguir mesmo se GET /apis nao retornar nenhuma API (normalmente indica erro de credenciais/permissao, nao um tenant vazio)",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--probe", action="store_true",
        help="so testa a conectividade com os endpoints principais (uma chamada cada) e sai -- "
             "nao roda a identificacao completa. Util para diagnosticar erros HTTP antes de "
             "rodar a varredura inteira.",
    )
    parser.add_argument(
        "--check-duplicate-values", action="store_true",
        help="alem de tudo, gera duplicidade_valores.csv: chaves DISTINTAS que compartilham o "
             "mesmo valor no mesmo ambiente. NAO sao candidatas a exclusao (uma API ainda pode "
             "depender especificamente de uma delas) -- servem so para apontar oportunidades de "
             "consolidacao manual. Desligado por padrao porque envolve ler valores de variaveis "
             "(o resto do script nunca le 'value'); o valor real nunca e escrito no relatorio, so "
             "um hash para agrupamento.",
    )
    args = parser.parse_args()

    cfg = load_config(args.env_file)
    wanted_env_ids = parse_environment_ids(args.environment_ids)

    try:
        client = ApiClient(cfg, verbose=args.verbose)
    except AuthError as e:
        raise SystemExit(str(e))

    if args.probe:
        probe_endpoints(client)
        return

    print("Varrendo APIs/revisions/custom-interceptors do tenant (pode demorar)...")
    interceptor_hits, destination_hits, n_apis, n_revisions, n_custom = scan_tenant_usage(
        client, args.sleep_ms, args.verbose, args.allow_empty_scan,
    )
    print(
        f"Varredura concluida: {n_apis} API(s), {n_revisions} revision(s), "
        f"{n_custom} custom-interceptor(s). "
        f"{len(interceptor_hits)} chave(s) distinta(s) referenciadas via interceptor, "
        f"{len(destination_hits)} via destination."
    )

    print("Listando ambientes do tenant...")
    environments = fetch_all_environments(client, args.verbose)
    if wanted_env_ids is not None:
        found_ids = {e["id"] for e in environments}
        missing = wanted_env_ids - found_ids
        if missing:
            print(f"aviso: environmentId(s) informados em --environment-ids nao encontrados no tenant: {sorted(missing)}")
        environments = [e for e in environments if e["id"] in wanted_env_ids]
    if not environments:
        raise SystemExit(
            "Nenhum ambiente para identificar (tenant sem ambientes, ou nenhum dos "
            "--environment-ids informados foi encontrado)."
        )
    print(f"Ambientes a identificar: {len(environments)}")

    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    report_rows = []
    duplicate_rows = []
    value_duplicate_rows = []
    for i, env in enumerate(environments, start=1):
        env_id = env["id"]
        resp = client.get(f"/environments/{env_id}")
        if resp.status_code != 200:
            print(f"aviso: GET /environments/{env_id} falhou ({resp.status_code}) -- ambiente ignorado na identificacao")
            continue
        detail = resp.json()
        env_name = detail.get("name") or env["name"] or str(env_id)

        for row in build_variable_rows(detail, env_id, env_name):
            status, evidence = classify_variable(env_id, row["variableKey"], interceptor_hits, destination_hits)
            row["classification"] = CLASSIFICATION_UNUSED if status == STATUS_SAFE else ""
            row["status"] = status
            row["evidence"] = evidence
            row["timestamp"] = ts
            report_rows.append(row)

        for key, locs in sorted(find_duplicate_keys(detail).items()):
            duplicate_rows.append({
                "environmentId": env_id,
                "environmentName": env_name,
                "variableKey": key,
                "occurrences": len(locs),
                "locations": "; ".join(f"map={m}:var={v}" for m, v in locs),
            })

        if args.check_duplicate_values:
            for value, locs in find_duplicate_values(detail).items():
                distinct_keys = sorted({key for _, _, key in locs})
                value_duplicate_rows.append({
                    "environmentId": env_id,
                    "environmentName": env_name,
                    "valueFingerprint": value_fingerprint(value),
                    "occurrences": len(locs),
                    "keys": "; ".join(distinct_keys),
                    "locations": "; ".join(f"map={m}:var={v}:key={k}" for m, v, k in locs),
                })

        if args.verbose or i % 10 == 0 or i == len(environments):
            print(f"  identificacao de ambientes: {i}/{len(environments)} (variaveis ate agora: {len(report_rows)})")
        if i < len(environments) and args.sleep_ms:
            time.sleep(args.sleep_ms / 1000)

    counts = {}
    for row in report_rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    safe_rows = [r for r in report_rows if r["status"] == STATUS_SAFE]

    report_file = os.path.join(args.output_dir, "identificacao_variaveis_report.csv")
    safe_file = os.path.join(args.output_dir, "confirmado_seguro_deletar.csv")
    duplicates_file = os.path.join(args.output_dir, "duplicidade_variaveis.csv")

    write_csv(report_file, REPORT_FIELDS, report_rows)
    write_csv(safe_file, OUTPUT_COLUMNS, safe_rows)
    write_csv(duplicates_file, DUPLICATE_FIELDS, duplicate_rows)

    print("\nResumo desta identificacao:", counts)
    print(f"{len(safe_rows)}/{len(report_rows)} variavel(is) sem uso confirmado, de {len(environments)} ambiente(s) identificado(s).")
    print(f"{len(duplicate_rows)} chave(s) duplicada(s) encontradas nos ambientes identificados.")
    print(f"\nRelatorio completo: {report_file}")
    print(f"CSV para o script de exclusao: {safe_file}")
    print(f"Relatorio de duplicidade (mesma key): {duplicates_file}")

    if args.check_duplicate_values:
        value_duplicates_file = os.path.join(args.output_dir, "duplicidade_valores.csv")
        write_csv(value_duplicates_file, VALUE_DUPLICATE_FIELDS, value_duplicate_rows)
        print(f"Relatorio de duplicidade (mesmo valor, keys distintas): {value_duplicates_file}")
        print(
            f"{len(value_duplicate_rows)} grupo(s) de valor duplicado entre chaves distintas -- "
            "NAO sao candidatas a exclusao automatica: exigem ajuste manual na(s) API(s) que "
            "ainda usa(m) a chave redundante antes de qualquer consolidacao."
        )

    print(
        "\nLEMBRETE: esta varredura NAO cobre interceptors customizados em Java. "
        "Se o tenant usa esse tipo de interceptor, valide manualmente antes de "
        "confiar cegamente no CSV gerado. Ver README.md."
    )


if __name__ == "__main__":
    main()
