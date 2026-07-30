#!/usr/bin/env python3
"""
Ferramenta de apoio para testar sanitize_variables.py (Script B) ponta a
ponta contra um tenant real, sem depender de dados reais do tenant. Uso:
gerar algumas variaveis de ambiente descartaveis para servir de candidatas.

Como nao existe endpoint de criacao de variavel/mapa individual na API v5 do
api-manager (mesma limitacao documentada no Script B), a criacao tambem passa
pelo mesmo mecanismo read-modify-write: GET /environments/{id} -> acrescenta
um novo grupo (mapVars) com variaveis aleatorias -> PUT /environments/{id}.
Isso tem a vantagem de exercitar exatamente o mesmo caminho de risco do
Script B (round-trip do ambiente inteiro), na direcao inversa.

Reaproveita a mesma autenticacao/config do sanitize_variables.py (.env na
pasta pai, por padrao).

Uso:
    # descobre os IDs de ambiente validos para esta credencial/tenant (comece
    # por aqui — um environment-id que nao existe/nao pertence ao tenant
    # costuma dar um 500 feio do backend, tipo "CommunicationException:
    # There was an error communicating with Access Control service", em vez
    # de um 404 limpo)
    python3 testing/create_test_variables.py --list-environments

    # cria 5 variaveis de teste no ambiente 10 (ex: staging) e gera um CSV
    # no formato aceito pelo sanitize_variables.py
    python3 testing/create_test_variables.py --environment-id 10

    # marca um ou mais environmentIds do SEU tenant como producao conhecida,
    # para exigir uma confirmacao reforcada antes de criar variaveis de teste
    # neles (recomendado sempre que voce sabe de cor quais ids sao producao)
    python3 testing/create_test_variables.py --environment-id 6 --known-production-env-ids 6,14

    # inclui tambem 1 variavel SECURED, para observar empiricamente se o
    # GET /environments/{id} devolve o valor real ou mascarado
    python3 testing/create_test_variables.py --environment-id 10 --include-secured

    # depois de validar o Script B contra o CSV gerado, remove o grupo de
    # teste inteiro do ambiente (mesmo que ja esteja parcial/totalmente
    # esvaziado pelo Script B)
    python3 testing/create_test_variables.py --environment-id 10 --cleanup --map-name sanitize-test-XXXXXX
"""
import argparse
import csv
import os
import random
import string
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import sanitize_variables as sv  # noqa: E402


def parse_env_id_set(raw):
    if not raw:
        return set()
    return {int(chunk.strip()) for chunk in raw.split(",") if chunk.strip()}


def random_suffix(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_test_vars(count, prefix, include_secured):
    suffix = random_suffix()
    variables = []
    for i in range(count):
        variables.append({
            "key": f"{prefix}-var-{i:03d}-{suffix}",
            "value": f"valor-descartavel-{random_suffix(10)}",
            "variableType": "DEFAULT",
        })
    if include_secured:
        variables.append({
            "key": f"{prefix}-secured-{suffix}",
            "value": f"segredo-descartavel-{random_suffix(16)}",
            "variableType": "SECURED",
        })
    return suffix, variables


def confirm(prompt):
    answer = input(f"{prompt} [digite 'sim' para confirmar]: ").strip().lower()
    if answer != "sim":
        raise SystemExit("Cancelado pelo operador.")


def do_create(client, args, known_production_env_ids):
    resp = client.get(f"/environments/{args.environment_id}")
    if resp.status_code != 200:
        raise SystemExit(f"GET /environments/{args.environment_id} falhou ({resp.status_code}): {resp.text[:300]}")
    environment = resp.json()
    env_name = environment.get("name", "")

    print(f"Ambiente alvo: id={args.environment_id} name={env_name!r}")
    if args.environment_id in known_production_env_ids:
        print(
            f"!! ATENCAO: environmentId={args.environment_id} foi informado em "
            "--known-production-env-ids como um ambiente de PRODUCAO conhecido."
        )
        if not args.yes:
            confirm("Tem certeza que quer criar variaveis de teste em um ambiente de PRODUCAO real")
    elif not args.yes:
        confirm(f"Confirma a criacao de {args.count} variavel(is) de teste no ambiente {args.environment_id}")

    suffix, variables = build_test_vars(args.count, args.map_name_prefix, args.include_secured)
    map_name = args.map_name or f"{args.map_name_prefix}-{suffix}"

    new_map = {
        "name": map_name,
        "description": "Variaveis de teste geradas por create_test_variables.py — seguro excluir.",
        "vars": variables,
    }
    environment.setdefault("mapVars", []).append(new_map)

    put_resp = client.put(f"/environments/{args.environment_id}", environment)
    if put_resp.status_code not in (200, 201):
        raise SystemExit(f"PUT /environments/{args.environment_id} falhou ({put_resp.status_code}): {put_resp.text[:300]}")

    # re-GET para descobrir os ids atribuidos pelo servidor ao novo mapa/variaveis
    confirm_resp = client.get(f"/environments/{args.environment_id}")
    if confirm_resp.status_code != 200:
        raise SystemExit(f"Criacao pode ter sido aplicada, mas a confirmacao falhou ({confirm_resp.status_code}).")
    fresh = confirm_resp.json()
    created_map = next((m for m in fresh.get("mapVars") or [] if m.get("name") == map_name), None)
    if created_map is None:
        raise SystemExit(
            f"PUT retornou {put_resp.status_code} mas o grupo '{map_name}' nao foi encontrado numa nova consulta. "
            "A API pode exigir um formato diferente para criar mapVars novos (ex: nao aceitar id ausente) — "
            "inspecione a resposta manualmente (--verbose) antes de tentar de novo."
        )

    rows = []
    keys_wanted = {v["key"] for v in variables}
    for v in created_map.get("vars") or []:
        if v.get("key") in keys_wanted:
            rows.append({
                "environmentId": args.environment_id,
                "environmentName": env_name,
                "mapId": created_map["id"],
                "mapName": map_name,
                "variableId": v["id"],
                "variableKey": v["key"],
                "classification": "teste_gerado_automaticamente",
            })

    if len(rows) != len(variables):
        print(
            f"aviso: esperava {len(variables)} variaveis no grupo criado, encontrei {len(rows)} — "
            "confira o ambiente manualmente."
        )

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=sv.INPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nCriado grupo '{map_name}' (mapId={created_map['id']}) com {len(rows)} variavel(is) de teste.")
    print(f"CSV pronto para o sanitize_variables.py: {args.output}")
    print(
        f"\nProximos passos sugeridos:\n"
        f"  python3 sanitize_variables.py --input {os.path.relpath(args.output, ROOT)} --dry-run\n"
        f"  python3 sanitize_variables.py --input {os.path.relpath(args.output, ROOT)}\n"
        f"\nDepois de validar, limpe o grupo de teste com:\n"
        f"  python3 testing/create_test_variables.py --environment-id {args.environment_id} "
        f"--cleanup --map-name {map_name}"
    )


def do_diagnose(client, environment_id=None):
    """Chamada minima possivel na API (GET /environments/count, sem parametros)
    — util para isolar se QUALQUER leitura em Environments falha (credencial/
    host mal configurado) ou se o problema e especifico de outro endpoint.
    Se environment_id for informado, tambem testa GET /environments/{id}
    (somente leitura, nao escreve nada) contra um ID especifico conhecido."""
    resp = client.get("/environments/count")
    print(f"GET /environments/count -> {resp.status_code}")
    print(resp.text[:500])
    if resp.status_code == 200:
        print("OK: a credencial consegue ler Environments neste host (contagem funciona).")
    else:
        print(
            "Falhou ja na contagem. Problema provavelmente e credencial/host mal "
            "configurado para este tenant (BASE_URL errado, ou Role sem vinculo "
            "real ao Client App) — nao adianta tentar nada especifico de um "
            "environmentId sem resolver isso primeiro."
        )
        return

    if environment_id is None:
        return

    print(f"\nGET /environments/{environment_id} -> ", end="")
    resp = client.get(f"/environments/{environment_id}")
    print(resp.status_code)
    print(resp.text[:500])
    if resp.status_code == 200:
        print(
            f"\nOK: GET por ID funciona para o environmentId={environment_id}. Se outro "
            "ID especifico falhar, o problema e mais provavelmente aquele ID nao "
            "existir/nao pertencer a este tenant do que um problema geral."
        )
    else:
        print(
            f"\nFalhou mesmo com environmentId={environment_id} (que deveria ser valido), "
            "apesar da contagem ter funcionado. Isso aponta para um problema no "
            "backend especifico de retornar o registro completo do ambiente (ex: "
            "falha ao enriquecer o registro com dados do Access Control) — nao "
            "parece ser algo corrigivel do lado do script/credencial. Vale reportar "
            "isso ao time de plataforma/suporte da Sensedia."
        )


def do_list_environments(client):
    # Chamada mais simples possivel (sem query params) — todos sao opcionais no
    # swagger, e menos parametros ajuda a isolar problemas no diagnostico.
    resp = client.get("/environments")
    if resp.status_code != 200:
        raise SystemExit(f"GET /environments falhou ({resp.status_code}): {resp.text[:300]}")
    environments = resp.json()
    if not environments:
        print("Nenhum ambiente retornado para este tenant/credencial.")
        return
    print(f"{len(environments)} ambiente(s) encontrado(s):\n")
    print(f"{'id':>6}  name")
    for env in sorted(environments, key=lambda e: e.get("id") or 0):
        print(f"{env.get('id'):>6}  {env.get('name', '')}")
    print("\nUse um desses IDs em --environment-id.")


def do_cleanup(client, args):
    if not args.map_name:
        raise SystemExit("--cleanup exige --map-name (o grupo de teste a remover).")
    resp = client.get(f"/environments/{args.environment_id}")
    if resp.status_code != 200:
        raise SystemExit(f"GET /environments/{args.environment_id} falhou ({resp.status_code}): {resp.text[:300]}")
    environment = resp.json()
    env_name = environment.get("name", "")
    map_vars = environment.get("mapVars") or []
    target = next((m for m in map_vars if m.get("name") == args.map_name), None)
    if target is None:
        print(f"Grupo '{args.map_name}' nao encontrado no ambiente {args.environment_id} ({env_name}) — nada a limpar.")
        return

    remaining = len(target.get("vars") or [])
    print(f"Ambiente: id={args.environment_id} name={env_name!r} | grupo alvo: id={target['id']} name={args.map_name!r} ({remaining} variavel(is) ainda dentro)")
    if not args.yes:
        confirm("Confirma a remocao deste grupo de teste inteiro")

    environment["mapVars"] = [m for m in map_vars if m.get("name") != args.map_name]
    put_resp = client.put(f"/environments/{args.environment_id}", environment)
    if put_resp.status_code not in (200, 201):
        raise SystemExit(f"PUT /environments/{args.environment_id} falhou ({put_resp.status_code}): {put_resp.text[:300]}")

    confirm_resp = client.get(f"/environments/{args.environment_id}")
    still_there = any(m.get("name") == args.map_name for m in (confirm_resp.json().get("mapVars") or []))
    if still_there:
        raise SystemExit("PUT respondeu OK mas o grupo ainda aparece numa nova consulta — confira manualmente.")
    print(f"Grupo '{args.map_name}' removido e confirmado.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--environment-id", type=int, default=None, help="obrigatorio, exceto com --list-environments/--diagnose")
    parser.add_argument("--env-file", default=os.path.join(ROOT, ".env"))
    parser.add_argument("--count", type=int, default=5, help="quantas variaveis DEFAULT criar (padrao: 5)")
    parser.add_argument("--include-secured", action="store_true", help="tambem cria 1 variavel SECURED, para observar se o GET devolve valor real ou mascarado")
    parser.add_argument("--map-name-prefix", default="sanitize-test")
    parser.add_argument("--map-name", default=None, help="nome do grupo; obrigatorio em --cleanup, opcional (auto-gerado) na criacao")
    parser.add_argument("--output", default=os.path.join(ROOT, "testing", "test_candidates.csv"))
    parser.add_argument("--cleanup", action="store_true", help="em vez de criar, remove o grupo indicado em --map-name")
    parser.add_argument("--list-environments", action="store_true", help="lista id/name dos ambientes visiveis para esta credencial e sai (nao precisa de --environment-id)")
    parser.add_argument("--diagnose", action="store_true", help="testa a chamada mais simples possivel (GET /environments/count) e sai — use se --list-environments ou a criacao estiverem falhando com erro 500/generico. Combine com --environment-id para tambem testar GET por ID (somente leitura)")
    parser.add_argument(
        "--known-production-env-ids", default=None,
        help="environmentIds (separados por virgula) do SEU tenant que voce sabe serem producao -- "
             "exige uma confirmacao extra antes de criar variaveis de teste neles. Vazio por padrao "
             "(nenhum ambiente e tratado como producao conhecida).",
    )
    parser.add_argument("--yes", action="store_true", help="pula as confirmacoes interativas")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--insecure", action="store_true",
        help="desativa a validacao de certificado TLS (verify=False) em todas as chamadas "
             "HTTPS. Use so como ultimo recurso -- ver README.md, secao de solucao de "
             "problemas.",
    )
    args = parser.parse_args()

    cfg = sv.load_config(args.env_file)
    try:
        client = sv.ApiClient(cfg, verbose=args.verbose, insecure=args.insecure)
    except sv.AuthError as e:
        raise SystemExit(str(e))

    if args.diagnose:
        do_diagnose(client, environment_id=args.environment_id)
        return

    if args.list_environments:
        do_list_environments(client)
        return

    if args.environment_id is None:
        raise SystemExit("--environment-id e obrigatorio (ou use --list-environments para descobrir os IDs validos).")

    if args.cleanup:
        do_cleanup(client, args)
    else:
        do_create(client, args, parse_env_id_set(args.known_production_env_ids))


if __name__ == "__main__":
    main()
