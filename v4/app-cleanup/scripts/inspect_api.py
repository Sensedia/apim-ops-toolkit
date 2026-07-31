"""
Passo 0 — apenas leitura. Não deleta nada.

Faz algumas chamadas de sondagem contra a API de Apps do Manager para
descobrir o formato real das respostas (o swagger local não documenta query
params nem o corpo das respostas). Salva tudo em ./debug/ para análise
posterior.

Uso:
    python3 scripts/inspect_api.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient, redact  # noqa: E402

DEBUG_DIR = os.path.join(os.path.dirname(__file__), "..", "debug")
APPS_TO_DELETE_FILE = os.path.join(os.path.dirname(__file__), "..", "appsToDelete.txt")


def save(name, status_code, body):
    path = os.path.join(DEBUG_DIR, name)
    with open(path, "w") as f:
        json.dump({"http_status": status_code, "body": redact(body)}, f, indent=2, ensure_ascii=False)
    print(f"  -> salvo em {path}")


def load_first_client_id():
    with open(APPS_TO_DELETE_FILE) as f:
        lines = [l.strip() for l in f if l.strip()]
    # primeira linha é o header "clientId"
    return lines[1] if len(lines) > 1 else None


def do_get(client, label, path, params=None):
    print(f"[GET] {label}: {path} params={params}")
    resp = client.get(path, params=params)
    print(f"  status: {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:
        body = resp.text
    return resp.status_code, body


def main():
    os.makedirs(DEBUG_DIR, exist_ok=True)
    client = ApiClient()

    status, body = do_get(client, "apps/count", "/apps/count")
    save("apps_count.json", status, body)

    status, body = do_get(client, "apps (details=true)", "/apps", params={"details": "true"})
    save("apps_all_raw.json", status, body)
    if isinstance(body, list):
        print(f"  body é uma lista com {len(body)} itens")
        if body:
            print(f"  chaves do primeiro item: {sorted(body[0].keys())}")
    elif isinstance(body, dict):
        print(f"  body é um dict com chaves: {sorted(body.keys())}")

    first_client_id = load_first_client_id()
    if first_client_id:
        status, body = do_get(
            client, "apps?clientId=<primeiro da lista>", "/apps", params={"clientId": first_client_id}
        )
        save("apps_filter_by_clientid.json", status, body)

        status, body = do_get(
            client, "apps/{id} usando clientId como id", f"/apps/{first_client_id}"
        )
        save("apps_get_by_id_using_clientid.json", status, body)

    print("\nInspeção concluída. Revise os arquivos em ./debug/")


if __name__ == "__main__":
    main()
