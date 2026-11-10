"""
Inventário (somente leitura) das APPs de um ambiente APIM v4, via Manager API.

Gera o arquivo de entrada do apps.py e do revoke_tokens.py: a coluna `clientId` (usada pelo script) e,
para conferência humana, `app_id`, `name`, `status` e `developer`. Não grava secret.

Os apps internos da plataforma (ID < 0) ficam fora do arquivo: eles são gerenciados
pela Sensedia.

Uso:
    python3 scripts/list_apps.py --env-file .env.<tenant> --output appsToRotate_<tenant>.txt
    python3 scripts/list_apps.py --env-file .env.<tenant> --status APPROVED --output appsToRotate_<tenant>.txt
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient  # noqa: E402
from ops import paginate  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--env-file", default=".env")
    p.add_argument("--output", required=True)
    p.add_argument("--status", default=None, help="filtrar por status (ex: APPROVED)")
    p.add_argument("--page-size", type=int, default=100)
    p.add_argument("--verbose", action="store_true")
    a = p.parse_args()

    client = ApiClient(a.env_file, verbose=a.verbose)
    who = client.whoami()
    print(f"operador: {who['login']} (id {who['id']})")

    def fetch(page, _offset):
        resp = client.get("/apps", params={"actualPage": page + 1, "pageSize": a.page_size, "details": "false"})
        if resp.status_code != 200:
            raise SystemExit(f"GET /apps falhou ({resp.status_code}): {resp.text[:300]}")
        return resp.json()

    apps = paginate(fetch, key=lambda x: x.get("id"))

    seen, rows, internal = set(), [], []
    for ap in apps:
        cid = ap.get("clientId") or ap.get("code")
        if not cid or cid in seen or (a.status and ap.get("status") != a.status):
            continue
        if int(ap.get("id", 0)) < 0:
            # apps internos: a API responde 404 ao PUT; ficam com a Sensedia
            internal.append(f"{ap.get('id')} {ap.get('name', '')}")
            continue
        if set(cid) <= {"*"}:
            raise SystemExit("clientId veio censurado: o usuário precisa da permissão SECRETS")
        seen.add(cid)
        rows.append({"clientId": cid, "app_id": ap.get("id"), "name": ap.get("name", ""),
                     "status": ap.get("status", ""), "developer": ap.get("developer", "")})

    with open(a.output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["clientId", "app_id", "name", "status", "developer"])
        w.writeheader()
        w.writerows(rows)
    by = {}
    for r in rows:
        by[r["status"]] = by.get(r["status"], 0) + 1
    print(f"{len(rows)} apps -> {a.output} | por status: {by}")
    if internal:
        print(f"apps internos fora do arquivo (gerenciados pela Sensedia): {', '.join(internal)}")


if __name__ == "__main__":
    main()
