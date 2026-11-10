"""
Revogação dos access tokens ativos das APPs (APIM v4 — somente Manager API).

Bloquear ou recriar um app não invalida os tokens já emitidos. Este script revoga os
tokens ativos das APPs do --input, sempre pela Manager API com o token do operador
(registrado no audit do API Manager).

Para cada clientId:
  1. GET /apps?clientId=<id> -> id do app (funciona também para o app antigo já renomeado
     e cancelado pelo apps.py --mode recreate)
  2. GET /access-tokens?appIds=<id>&status=ACTIVE (paginado)
  3. Backup de cada token (código mascarado + sha256, owner, criação) em
     backup/<tag>/tokens_backup.jsonl
  4. PUT /access-tokens/{code} com status REVOKED
  5. Confirma reconsultando GET /access-tokens?code=<code>

--created-after AAAA-MM-DDTHH:MM (UTC) restringe aos tokens criados depois do horário.

Uso:
    python3 scripts/revoke_tokens.py --input appsToRotate.txt --env-file .env --dry-run
    python3 scripts/revoke_tokens.py --input appsToRotate.txt --env-file .env --created-after 2026-01-31T12:00
"""
import argparse
import datetime as dt
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient  # noqa: E402
from ops import append_csv, append_jsonl, confirm_batch, dirs, load_client_ids, load_report, now, paginate  # noqa: E402

REPORT_FIELDS = ["token_sha256", "clientId", "app_id", "app_name", "owner", "created", "status", "http_status",
                 "operator", "timestamp", "error"]
DONE = {"revoked", "already_inactive"}


def mask(code):
    return f"{code[:4]}…{code[-4:]}" if code and len(code) > 10 else "****"


def find_app(client, cid):
    resp = client.get("/apps", params={"clientId": cid})
    if resp.status_code != 200:
        return None
    apps = [x for x in resp.json() if (x.get("clientId") or x.get("code")) == cid]  # só exato
    return apps[0] if len(apps) == 1 else None


def list_tokens(client, app_id, page_size=200):
    def fetch(_page, offset):
        resp = client.get("/access-tokens", params={"appIds": app_id, "status": "ACTIVE", "skip": offset, "limit": page_size})
        if resp.status_code != 200:
            raise RuntimeError(f"GET /access-tokens falhou ({resp.status_code}): {resp.text[:200]}")
        return resp.json()
    return paginate(fetch, key=lambda t: t.get("code"))


def created_ms(tok):
    v = tok.get("creationDate")
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:  # noqa: BLE001
        return None


def token_status(client, code):
    """Status atual do token (None se a consulta falhar ou não achar o token exato)."""
    resp = client.get("/access-tokens", params={"code": code})
    if resp.status_code != 200:
        return None
    rows = [r for r in resp.json() if r.get("code") == code]
    return rows[0].get("status") if rows else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--env-file", default=".env")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--created-after", default=None, help="UTC, ex: 2026-01-31T12:00")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--limit", type=int, default=None, help="limite de apps nesta execução")
    p.add_argument("--only", default=None)
    p.add_argument("--retry-errors", action="store_true")
    p.add_argument("--yes", action="store_true", help="não pede confirmação antes de revogar em lote")
    p.add_argument("--verbose", action="store_true", help="loga request/response (secrets e códigos mascarados)")
    a = p.parse_args()

    after_ms = None
    if a.created_after:
        after_ms = int(dt.datetime.fromisoformat(a.created_after).replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
    backup_dir, _ = dirs(a.env_file, a.output_dir)
    report_file = os.path.join(backup_dir, "report_tokens.csv")
    backup_file = os.path.join(backup_dir, "tokens_backup.jsonl")
    done = load_report(report_file, "token_sha256")

    client = ApiClient(a.env_file, verbose=a.verbose)
    who = client.whoami()
    operator = f"{who['login']} (id {who['id']})"
    ids = [a.only] if a.only else load_client_ids(a.input)
    if a.limit:
        ids = ids[: a.limit]
    print(f"operador: {operator} | apps: {len(ids)} | created-after: {a.created_after or '-'}"
          + (" | DRY-RUN" if a.dry_run else ""))

    if not a.dry_run:
        confirm_batch("a revogação dos tokens ativos das APPs", len(ids), a.yes)

    counts = {}
    for n, cid in enumerate(ids, 1):
        app = find_app(client, cid)
        if not app:
            print(f"[{n}/{len(ids)}] {cid} -> app não encontrado")
            counts["app_not_found"] = counts.get("app_not_found", 0) + 1
            continue
        try:
            tokens = list_tokens(client, app["id"])
        except Exception as e:  # noqa: BLE001
            print(f"[{n}/{len(ids)}] {cid} -> erro listando tokens: {e}")
            counts["list_error"] = counts.get("list_error", 0) + 1
            continue
        if after_ms:
            # token sem data legível fica DENTRO do escopo: é melhor revogar a mais do que deixar escapar
            unknown = [t for t in tokens if created_ms(t) is None]
            tokens = [t for t in tokens if created_ms(t) is None or created_ms(t) >= after_ms]
            if unknown:
                print(f"    {len(unknown)} token(s) sem data de criação legível incluídos no escopo")
        print(f"[{n}/{len(ids)}] {cid} {app.get('name', '')}: {len(tokens)} token(s) ativo(s) no escopo")
        for t in tokens:
            code = t.get("code") or ""
            if not code or set(code) <= {"*"}:
                counts["censored"] = counts.get("censored", 0) + 1
                print("    token mascarado: o operador precisa da permissão SECRETS")
                continue
            h = hashlib.sha256(code.encode()).hexdigest()
            prior = done.get(h, {}).get("status")
            if prior in DONE or (prior and prior != "would_revoke" and not a.retry_errors):
                continue
            row = {"token_sha256": h, "clientId": cid, "app_id": app["id"], "app_name": app.get("name", ""),
                   "owner": t.get("owner", ""), "created": t.get("creationDate", ""), "operator": operator,
                   "timestamp": now()}
            append_jsonl(backup_file, {"timestamp": now(), "operator": operator, "code_masked": mask(code),
                                       "code_sha256": h, "clientId": cid, "app_id": app["id"], "owner": t.get("owner"),
                                       "creationDate": t.get("creationDate"), "expiresIn": t.get("expiresIn")})
            if a.dry_run:
                row["status"] = "would_revoke"
            else:
                body = dict(t)
                body["status"] = "REVOKED"
                resp = client.put(f"/access-tokens/{code}", json=body)
                row["http_status"] = resp.status_code
                if resp.status_code != 200:
                    row.update({"status": "error", "error": resp.text[:250]})
                else:
                    st = token_status(client, code)
                    if st and st != "ACTIVE":
                        row["status"] = "revoked"
                    else:
                        # não conta como revogado sem confirmação: reexecute com --retry-errors
                        row.update({"status": "revoke_not_confirmed",
                                    "error": f"PUT 200, mas a reconsulta devolveu status={st!r}"})
            append_csv(report_file, REPORT_FIELDS, row)
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            print(f"    {mask(code)} owner={t.get('owner', '')} -> {row['status']}"
                  + (f" ({row['error'][:120]})" if row.get("error") else ""))
            time.sleep(0.05)

    print("\nResumo:", counts)
    print(f"Relatório: {report_file}\nBackup: {backup_file}")


if __name__ == "__main__":
    main()
