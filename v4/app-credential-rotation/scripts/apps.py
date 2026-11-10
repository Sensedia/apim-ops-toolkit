"""
Bloqueio, desbloqueio e troca de credenciais de APPs (APIM v4 — somente Manager API).

Todas as operações usam a Manager API com o token do operador e ficam registradas no
audit do API Manager com esse usuário. O operador também vai em cada linha do report.

Para cada clientId do --input:

  --mode block
    PUT /apps/{id} com status CANCELLED. O app deixa de emitir tokens novos; os tokens
    já emitidos continuam valendo até serem revogados (revoke_tokens.py).

  --mode unblock
    Desfaz o block deste script: volta o status anterior (lido do report).

  --mode recreate   (troca client_id E secret)
    A Manager API v4 não troca o secret de um app existente. A troca de credenciais é
    feita recriando o app com a mesma configuração:
      1. GET /apps/{id}: backup do payload completo (inclusive APIs e planos)
      2. PUT no app antigo: renomeia para "<nome> [substituído AAAA-MM-DD <início do client_id>]" e CANCELLED
         (o nome do app é único; o antigo fica guardado para consulta/rollback)
      3. POST /apps com o nome original, a mesma descrição, developer, extraInfo, APIs e
         planos -> o Manager gera client_id e secret novos
      4. Grava client_id/secret novos em output/<tag>/new_credentials.csv (0600)
      5. Confirma: app novo APPROVED com os mesmos planos; app antigo CANCELLED
    Se o POST falhar, o app antigo volta ao nome e status originais (rollback). Se o POST
    estourar o tempo, o script procura o app novo pelo nome antes de decidir.
    APPs que já estavam CANCELLED antes deste script são puladas (skipped_cancelled): o
    script não reativa o que alguém cancelou de propósito. --include-cancelled muda isso.
    Depois, revogue os tokens do app antigo (revoke_tokens.py com o mesmo --input).

Só processa o app cujo clientId bate exatamente com o do arquivo. Fora do --dry-run,
pede confirmação antes de alterar mais de uma APP (--yes pula a pergunta). O backup
local guarda o payload sem o secret (só o sha256), e o --dry-run não grava backup.

Resumível: o report fica em backup/<tag>/report.csv e reexecuções pulam o que já foi
concluído no mesmo modo, a menos que --retry-errors.

Uso:
    python3 scripts/apps.py --mode block    --input appsToRotate.txt --env-file .env --dry-run
    python3 scripts/apps.py --mode recreate --input appsToRotate.txt --env-file .env --dry-run --limit 1
    python3 scripts/apps.py --mode recreate --input appsToRotate.txt --env-file .env --only <clientId>
    python3 scripts/apps.py --mode unblock  --input appsToRotate.txt --env-file .env
"""
import argparse
import hashlib
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient, redact  # noqa: E402
from ops import append_csv, append_jsonl, confirm_batch, dirs, load_client_ids, load_report, now  # noqa: E402

REPORT_FIELDS = ["clientId", "mode", "app_id", "app_name", "status", "previous_status", "new_status",
                 "new_app_id", "new_clientId", "http_status", "operator", "timestamp", "error", "duration_seconds"]
DONE = {"block": {"blocked", "already_blocked", "not_found"},
        "unblock": {"unblocked", "not_blocked_by_tool", "not_found"},
        "recreate": {"recreated", "not_found", "skipped_cancelled"}}
CREDS_FIELDS = ["old_clientId", "app_name", "new_app_id", "new_clientId", "new_secret", "created_at", "operator"]
IDENTITY_FIELDS = ("id", "clientId", "code", "secret", "creationDate", "accessTokens")


def censored(v):
    return not v or set(str(v)) <= {"*"}


def find_app(client, cid):
    """Busca pelo clientId e devolve o detalhe (GET /apps/{id} traz APIs e planos)."""
    resp = client.get("/apps", params={"clientId": cid})
    if resp.status_code != 200:
        return None, resp.status_code, f"GET /apps falhou: {resp.text[:300]}"
    # só aceita correspondência exata: a busca da API pode devolver outras APPs
    found = [a for a in resp.json() if (a.get("clientId") or a.get("code")) == cid]
    if not found:
        return None, 200, ""
    if len(found) > 1:
        return None, 200, f"{len(found)} apps com o mesmo clientId; trate manualmente"
    det = client.get(f"/apps/{found[0]['id']}")
    if det.status_code != 200:
        return None, det.status_code, f"GET /apps/{found[0]['id']} falhou: {det.text[:300]}"
    return det.json(), 200, ""


def find_by_name(client, name, exclude_id=None):
    resp = client.get("/apps", params={"name": name})
    if resp.status_code != 200:
        return None
    same = [a for a in resp.json() if a.get("name") == name and a.get("id") != exclude_id]
    return same[0] if len(same) == 1 else None


def backup_view(app):
    """Payload para o backup local: sem o secret em claro (só o sha256)."""
    out = redact(app)
    if app.get("secret"):
        out["secret_sha256"] = hashlib.sha256(str(app["secret"]).encode()).hexdigest()
    return out


def plans_of(app):
    return sorted(p.get("id") for api in (app.get("apis") or []) for p in (api.get("plans") or []))


def put_app(client, app, **changes):
    body = dict(app)
    body.update(changes)
    return client.put(f"/apps/{app['id']}", json=body)


def do_block(client, app, dry):
    if app.get("status") == "CANCELLED":
        return {"status": "already_blocked", "new_status": "CANCELLED"}
    if dry:
        return {"status": "would_block", "new_status": "CANCELLED"}
    resp = put_app(client, app, status="CANCELLED")
    if resp.status_code != 200:
        return {"status": "error", "http_status": resp.status_code, "error": resp.text[:300]}
    again, _, err = find_app(client, app.get("clientId"))
    ok = again and again.get("status") == "CANCELLED"
    return {"status": "blocked" if ok else "block_not_confirmed", "http_status": resp.status_code,
            "new_status": "CANCELLED", "error": "" if ok else (err or "status não mudou")}


def do_unblock(client, app, previous, dry):
    if not previous:
        return {"status": "not_blocked_by_tool", "error": "nenhum block deste script no report para este app"}
    if dry:
        return {"status": "would_unblock", "new_status": previous}
    resp = put_app(client, app, status=previous)
    if resp.status_code != 200:
        return {"status": "error", "http_status": resp.status_code, "error": resp.text[:300]}
    return {"status": "unblocked", "http_status": resp.status_code, "new_status": previous}


def do_recreate(client, app, creds_file, operator, dry, restore_status):
    """restore_status: status a usar no app novo. Para APP CANCELLED, só vem preenchido
    quando o cancelamento foi feito por este script (--mode block); caso contrário a APP
    é pulada, para não reativar algo que alguém cancelou de propósito."""
    cid, name, status = app.get("clientId"), app.get("name", ""), app.get("status")
    if censored(cid) or censored(app.get("secret")):
        return {"status": "error", "error": "clientId/secret mascarados: o operador precisa da permissão SECRETS"}
    new_status = restore_status or status
    if new_status == "CANCELLED":
        return {"status": "skipped_cancelled",
                "error": "APP já estava CANCELLED antes deste script; não é recriada (use --include-cancelled)"}
    if dry:
        return {"status": "would_recreate", "new_status": new_status}
    # sufixo com data e início do client_id antigo: único mesmo com várias trocas no dia
    old_name = f"{name} [substituído {time.strftime('%Y-%m-%d')} {str(cid)[:8]}]"
    r1 = put_app(client, app, name=old_name, status="CANCELLED")
    if r1.status_code != 200:
        return {"status": "error", "http_status": r1.status_code, "error": f"PUT no app antigo: {r1.text[:250]}"}
    new_body = {k: v for k, v in app.items() if k not in IDENTITY_FIELDS}
    new_body["name"] = name
    new_body["status"] = new_status

    created, post_status, post_err = None, None, ""
    try:
        r2 = client.post("/apps", json=new_body)
        post_status = r2.status_code
        if r2.status_code in (200, 201):
            created = r2.json()
        else:
            post_err = r2.text[:200]
    except Exception as e:  # noqa: BLE001  (timeout/conexão: o app pode ter sido criado mesmo assim)
        post_err = f"{e.__class__.__name__}: {str(e)[:150]}"
        maybe = find_by_name(client, name, exclude_id=app["id"])
        if maybe:
            created = {"id": maybe.get("id"), "code": maybe.get("clientId"), "secret": maybe.get("secret")}
    if not created:
        rb = put_app(client, dict(app), name=name, status=status)  # rollback do app antigo
        return {"status": "error_rolled_back" if rb.status_code == 200 else "error_rollback_failed",
                "http_status": post_status,
                "error": f"POST /apps: {post_err} | rollback do antigo -> {rb.status_code}"}

    new_id, new_cid, new_secret = created.get("id"), created.get("code") or created.get("clientId"), created.get("secret")
    append_csv(creds_file, CREDS_FIELDS, {"old_clientId": cid, "app_name": name, "new_app_id": new_id,
                                          "new_clientId": new_cid, "new_secret": new_secret,
                                          "created_at": now(), "operator": operator})
    new_app, _, _ = find_app(client, new_cid)
    old_app, _, _ = find_app(client, cid)
    problems = []
    if censored(new_secret):
        problems.append("secret novo veio mascarado: recupere pela interface")
    if not new_app or new_app.get("status") != new_status:
        problems.append("app novo não encontrado ou com status diferente")
    elif plans_of(new_app) != plans_of(app):
        problems.append(f"planos diferentes: antigo {plans_of(app)} novo {plans_of(new_app)}")
    if not old_app or old_app.get("status") != "CANCELLED":
        problems.append("app antigo não ficou CANCELLED")
    if post_err:
        problems.append(f"POST não respondeu ({post_err}); app novo encontrado pelo nome")
    return {"status": "recreated" if not problems else "recreate_not_confirmed", "http_status": post_status,
            "new_status": new_status, "new_app_id": new_id, "new_clientId": new_cid,
            "error": "; ".join(problems)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["block", "unblock", "recreate"], required=True)
    p.add_argument("--input", required=True, help="arquivo com a coluna 'clientId' (gerado pelo list_apps.py)")
    p.add_argument("--env-file", default=".env")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--retry-errors", action="store_true")
    p.add_argument("--only", default=None, help="processar apenas este clientId")
    p.add_argument("--gpg-passphrase-file", default=None,
                   help="recreate: cifra o new_credentials.csv com GPG (AES256) ao final e apaga o texto puro")
    p.add_argument("--include-cancelled", action="store_true",
                   help="recreate: também recria APPs que já estavam CANCELLED (o app novo nasce APPROVED)")
    p.add_argument("--yes", action="store_true", help="não pede confirmação antes de alterar várias APPs")
    p.add_argument("--verbose", action="store_true", help="loga request/response (secrets e códigos mascarados)")
    a = p.parse_args()

    backup_dir, out_dir = dirs(a.env_file, a.output_dir)
    report_file = os.path.join(backup_dir, "report.csv")
    backup_file = os.path.join(backup_dir, "apps_backup.jsonl")
    creds_file = os.path.join(out_dir, "new_credentials.csv")
    report = load_report(report_file, lambda r: f"{r['mode']}:{r['clientId']}")

    ids = [a.only] if a.only else load_client_ids(a.input)
    pending = []
    for cid in ids:
        prior = report.get(f"{a.mode}:{cid}", {}).get("status")
        if prior in DONE[a.mode]:
            continue
        if prior and not prior.startswith("would_") and not a.retry_errors:
            continue
        pending.append(cid)
    if a.limit:
        pending = pending[: a.limit]

    client = ApiClient(a.env_file, verbose=a.verbose)
    who = client.whoami()
    operator = f"{who['login']} (id {who['id']})"
    print(f"modo: {a.mode} | operador: {operator} | input: {a.input}")
    print(f"total no arquivo: {len(ids)} | a processar agora: {len(pending)}" + (" | DRY-RUN" if a.dry_run else ""))

    if not a.dry_run:
        confirm_batch(f"--mode {a.mode}", len(pending), a.yes)

    counts = {}
    for i, cid in enumerate(pending, 1):
        started = time.perf_counter()
        row = {"clientId": cid, "mode": a.mode, "operator": operator, "timestamp": now()}
        app, http, err = find_app(client, cid)
        if app is None:
            row.update({"status": "not_found" if not err else "error", "http_status": http, "error": err})
        else:
            if not a.dry_run:
                append_jsonl(backup_file, {"mode": a.mode, "timestamp": now(), "operator": operator,
                                           "app": backup_view(app)})
            row.update({"app_id": app["id"], "app_name": app.get("name", ""), "previous_status": app.get("status", "")})
            try:
                if a.mode == "block":
                    row.update(do_block(client, app, a.dry_run))
                elif a.mode == "unblock":
                    blocked = report.get(f"block:{cid}", {})
                    prev = blocked.get("previous_status") if blocked.get("status") == "blocked" else None
                    row.update(do_unblock(client, app, prev, a.dry_run))
                else:
                    restore = None
                    if app.get("status") == "CANCELLED":
                        blocked = report.get(f"block:{cid}", {})
                        if blocked.get("status") == "blocked":
                            restore = blocked.get("previous_status")
                        elif a.include_cancelled:
                            restore = "APPROVED"
                    row.update(do_recreate(client, app, creds_file, operator, a.dry_run, restore))
            except Exception as e:  # noqa: BLE001
                row.update({"status": "error", "error": f"{e.__class__.__name__}: {str(e)[:250]}"})
        row["duration_seconds"] = round(time.perf_counter() - started, 3)
        append_csv(report_file, REPORT_FIELDS, row)
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        print(f"[{i}/{len(pending)}] {cid} {row.get('app_name', '')} -> {row['status']}"
              + (f" | novo clientId {row['new_clientId']}" if row.get("new_clientId") else "")
              + (f"\n    causa: {row['error']}" if row.get("error") else ""))

    print("\nResumo desta execução:", counts)
    print(f"Relatório: {report_file}\nBackup: {backup_file}")
    if a.mode == "recreate" and not a.dry_run and os.path.exists(creds_file):
        print(f"Credenciais novas: {creds_file} (0600)")
        if a.gpg_passphrase_file:
            subprocess.run(["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase-file",
                            a.gpg_passphrase_file, "--symmetric", "--cipher-algo", "AES256",
                            "-o", creds_file + ".gpg", creds_file], check=True)
            subprocess.run(["shred", "-u", creds_file], check=True)
            print(f"Cifrado em {creds_file}.gpg; texto puro apagado com shred")


if __name__ == "__main__":
    main()
