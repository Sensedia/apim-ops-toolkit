"""
Sanitização/exclusão de APPs (APIM v4 — Manager API).

Para cada clientId no arquivo passado via --input:
  1. Busca o app via GET /apps?clientId=<id>
  2. Se não encontrado, registra "not_found" e segue.
  3. Se encontrado, faz backup do payload completo (com secret) em
     backup/<tenant>/apps_backup.jsonl
  4. Deleta via DELETE /apps/{id} (id numérico interno, != clientId)
  5. Valida a deleção reconsultando GET /apps?clientId=<id> — só marca
     "deleted" se a segunda consulta confirmar que o app não existe mais.
     Se o DELETE respondeu OK mas o app ainda aparece na validação, marca
     "delete_not_confirmed" (não confia só no HTTP status do DELETE).
  6. Registra o resultado em backup/<tenant>/report.csv

--input é obrigatório: o script só processa as APPs contidas no arquivo
informado, nunca uma lista default — cada tenant/execução tem seu próprio
arquivo de clientIds.

O diretório de output é derivado do --env-file (ex: .env.<tenant> -> backup/<tenant>/),
pra não misturar o estado/resumabilidade de ambientes diferentes. Use
--output-dir para sobrescrever explicitamente.

Resumível: reexecuções pulam clientIds já processados com sucesso
(status "deleted" ou "not_found") a menos que --retry-errors seja usado.
A resumabilidade é sempre relativa ao MESMO diretório de output — trocar de
--env-file sem trocar de --output-dir (ou vice-versa) é um erro do operador,
não algo que o script possa detectar sozinho.

Uso:
    python3 scripts/sanitize_apps.py --input appsToDelete.txt --dry-run --limit 5
    python3 scripts/sanitize_apps.py --input appsToDelete.txt
    python3 scripts/sanitize_apps.py --input appsToDelete_<tenant>.txt --env-file .env.<tenant>
"""
import argparse
import csv
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
REPORT_FIELDS = [
    "clientId", "app_id", "app_name", "status", "http_status", "timestamp", "error",
    "duration_seconds",
]


def format_duration(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def tag_from_env_file(env_path):
    base = os.path.basename(env_path)
    tag = re.sub(r"^\.env[.-]?", "", base).strip("_-") or "default"
    return re.sub(r"[^a-zA-Z0-9_-]", "_", tag)


def load_client_ids(path):
    with open(path) as f:
        lines = [l.strip() for l in f if l.strip()]
    # primeira linha é o header "clientId"
    seen = set()
    ids = []
    for line in lines[1:]:
        if line not in seen:
            seen.add(line)
            ids.append(line)
    return ids


def load_already_processed(report_file):
    processed = {}
    if not os.path.exists(report_file):
        return processed
    with open(report_file) as f:
        for row in csv.DictReader(f):
            processed[row["clientId"]] = row["status"]
    return processed


def load_delete_durations(report_file):
    """Duração das deleções já registradas antes desta execução, usada para
    estimar o tempo restante desde o início (não só a partir do zero)."""
    durations = []
    if not os.path.exists(report_file):
        return durations
    with open(report_file) as f:
        for row in csv.DictReader(f):
            if row["status"] == "deleted" and row.get("duration_seconds"):
                try:
                    durations.append(float(row["duration_seconds"]))
                except ValueError:
                    pass
    return durations


def load_already_backed_up(backup_file):
    backed_up = set()
    if not os.path.exists(backup_file):
        return backed_up
    with open(backup_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            backed_up.add(json.loads(line)["clientId"])
    return backed_up


def append_backup(backup_file, app):
    os.makedirs(os.path.dirname(backup_file), exist_ok=True)
    with open(backup_file, "a") as f:
        f.write(json.dumps(app, ensure_ascii=False) + "\n")


def migrate_report_if_needed(report_file):
    """Se o report.csv existente for de uma versão anterior do script (sem
    alguma coluna do REPORT_FIELDS atual), reescreve com o header atual,
    preenchendo colunas novas com vazio nas linhas antigas."""
    if not os.path.exists(report_file):
        return
    with open(report_file, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames == REPORT_FIELDS:
            return
        rows = list(reader)
    with open(report_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS, restval="")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def append_report(report_file, row):
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    is_new = not os.path.exists(report_file)
    with open(report_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        if is_new:
            writer.writeheader()
        writer.writerow(row)


def confirm_deleted(client, client_id):
    """Reconsulta a API pra confirmar que o clientId realmente não existe mais."""
    resp = client.get("/apps", params={"clientId": client_id})
    if resp.status_code != 200:
        return False, f"validação falhou: GET /apps retornou {resp.status_code}: {resp.text[:300]}"
    return (len(resp.json()) == 0), None


def process_one(client, client_id, backup_file, backed_up, dry_run):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    started = time.perf_counter()

    def finish(result):
        result["duration_seconds"] = round(time.perf_counter() - started, 3)
        return result

    resp = client.get("/apps", params={"clientId": client_id})
    if resp.status_code != 200:
        return finish({
            "clientId": client_id, "app_id": "", "app_name": "",
            "status": "error", "http_status": resp.status_code,
            "timestamp": ts, "error": f"GET /apps falhou: {resp.text[:300]}",
        })

    matches = resp.json()
    if not matches:
        return finish({
            "clientId": client_id, "app_id": "", "app_name": "",
            "status": "not_found", "http_status": 200, "timestamp": ts, "error": "",
        })

    last_result = None
    for app in matches:
        app_id = app["id"]
        app_name = app.get("name", "")

        if client_id not in backed_up:
            append_backup(backup_file, app)
            backed_up.add(client_id)

        if dry_run:
            last_result = {
                "clientId": client_id, "app_id": app_id, "app_name": app_name,
                "status": "would_delete", "http_status": "", "timestamp": ts, "error": "",
            }
            continue

        del_resp = client.delete(f"/apps/{app_id}")
        if del_resp.status_code not in (200, 204):
            last_result = {
                "clientId": client_id, "app_id": app_id, "app_name": app_name,
                "status": "error", "http_status": del_resp.status_code,
                "timestamp": ts, "error": del_resp.text[:300],
            }
            continue

        confirmed, validation_error = confirm_deleted(client, client_id)
        if confirmed:
            last_result = {
                "clientId": client_id, "app_id": app_id, "app_name": app_name,
                "status": "deleted", "http_status": del_resp.status_code,
                "timestamp": ts, "error": "",
            }
        else:
            last_result = {
                "clientId": client_id, "app_id": app_id, "app_name": app_name,
                "status": "delete_not_confirmed", "http_status": del_resp.status_code,
                "timestamp": ts,
                "error": validation_error or "app ainda aparece na busca após o DELETE",
            }

    return finish(last_result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", required=True,
        help="arquivo com os clientIds a processar (uma coluna 'clientId', com header)",
    )
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--output-dir", default=None, help="default: backup/<derivado do --env-file>")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--retry-errors", action="store_true")
    parser.add_argument("--only", default=None, help="processar apenas este clientId (ignora o resto do arquivo)")
    parser.add_argument("--verbose", action="store_true", help="loga request/response completos de cada chamada")
    args = parser.parse_args()

    output_dir = args.output_dir or os.path.join(ROOT, "backup", tag_from_env_file(args.env_file))
    report_file = os.path.join(output_dir, "report.csv")
    backup_file = os.path.join(output_dir, "apps_backup.jsonl")

    migrate_report_if_needed(report_file)

    client_ids = [args.only] if args.only else load_client_ids(args.input)
    processed = load_already_processed(report_file)
    backed_up = load_already_backed_up(backup_file)

    pending = []
    for cid in client_ids:
        prior_status = processed.get(cid)
        if prior_status in ("deleted", "not_found", "would_delete"):
            continue
        if prior_status in ("error", "delete_not_confirmed") and not args.retry_errors:
            continue
        pending.append(cid)

    already_done = len(client_ids) - len(pending)
    if args.limit:
        pending = pending[: args.limit]
    pending_this_run = set(pending)

    print(f"input: {args.input} | env-file: {args.env_file} | output-dir: {output_dir}")
    print(
        f"total no arquivo: {len(client_ids)} | já processados antes: {already_done} | "
        f"a processar agora: {len(pending)}"
    )
    if args.dry_run:
        print("modo DRY-RUN: vai buscar e fazer backup, mas não vai deletar nada")

    client = ApiClient(args.env_file, verbose=args.verbose)

    # janela usada pra média móvel do tempo de deleção (amostras mais recentes
    # pesam mais que deleções muito antigas de execuções passadas)
    delete_durations = load_delete_durations(report_file)[-50:]
    dry_run_durations = []

    counts = {}
    i = 0
    for cid in client_ids:
        prior_status = processed.get(cid)
        if prior_status in ("deleted", "not_found", "would_delete"):
            print(f"[skip] {cid} -> já processado antes: {prior_status}")
            continue
        if prior_status in ("error", "delete_not_confirmed") and not args.retry_errors:
            print(f"[skip] {cid} -> já processado antes: {prior_status} (use --retry-errors para tentar de novo)")
            continue
        if cid not in pending_this_run:
            continue  # ficou de fora nesta execução por causa do --limit

        i += 1
        result = process_one(client, cid, backup_file, backed_up, args.dry_run)
        append_report(report_file, result)
        counts[result["status"]] = counts.get(result["status"], 0) + 1

        duration = result["duration_seconds"]
        if result["status"] == "deleted":
            delete_durations.append(duration)
            delete_durations = delete_durations[-50:]
        elif result["status"] == "would_delete":
            dry_run_durations.append(duration)
            dry_run_durations = dry_run_durations[-50:]

        remaining = len(pending) - i
        # em execução real, projeta com base na média das deleções reais
        # (mais lenta: GET + DELETE + confirmação); em dry-run, com base nas
        # buscas já feitas (só GET) — cada modo tem seu próprio custo por item
        sample = delete_durations if not args.dry_run else (dry_run_durations or delete_durations)
        eta = f" | ETA: ~{format_duration((sum(sample) / len(sample)) * remaining)}" if sample and remaining else ""

        print(f"[{i}/{len(pending)}] {cid} -> {result['status']} ({duration:.1f}s){eta}")
        if result["status"] in ("error", "delete_not_confirmed") and result["error"]:
            print(f"    causa: {result['error']}")

    print("\nResumo desta execução:", counts)
    print(f"Relatório completo em: {report_file}")
    print(f"Backup completo em: {backup_file}")


if __name__ == "__main__":
    main()
