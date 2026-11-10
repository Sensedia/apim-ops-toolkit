"""Helpers de execução compartilhados: diretórios por env-file, report resumível,
backup JSONL e journal de secrets (mesmo padrão do v4/app-cleanup)."""
import csv
import json
import os
import re
import time

ROOT = os.path.join(os.path.dirname(__file__), "..")


def tag_from_env_file(env_path):
    base = os.path.basename(env_path)
    tag = re.sub(r"^\.env[.-]?", "", base).strip("_-") or "default"
    return re.sub(r"[^a-zA-Z0-9_-]", "_", tag)


def dirs(env_file, output_dir=None):
    tag = tag_from_env_file(env_file)
    backup = os.path.abspath(output_dir or os.path.join(ROOT, "backup", tag))
    out = os.path.abspath(os.path.join(ROOT, "output", tag))
    os.makedirs(backup, mode=0o700, exist_ok=True)
    os.makedirs(out, mode=0o700, exist_ok=True)
    return backup, out


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def load_client_ids(path):
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if "clientId" not in (reader.fieldnames or []):
            raise SystemExit(f"{path}: falta a coluna 'clientId' no header")
        seen, ids = set(), []
        for row in reader:
            cid = (row.get("clientId") or "").strip()
            if cid and cid not in seen:
                seen.add(cid)
                ids.append(cid)
    return ids


def load_report(report_file, key):
    """Última linha por chave (o report é append-only; a última linha vale).
    `key` é o nome de uma coluna ou uma função row -> chave."""
    out = {}
    if os.path.exists(report_file):
        with open(report_file, newline="") as f:
            for row in csv.DictReader(f):
                out[key(row) if callable(key) else row[key]] = row
    return out


def append_csv(path, fields, row, mode=0o600):
    is_new = not os.path.exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, mode)
    with os.fdopen(fd, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, restval="", extrasaction="ignore")
        if is_new:
            w.writeheader()
        w.writerow(row)
        f.flush()
        os.fsync(f.fileno())


def append_jsonl(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def confirm_batch(action, count, assume_yes):
    """Pede confirmação antes de alterar mais de um item fora do --dry-run.
    Sem terminal interativo, exige --yes."""
    if assume_yes or count <= 1:
        return
    import sys
    if not sys.stdin.isatty():
        raise SystemExit(f"{action} em {count} itens sem terminal interativo: rode com --yes para confirmar")
    answer = input(f"Confirma {action} em {count} itens? Digite 'sim' para seguir: ").strip().lower()
    if answer != "sim":
        raise SystemExit("cancelado pelo operador; nada foi alterado")


def paginate(fetch, key, max_pages=1000):
    """Lê páginas até vir uma vazia (não para em página menor que o tamanho pedido,
    porque a API pode limitar o tamanho). Para também se uma página não trouxer item
    novo, para não entrar em laço quando a API ignora o parâmetro de paginação."""
    items, seen, page = [], set(), 0
    while page < max_pages:
        batch = fetch(page, len(items))
        if not batch:
            break
        new = [x for x in batch if key(x) not in seen]
        if not new:
            break
        for x in new:
            seen.add(key(x))
        items.extend(new)
        page += 1
    return items
