#!/usr/bin/env python3
"""
Exclusao segura de variaveis de ambiente (API Manager v5).

Le um CSV de variaveis ja revalidadas como seguras para exclusao (saida do
script de identificacao, script irmao deste, no mesmo repositorio) e exclui
cada uma, UMA POR VEZ, nunca em lote:

  1. GET  /environments/{environmentId}   -> ambiente completo (mapVars[].vars[])
  2. Remove so a variavel-alvo dessa arvore, preservando o resto intocado
  3. Faz backup local do ambiente ANTES de cada alteracao real
  4. PUT  /environments/{environmentId}   -> ambiente atualizado
  5. Confirma a exclusao com uma nova consulta (nao confia so no HTTP status)

Nao existe endpoint de exclusao por variavel individual na API v5 do
api-manager — por isso o mecanismo e sempre ler o ambiente inteiro, tirar so
a variavel-alvo, e regravar o ambiente inteiro de volta.

Uso basico:
    python3 sanitize_variables.py --input confirmado_seguro_deletar.csv --dry-run
    python3 sanitize_variables.py --input confirmado_seguro_deletar.csv
    python3 sanitize_variables.py --input confirmado_seguro_deletar.csv --retry-errors

Veja o README.md para o passo a passo completo (credenciais, .env, como ler
o relatorio gerado).
"""
import argparse
import csv
import json
import os
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

INPUT_COLUMNS = [
    "environmentId", "environmentName", "mapId", "mapName",
    "variableId", "variableKey", "classification",
]
REPORT_FIELDS = INPUT_COLUMNS + [
    "status", "http_status", "error", "timestamp", "duration_seconds",
]

# Status finais de uma linha nesta execucao.
STATUS_DELETED = "deleted"
STATUS_NOT_FOUND = "not_found"
STATUS_WOULD_DELETE = "would_delete"
STATUS_BLOCKED_BY_CONNECTOR = "blocked_by_connector"
STATUS_DELETE_NOT_CONFIRMED = "delete_not_confirmed"
STATUS_SECURED_MASKED_ABORT = "secured_value_masked_abort"
STATUS_KEY_MISMATCH = "key_mismatch_error"
STATUS_FORBIDDEN_CHECK_PERMISSIONS = "forbidden_check_permissions"
STATUS_ERROR = "error"

# Nestes status, uma re-execucao pula a linha (ja concluida de verdade).
TERMINAL_ALWAYS = {STATUS_DELETED, STATUS_NOT_FOUND, STATUS_BLOCKED_BY_CONNECTOR}
# "would_delete" so e terminal enquanto o modo continuar sendo --dry-run.
# Se a execucao anterior foi --dry-run e agora e uma execucao real, a linha
# precisa ser reprocessada de verdade — seria um bug grave pular a exclusao
# real so porque uma simulacao ja tinha "processado" aquela linha.
TERMINAL_ONLY_IN_DRY_RUN = {STATUS_WOULD_DELETE}
# Estes so sao pulados de novo se --retry-errors NAO for usado.
RETRYABLE_BY_DEFAULT_BLOCKED = {
    STATUS_ERROR, STATUS_DELETE_NOT_CONFIRMED, STATUS_SECURED_MASKED_ABORT,
    STATUS_KEY_MISMATCH, STATUS_FORBIDDEN_CHECK_PERMISSIONS,
}

# Segundo a doc oficial (docs.sensedia.com/access-control/client-apps), 403 e o
# codigo GENERICO de "token valido, mas sem permissao para o recurso" — o mesmo
# codigo usado quando a variavel esta em uso por um Connector. So tratamos como
# blocked_by_connector se a resposta realmente mencionar isso; caso contrario e
# um problema de permissao da credencial usada, nao um resultado esperado.
def is_connector_block(response_text):
    return "connector" in (response_text or "").lower()


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
    """Cliente OAuth2 client_credentials para a API Manager v5. Autentica via
    Credencial de Seguranca (endpoint /user-management/v1/oauth2/token --
    ver README.md secao 2). Renova o token automaticamente perto
    do vencimento ou se uma chamada devolver 401."""

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
        # renova 5 minutos antes do vencimento real, por seguranca
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
    # algumas vezes com backoff exponencial antes de desistir. Seguro tambem
    # para o PUT, ja que o payload enviado e sempre o estado completo e
    # deterministico do ambiente (nao um delta) -- reenviar o mesmo PUT
    # converge para o mesmo estado, nao duplica nada.
    MAX_5XX_RETRIES = 3
    RETRY_BACKOFF_SECONDS = 1.0

    def _request(self, method, path, retry_on_401=True, **kwargs):
        self._ensure_token()
        attempt_5xx = 0
        while True:
            resp = requests.request(
                method, f"{self.base_url}{path}", headers=self._headers(),
                timeout=REQUEST_TIMEOUT, **kwargs,
            )
            if self.verbose:
                print(f"[verbose] {method} {path} -> {resp.status_code}")

            if resp.status_code == 401 and retry_on_401:
                self._refresh_token()
                return self._request(method, path, retry_on_401=False, **kwargs)

            if 500 <= resp.status_code < 600 and attempt_5xx < self.MAX_5XX_RETRIES:
                attempt_5xx += 1
                wait = self.RETRY_BACKOFF_SECONDS * (2 ** (attempt_5xx - 1))
                print(
                    f"aviso: {method} {path} respondeu HTTP {resp.status_code} -- tentativa "
                    f"{attempt_5xx}/{self.MAX_5XX_RETRIES}, nova tentativa em {wait:.0f}s "
                    f"(pode ser comunicacao intermitente entre servicos do backend: "
                    f"{resp.text[:200]})"
                )
                time.sleep(wait)
                continue

            return resp

    def get(self, path, **kwargs):
        return self._request("GET", path, **kwargs)

    def put(self, path, json_body, **kwargs):
        return self._request("PUT", path, json=json_body, **kwargs)


def load_input_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = [c for c in INPUT_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(
                f"CSV de entrada '{path}' nao tem as colunas esperadas: {missing}. "
                f"Colunas esperadas: {INPUT_COLUMNS}"
            )
        rows = list(reader)

    seen = set()
    deduped = []
    duplicates = 0
    for row in rows:
        key = row["variableId"]
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        deduped.append(row)
    if duplicates:
        print(f"aviso: {duplicates} linha(s) duplicada(s) por variableId foram ignoradas no CSV de entrada")
    return deduped


def load_report_status(report_file):
    statuses = {}
    if not os.path.exists(report_file):
        return statuses
    with open(report_file, newline="") as f:
        for row in csv.DictReader(f):
            statuses[row["variableId"]] = row["status"]
    return statuses


def append_report(report_file, row):
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    is_new = not os.path.exists(report_file)
    with open(report_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        if is_new:
            writer.writeheader()
        writer.writerow(row)


def append_backup(backup_file, variable_id, map_id, environment_json):
    os.makedirs(os.path.dirname(backup_file), exist_ok=True)
    entry = {
        "variableId": variable_id,
        "mapId": map_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": environment_json,
    }
    with open(backup_file, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def looks_masked(value):
    """Heuristica para valores de variaveis SECURED que parecem ter vindo
    mascarados (e nao o segredo real) numa resposta de GET."""
    if value is None:
        return True
    if value == "":
        return True
    if set(value) <= {"*", "•", "x", "X"}:
        return True
    return False


def find_masked_secured_vars(environment):
    masked = []
    for m in environment.get("mapVars") or []:
        for v in m.get("vars") or []:
            if v.get("variableType") == "SECURED" and looks_masked(v.get("value")):
                masked.append((m.get("id"), v.get("id"), v.get("key")))
    return masked


def locate_variable(environment, map_id, variable_id):
    for m in environment.get("mapVars") or []:
        if m.get("id") != map_id:
            continue
        for v in m.get("vars") or []:
            if v.get("id") == variable_id:
                return m, v
        return m, None  # mapa existe, variavel nao
    return None, None  # mapa nem existe mais


def process_row(client, row, backup_file, dry_run):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    started = time.perf_counter()
    env_id = int(row["environmentId"])
    map_id = int(row["mapId"])
    variable_id = int(row["variableId"])
    expected_key = row["variableKey"]

    def finish(status, http_status="", error=""):
        return {
            **row, "status": status, "http_status": http_status, "error": error,
            "timestamp": ts, "duration_seconds": round(time.perf_counter() - started, 3),
        }

    try:
        resp = client.get(f"/environments/{env_id}")
    except requests.exceptions.RequestException as e:
        return finish(STATUS_ERROR, "", f"GET /environments/{env_id} falhou: {e}")
    if resp.status_code != 200:
        return finish(STATUS_ERROR, resp.status_code, f"GET /environments/{env_id}: {resp.text[:300]}")
    environment = resp.json()

    masked = find_masked_secured_vars(environment)
    if masked:
        preview = ", ".join(f"map={m} var={v} key={k}" for m, v, k in masked[:5])
        return finish(
            STATUS_SECURED_MASKED_ABORT, 200,
            "ambiente tem variavel(is) SECURED com valor aparentemente mascarado "
            f"({preview}); abortado por seguranca para nao sobrescrever segredos reais "
            "no PUT. Contate a Sensedia antes de reprocessar esta linha.",
        )

    map_obj, var_obj = locate_variable(environment, map_id, variable_id)
    if var_obj is None:
        return finish(STATUS_NOT_FOUND, 200)
    if var_obj.get("key") != expected_key:
        return finish(
            STATUS_KEY_MISMATCH, 200,
            f"variableId {variable_id} encontrado no map {map_id}, mas a key atual "
            f"('{var_obj.get('key')}') difere da esperada ('{expected_key}') — "
            "revisar manualmente antes de excluir.",
        )

    if dry_run:
        return finish(STATUS_WOULD_DELETE)

    append_backup(backup_file, variable_id, map_id, environment)

    map_obj["vars"] = [v for v in map_obj["vars"] if v.get("id") != variable_id]

    try:
        put_resp = client.put(f"/environments/{env_id}", environment)
    except requests.exceptions.RequestException as e:
        return finish(STATUS_ERROR, "", f"PUT /environments/{env_id} falhou: {e}")

    if put_resp.status_code == 403:
        if is_connector_block(put_resp.text):
            return finish(STATUS_BLOCKED_BY_CONNECTOR, 403, put_resp.text[:300])
        return finish(
            STATUS_FORBIDDEN_CHECK_PERMISSIONS, 403,
            "PUT retornou 403 sem mencionar uso por Connector — provavelmente a "
            "credencial usada nao tem permissao de EDICAO em Environments "
            f"(ver README, secao de credenciais). Resposta da API: {put_resp.text[:300]}",
        )
    if put_resp.status_code not in (200, 201):
        return finish(STATUS_ERROR, put_resp.status_code, put_resp.text[:300])

    try:
        confirm_resp = client.get(f"/environments/{env_id}")
    except requests.exceptions.RequestException as e:
        return finish(STATUS_DELETE_NOT_CONFIRMED, put_resp.status_code, f"validacao falhou: {e}")
    if confirm_resp.status_code != 200:
        return finish(
            STATUS_DELETE_NOT_CONFIRMED, put_resp.status_code,
            f"validacao falhou: GET retornou {confirm_resp.status_code}",
        )
    _, still_there = locate_variable(confirm_resp.json(), map_id, variable_id)
    if still_there is not None:
        return finish(
            STATUS_DELETE_NOT_CONFIRMED, put_resp.status_code,
            "PUT respondeu OK mas a variavel ainda aparece numa nova consulta",
        )
    return finish(STATUS_DELETED, put_resp.status_code)


def format_duration(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, help="CSV com as variaveis a excluir (saida do script de identificacao)")
    parser.add_argument("--env-file", default=os.path.join(ROOT, ".env"))
    parser.add_argument("--output-dir", default=os.path.join(ROOT, "backup"))
    parser.add_argument("--dry-run", action="store_true", help="simula sem alterar nada (so consulta e faz relatorio)")
    parser.add_argument("--limit", type=int, default=None, help="processa no maximo N linhas pendentes nesta execucao")
    parser.add_argument("--retry-errors", action="store_true", help="reprocessa linhas com status error/delete_not_confirmed/secured_value_masked_abort/key_mismatch_error")
    parser.add_argument("--sleep-ms", type=int, default=250, help="pausa entre variaveis, em milissegundos (padrao: 250)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.env_file)
    report_file = os.path.join(args.output_dir, "report.csv")

    def backup_file_for(env_id):
        return os.path.join(args.output_dir, f"environment_{env_id}_backup.jsonl")

    rows = load_input_rows(args.input)
    prior_status = load_report_status(report_file)

    def already_done(status):
        if status in TERMINAL_ALWAYS:
            return True
        if status in TERMINAL_ONLY_IN_DRY_RUN and args.dry_run:
            return True
        if status in RETRYABLE_BY_DEFAULT_BLOCKED and not args.retry_errors:
            return True
        return False

    pending = [r for r in rows if not already_done(prior_status.get(r["variableId"]))]
    if args.limit:
        pending = pending[: args.limit]

    print(f"input: {args.input} | output-dir: {args.output_dir}")
    print(f"total no CSV: {len(rows)} | pendentes nesta execucao: {len(pending)}")
    if args.dry_run:
        print(
            "modo DRY-RUN: nenhuma variavel sera excluida de verdade, e nenhum "
            "arquivo de backup sera gravado (o backup so e feito imediatamente "
            "antes de uma alteracao real)"
        )
    if not pending:
        print("nada a fazer.")
        return

    try:
        client = ApiClient(cfg, verbose=args.verbose)
    except AuthError as e:
        raise SystemExit(str(e))

    durations = []
    counts = {}
    for i, row in enumerate(pending, start=1):
        result = process_row(client, row, backup_file_for(int(row["environmentId"])), args.dry_run)
        append_report(report_file, result)
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        durations.append(result["duration_seconds"])
        durations = durations[-50:]

        remaining = len(pending) - i
        eta = f" | ETA: ~{format_duration((sum(durations) / len(durations)) * remaining)}" if remaining else ""
        print(f"[{i}/{len(pending)}] variableId={row['variableId']} ({row['variableKey']}) -> {result['status']}{eta}")
        if result["error"]:
            print(f"    detalhe: {result['error']}")

        if i < len(pending) and args.sleep_ms:
            time.sleep(args.sleep_ms / 1000)

    print("\nResumo desta execucao:", counts)
    print(f"Relatorio completo em: {report_file}")
    if args.dry_run:
        print("Nenhum backup foi gravado (modo DRY-RUN nao altera nada, entao nao ha o que salvar antes)")
    else:
        print(f"Backups completos em: {args.output_dir}/environment_<id>_backup.jsonl")


if __name__ == "__main__":
    main()
