"""Shared helpers for the APIM v4 App cleanup scripts."""
import os
import re

import requests

API_BASE_PATH = "/api-manager/api/v3"  # fixo entre ambientes (vem do swagger)
REQUEST_TIMEOUT = 120

_REDACT_KEY_RE = re.compile(r"secret|password|clientsecret", re.IGNORECASE)


def load_dotenv(path=".env"):
    """Minimal .env loader (supports hyphenated keys like `sensedia-auth`)."""
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


def get_token(env_path=".env"):
    env = load_dotenv(env_path)
    token = env.get("sensedia-auth") or os.environ.get("SENSEDIA_AUTH")
    if not token:
        raise SystemExit(
            f"Token não encontrado. Defina 'sensedia-auth=<token>' em {env_path} "
            "ou exporte SENSEDIA_AUTH no shell."
        )
    return token


def get_user_id(env_path=".env"):
    env = load_dotenv(env_path)
    user_id = env.get("userId") or os.environ.get("USER_ID")
    if not user_id:
        raise SystemExit(
            f"userId não encontrado. Defina 'userId=<id>' em {env_path} "
            "ou exporte USER_ID no shell."
        )
    return user_id


def get_origin(env_path=".env"):
    env = load_dotenv(env_path)
    origin = env.get("MANAGER_ORIGIN") or os.environ.get("MANAGER_ORIGIN")
    if not origin:
        raise SystemExit(
            f"MANAGER_ORIGIN não encontrado. Defina 'MANAGER_ORIGIN=<url do seu Manager>' "
            f"em {env_path} ou exporte MANAGER_ORIGIN no shell."
        )
    return origin


def _redact_headers(headers):
    out = dict(headers)
    for k in out:
        if k.lower() in ("sensedia-auth", "xsrf-token"):
            out[k] = "***REDACTED***"
    return out


class ApiClient:
    """Cliente autenticado para a Manager API: resolve Sensedia-Auth, XSRF-TOKEN
    (via /login/swagger-editor), userId e a base URL a partir do arquivo de
    config indicado (permite trocar de ambiente só troca de --env-file)."""

    def __init__(self, env_path=".env", verbose=False):
        self.verbose = verbose
        env = load_dotenv(env_path)
        self.token = get_token(env_path)
        self.user_id = get_user_id(env_path)
        self.origin = get_origin(env_path)
        # MANAGER_BASE_URL só precisa ser definido se o path da API divergir do padrão
        self.base_url = (
            env.get("MANAGER_BASE_URL")
            or os.environ.get("MANAGER_BASE_URL")
            or f"{self.origin}{API_BASE_PATH}"
        )
        if self.verbose:
            print(f"[verbose] base_url={self.base_url} origin={self.origin} userId={self.user_id}")
        self.xsrf = self._fetch_xsrf()

    def _log_response(self, resp):
        if not self.verbose:
            return
        print(f"[verbose] -> {resp.request.method} {resp.request.url}")
        print(f"[verbose]    request headers: {_redact_headers(resp.request.headers)}")
        print(f"[verbose]    status: {resp.status_code}")
        print(f"[verbose]    response headers: {dict(resp.headers)}")
        print(f"[verbose]    body (primeiros 500 chars): {resp.text[:500]!r}")

    # endpoints candidatos pra obter o XSRF-TOKEN sem exigir ele mesmo (varia
    # por ambiente/versão do Manager — ex: /login/swagger-editor não existe
    # em todo deploy)
    XSRF_BOOTSTRAP_PATHS = ["/login/swagger-editor", "/federated/authorize"]

    def _fetch_xsrf(self):
        """Tenta obter um XSRF-TOKEN. Se nenhum endpoint candidato devolver um,
        retorna None — nem todo ambiente exige XSRF-TOKEN (depende do WAF/gateway
        na frente do Manager); a própria API avisa via erro de CSRF se precisar."""
        for path in self.XSRF_BOOTSTRAP_PATHS:
            resp = requests.get(
                f"{self.base_url}{path}",
                headers={"Sensedia-Auth": self.token, "Origin": self.origin, "userId": self.user_id},
                timeout=REQUEST_TIMEOUT,
            )
            self._log_response(resp)
            xsrf = resp.cookies.get("XSRF-TOKEN") or resp.headers.get("xsrf-token")
            if xsrf:
                if self.verbose:
                    print(f"[verbose] XSRF-TOKEN obtido via {path}")
                return xsrf

        if self.verbose:
            print("[verbose] Nenhum XSRF-TOKEN obtido nos endpoints candidatos — seguindo sem ele.")
        return None

    def _headers(self, extra=None):
        headers = {
            "Sensedia-Auth": self.token,
            "userId": self.user_id,
            "Origin": self.origin,
            "Accept": "application/json",
        }
        if self.xsrf:
            headers["XSRF-TOKEN"] = self.xsrf
        if extra:
            headers.update(extra)
        return headers

    @staticmethod
    def _is_csrf_error(resp):
        return resp.status_code == 401 and "CSRF Token" in resp.text

    def _request(self, method, path, **kwargs):
        resp = requests.request(method, f"{self.base_url}{path}", headers=self._headers(), timeout=REQUEST_TIMEOUT, **kwargs)
        self._log_response(resp)
        if self._is_csrf_error(resp) and not self.xsrf:
            # este ambiente exige XSRF-TOKEN e nenhum bootstrap conseguiu um antes;
            # deixa claro em vez de simplesmente falhar calado
            raise SystemExit(
                f"{method} {path} exige XSRF-TOKEN mas nenhum dos endpoints em "
                f"XSRF_BOOTSTRAP_PATHS ({self.XSRF_BOOTSTRAP_PATHS}) devolveu um para "
                f"este ambiente. Descubra no DevTools da UI qual chamada devolve o "
                f"header xsrf-token e adicione o path em ApiClient.XSRF_BOOTSTRAP_PATHS."
            )
        return resp

    def get(self, path, params=None, **kwargs):
        return self._request("GET", path, params=params, **kwargs)

    def delete(self, path, **kwargs):
        return self._request("DELETE", path, **kwargs)

    def post(self, path, json=None, **kwargs):
        return self._request("POST", path, json=json, **kwargs)


def redact(obj):
    """Recursively mask values of keys that look like secrets, for safe local dumps."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _REDACT_KEY_RE.search(str(k)):
                out[k] = "***REDACTED***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj
