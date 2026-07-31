"""Diagnóstico do token sem expor o valor: mostra tamanho e caracteres
suspeitos (espaços, aspas, quebras de linha) nas pontas."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import get_token  # noqa: E402


def main():
    token = get_token()
    print(f"tamanho: {len(token)}")
    print(f"repr primeiros 3 chars: {token[:3]!r}")
    print(f"repr últimos 3 chars: {token[-3:]!r}")
    print(f"contém espaço? {' ' in token}")
    print(f"contém aspas? {chr(34) in token or chr(39) in token}")
    print(f"contém \\r ou \\n? {chr(13) in token or chr(10) in token}")


if __name__ == "__main__":
    main()
