"""Confere se um clientId específico realmente deixou de existir na API."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from common import ApiClient  # noqa: E402


def main():
    client_id = sys.argv[1]
    client = ApiClient()

    count_resp = client.get("/apps/count")
    print(f"/apps/count -> {count_resp.status_code} {count_resp.text}")

    filter_resp = client.get("/apps", params={"clientId": client_id})
    print(f"/apps?clientId={client_id} -> {filter_resp.status_code} {filter_resp.json()}")


if __name__ == "__main__":
    main()
