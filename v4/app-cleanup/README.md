# app-cleanup (APIM v4)

Remove APPs (client credentials) obsoletas de um ambiente APIM v4 via Manager API,
com backup do payload completo antes de cada exclusão e confirmação pós-delete
(não confia apenas no status HTTP do `DELETE`).

## Pré-requisitos

- Python 3.8+
- `pip install requests`
- Um token de autenticação (`Sensedia-Auth`) e `userId` válidos para o ambiente alvo
- A URL base do Manager do ambiente alvo

## Configuração

Copie `.env.example` para `.env` e preencha:

```bash
cp .env.example .env
```

Para múltiplos ambientes/tenants, use um arquivo por ambiente (ex: `.env.staging`,
`.env.producao`) e passe via `--env-file`.

## Formato do arquivo de entrada

Um CSV de uma coluna com header `clientId` (veja `appsToDelete.example.txt`):

```
clientId
00000000-0000-0000-0000-000000000001
00000000-0000-0000-0000-000000000002
```

## Uso

```bash
# 1. Inspeção read-only da API (opcional, ajuda a validar conectividade/formato)
python3 scripts/inspect_api.py

# 2. Dry-run: busca e faz backup, mas não deleta
python3 scripts/sanitize_apps.py --input appsToDelete.txt --dry-run --limit 5

# 3. Execução real
python3 scripts/sanitize_apps.py --input appsToDelete.txt --env-file .env

# 4. Verificação pontual pós-execução
python3 scripts/verify_delete.py <clientId>
```

O script é resumível: reexecuções pulam `clientId`s já processados com sucesso
(`deleted` ou `not_found`). Use `--retry-errors` para reprocessar falhas anteriores.

## Scripts

| Script | Função |
|---|---|
| `sanitize_apps.py` | Script principal — busca, backup e exclusão das APPs |
| `verify_delete.py` | Confirma que um `clientId` específico não existe mais |
| `inspect_api.py` | Sondagem read-only da API (formato de resposta, contagens) |
| `diag_token.py` | Diagnostica problemas comuns no token (espaços, aspas, quebras de linha) sem expor o valor |
| `common.py` | Cliente HTTP compartilhado (autenticação, XSRF, redact de segredos) |

## Saída

Por execução, gera em `backup/<tag-do-env-file>/`:
- `apps_backup.jsonl` — payload completo de cada APP encontrada, antes da exclusão
- `report.csv` — status por `clientId` (`deleted`, `not_found`, `error`, `delete_not_confirmed`, `would_delete`)
