# app-credential-rotation (APIM v4)

Scripts para bloquear APPs, revogar access tokens e trocar as credenciais (client_id e
secret) das APPs de um ambiente API Manager v4. Usam **somente a Manager API**, com o
token de um usuário administrador: cada operação fica registrada no audit do API
Manager com esse usuário, e também no relatório local de cada execução.

| Script | O que faz | Chamadas na Manager API |
|---|---|---|
| `list_apps.py` | Inventário das APPs (arquivo de entrada dos outros scripts) | `GET /apps` |
| `apps.py --mode block` | Bloqueia as APPs: nenhum token novo é emitido | `PUT /apps/{id}` (status `CANCELLED`) |
| `apps.py --mode unblock` | Desfaz o bloqueio feito pelo script | `PUT /apps/{id}` (status anterior) |
| `apps.py --mode recreate` | Troca client_id e secret recriando a APP com a mesma configuração | `PUT /apps/{id}` + `POST /apps` |
| `revoke_tokens.py` | Revoga os access tokens ativos das APPs | `GET` e `PUT /access-tokens/{code}` |

## Como funciona

- **Bloqueio.** A APP com status `CANCELLED` deixa de emitir tokens. Os tokens que já
  foram emitidos continuam válidos até expirar ou ser revogados: rode o
  `revoke_tokens.py` depois.
- **Troca de credenciais (`recreate`).** O API Manager v4 não troca o secret de uma APP
  existente, então o script recria a APP:
  1. guarda o payload completo da APP (APIs, planos, developer, extraInfo) no backup;
  2. renomeia a APP atual para `<nome> [substituído AAAA-MM-DD]` e muda o status para
     `CANCELLED` (o nome de APP é único; a antiga fica guardada para consulta);
  3. cria a APP nova com o nome original e a mesma configuração: o API Manager gera
     client_id e secret novos;
  4. grava as credenciais novas em `output/<tag>/new_credentials.csv`;
  5. confere que a APP nova tem os mesmos planos e que a antiga ficou `CANCELLED`.

  Se a criação falhar, a APP antiga volta ao nome e status originais. **O client_id muda
  junto com o secret**: os consumidores precisam atualizar os dois.
- **Revogação.** Lista os tokens ativos de cada APP do arquivo de entrada e revoga um a
  um. Funciona também para a APP antiga depois do `recreate` (o client_id dela continua
  o mesmo).

## Pré-requisitos

- Python 3.8+ e `pip install -r requirements.txt`
- Um usuário administrador do API Manager com permissão de editar APPs e Access Tokens
  **e** a permissão SECRETS (sem ela client_id, secret e código dos tokens voltam
  mascarados e os scripts param)
- O token (`Sensedia-Auth`) e o `userId` desse usuário
- `gpg`, se for usar `--gpg-passphrase-file`

## Configuração

```bash
cp .env.example .env
```

Preencha `sensedia-auth`, `userId` e `MANAGER_ORIGIN` (ex.:
`https://manager-<empresa>.sensedia.com`). Para mais de um ambiente, use um arquivo por
ambiente (`.env.producao`, `.env.homologacao`) e passe com `--env-file`.

## Uso

```bash
# 1. inventário (arquivo com a coluna clientId; revise e deixe só as APPs desejadas)
python3 scripts/list_apps.py --env-file .env --output appsToRotate.txt

# 2. (opcional) bloquear tudo de imediato
python3 scripts/apps.py --mode block --input appsToRotate.txt --env-file .env --dry-run
python3 scripts/apps.py --mode block --input appsToRotate.txt --env-file .env

# 3. revogar os tokens ativos (todos, ou só os criados depois de um horário, em UTC)
python3 scripts/revoke_tokens.py --input appsToRotate.txt --env-file .env --dry-run
python3 scripts/revoke_tokens.py --input appsToRotate.txt --env-file .env --created-after 2026-01-31T12:00

# 4. trocar as credenciais: comece com uma APP e confira antes de seguir
python3 scripts/apps.py --mode recreate --input appsToRotate.txt --env-file .env --dry-run
python3 scripts/apps.py --mode recreate --input appsToRotate.txt --env-file .env --only <clientId>
python3 scripts/apps.py --mode recreate --input appsToRotate.txt --env-file .env --gpg-passphrase-file ~/.senha

# 5. revogar os tokens que as APPs antigas ainda tiverem
python3 scripts/revoke_tokens.py --input appsToRotate.txt --env-file .env
```

Todos os scripts que alteram dados aceitam `--dry-run`, `--limit`, `--only <clientId>`,
`--retry-errors` e `--verbose`, e podem ser reexecutados: pulam o que já foi concluído.

## Saída

Em `backup/<tag-do-env-file>/`:
- `report.csv` e `report_tokens.csv`: resultado de cada item, com o usuário que operou e
  o horário
- `apps_backup.jsonl`: payload completo de cada APP antes da mudança (**contém o secret
  antigo**)
- `tokens_backup.jsonl`: dados dos tokens revogados (código mascarado + sha256)

Em `output/<tag-do-env-file>/`:
- `new_credentials.csv` (permissão 0600): client_id antigo, client_id novo e secret novo
  de cada APP recriada, para entregar a quem consome a APP. Com `--gpg-passphrase-file`
  o arquivo sai cifrado (AES256) e o texto puro é apagado.

## Cuidados

- **As integrações param** quando a APP é bloqueada ou recriada, até o consumidor
  receber e configurar as credenciais novas. Combine a janela com cada consumidor.
- A APP antiga fica `CANCELLED` com o sufixo `[substituído AAAA-MM-DD]`; apague pela
  interface quando não precisar mais dela.
- APPs com a mesma credencial configurada em vários lugares (por exemplo, em
  interceptors que comparam o client_id) precisam ser ajustadas depois da troca.
- `backup/` e `output/` contêm credenciais: guarde em local seguro e apague quando
  terminar.
- As APPs internas da plataforma (ID negativo) não aparecem no inventário e são
  tratadas pela Sensedia.
