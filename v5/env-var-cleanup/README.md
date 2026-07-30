# Exclusão segura de variáveis de ambiente — API Manager v5

Este script exclui, uma por uma, as variáveis de ambiente listadas em um CSV
(a lista final gerada pelo script de identificação, já revalidada como segura para exclusão).
Ele nunca processa variáveis em lote e sempre confirma cada exclusão com uma
nova consulta antes de marcar a linha como concluída.

Você pode interromper a execução a qualquer momento (Ctrl+C) e rodar o mesmo
comando de novo depois — ele retoma de onde parou, sem repetir o que já foi
concluído.

## 1. Pré-requisitos

- Python 3.8 ou mais recente instalado (`python3 --version`).
- Acesso à internet para o host do seu API Manager.
- Um usuário **Super Admin** do seu tenant, para gerar as credenciais no passo 2.

Instale a única dependência do script:

```bash
pip install -r requirements.txt
```

## 2. Gerar as credenciais de acesso

> ⚠️ **Use uma Credencial de Segurança (Security Credential), não uma
> credencial de Client App.** Existem dois tipos de credencial no Access
> Control e eles **não são equivalentes** para este script:
>
> - **Client App** (`Access Control → Account Settings → Credentials`, a
>   nível de organização/app) — gera um token **sem usuário associado**.
>   Isso é um bug conhecido do API Manager v5 (confirmado empiricamente, ver
>   seção 10): quebra `GET`/`PUT` em qualquer ambiente cuja visibilidade
>   dependa de checagem de grupo do usuário (ex.: visibilidade do tipo
>   `GROUP`), com `HTTP 500` (`CommunicationException` / "There was an error
>   communicating with Access Control service"). Além disso, este tipo de
>   credencial nem é aceito pelo endpoint de token abaixo (`401
>   invalid_client`) — os dois tipos vivem em registros separados no Access
>   Control.
> - **Credencial de Segurança** (`Access Control → [ícone no canto superior
>   direito] → My Account Settings → Credentials`, por usuário) — é a que
>   este script precisa. Gera um token associado ao usuário que a criou,
>   evitando o bug acima, e herda diretamente as permissões desse usuário
>   (sem precisar atribuir nenhuma Role separada de Environments).

Passo a passo (documentação oficial: [docs.sensedia.com/pt-BR/docs/access-control/users/security-credentials](https://docs.sensedia.com/pt-BR/docs/access-control/users/security-credentials)):

1. Acesse o **API Manager** com um usuário **Super Admin**.
2. Clique no ícone no canto superior direito da tela.
3. Clique em **My Account Settings**.
4. Vá na aba **Credentials** e clique em **Generate Credentials**.
5. Anote o **Client ID** e o **Client Secret** exibidos — o secret **não é
   exibido novamente**.

Antes de gerar, confirme que a conta usada atende aos pré-requisitos (a
credencial não funciona se algum destes não for atendido):

- É um usuário **Super Admin**.
- O login **não é federado** (SSO) — credenciais de segurança não podem ser
  geradas com login federado.
- **MFA está desabilitado** nessa conta — credenciais de segurança não
  funcionam com [MFA](https://docs.sensedia.com/en-US/docs/access-control/users/mfa)
  habilitado.
- Não há já uma credencial de segurança ativa para esse usuário — só é
  permitida **uma por usuário**; se já existir uma, revogue-a antes (mesma
  aba **Credentials** → **Revoke Credentials** → **Remove**).

As credenciais expiram em 3650 dias (10 anos), mas cada **token** gerado com
elas tem vida útil padrão de 86400 segundos (24h).

> Uma credencial de Client App já gerada para outro uso **não deve ser
> reaproveitada aqui** — gere uma Credencial de Segurança específica para
> este script.

## 3. Configurar o `.env`

Copie o arquivo de exemplo:

```bash
cp .env.example .env
```

`BASE_URL` e `TOKEN_URL` já vêm preenchidos com os valores padrão confirmados
para tenants v5:

- `BASE_URL=https://platform-production.sensedia.com/api-manager/api/v3`
- `TOKEN_URL=https://platform-production.sensedia.com/user-management/v1/oauth2/token`
  (**este é o endpoint específico de Credencial de Segurança** — diferente
  do endpoint antigo de Client App, `/access-control/api/v1/oauth2/token`,
  que não reconhece este tipo de credencial)

Só ajuste esses dois valores se o seu tenant usar um **host dedicado** (por
exemplo, ambientes PCI ou cluster próprio) — nesse caso, use o mesmo host que
você já usa para acessar o Manager pelo navegador, mantendo o caminho de cada
URL.

Edite `.env` e preencha:

- `CLIENT_ID` / `CLIENT_SECRET` — gerados no passo 2.
- `SCOPE` — já vem preenchido com `apis/all` (escopo confirmado para este
  endpoint); normalmente não precisa alterar.

**Nunca compartilhe o arquivo `.env` preenchido** (contém uma credencial
secreta) e não o envie por e-mail, chat ou repositório de código.

A autenticação usa sempre **HTTP Basic Auth** no endpoint de token — é o
único formato aceito (uma tentativa sem o header Basic é rejeitada com
`400 Authorization header is required`, mesmo enviando as credenciais no
corpo). Se o script falhar ao gerar o token com erro `401`
(`invalid_client` / "does not exist or is inactive"), o problema é a
credencial em si, não o formato da requisição:

1. Confira se `TOKEN_URL` é o endpoint de Credencial de Segurança acima (não
   o antigo endpoint de Client App).
2. Confira se `CLIENT_ID`/`CLIENT_SECRET` foram copiados **exatamente** (sem
   espaços, sem quebra de linha no meio) — erro de cópia é a causa mais
   comum, já que o `Client Secret` só é exibido uma vez.
3. Confira em **My Account Settings → Credentials** se essa credencial ainda
   aparece como ativa.
4. Se persistir, **revogue e gere uma credencial nova**.

## 4. Rodar primeiro em modo simulação (`--dry-run`)

**Sempre rode com `--dry-run` antes de rodar de verdade.** Nesse modo o
script consulta tudo, mostra o que faria, mas não altera nada:

```bash
python3 sanitize_variables.py --input confirmado_seguro_deletar.csv --dry-run
```

Um exemplo de CSV de entrada (mesmo formato gerado pelo script de
identificação) está em `exemplo_input.csv`.

Revise a saída no terminal e o arquivo `backup/report.csv` gerado. Confira se
os status fazem sentido antes de seguir para a execução real.

## 5. Rodar de verdade

Quando estiver confiante no resultado da simulação, rode sem `--dry-run`:

```bash
python3 sanitize_variables.py --input confirmado_seguro_deletar.csv
```

O script processa uma variável por vez, mostrando o progresso e uma
estimativa de tempo restante. Se a execução for interrompida por qualquer
motivo (queda de rede, Ctrl+C, etc.), **basta rodar o mesmo comando de novo**
— o script pula automaticamente o que já foi concluído com sucesso.

### Outras opções úteis

| Opção | Para que serve |
|---|---|
| `--limit N` | Processa no máximo N variáveis pendentes nesta execução (útil para testar com um lote pequeno antes do restante) |
| `--retry-errors` | Reprocessa linhas que ficaram com status de erro em execuções anteriores (ver tabela de status abaixo) |
| `--sleep-ms 250` | Pausa entre cada variável, em milissegundos (padrão: 250ms — evita sobrecarregar a API) |
| `--verbose` | Mostra detalhes de cada chamada HTTP (útil para diagnosticar problemas) |

## 6. Onde ficam os resultados

Tudo fica na pasta `backup/` (criada automaticamente):

- **`backup/report.csv`** — uma linha por variável processada, com o status
  final. É este arquivo que o script usa para saber o que já foi feito.
- **`backup/environment_<ID>_backup.jsonl`** — uma cópia completa do
  ambiente, feita imediatamente **antes** de cada alteração real (não é
  gerado em modo `--dry-run`). Serve para restauração manual em caso de
  necessidade — guarde esses arquivos até ter certeza de que tudo está OK.

## 7. Como interpretar o `status` no relatório

| Status | Significado | Ação recomendada |
|---|---|---|
| `deleted` | Variável excluída e confirmada por uma nova consulta | Nenhuma |
| `not_found` | A variável já não existia mais no ambiente (pode já ter sido removida antes) | Nenhuma |
| `would_delete` | Simulação (`--dry-run`): seria excluída | Revisar antes de rodar sem `--dry-run` |
| `blocked_by_connector` | A API bloqueou a exclusão porque a variável está em uso por um **Connector** | Esperado pela plataforma — variável em uso, não excluir agora. Se quiser removê-la, é preciso primeiro desvincular o Connector |
| `forbidden_check_permissions` | A API recusou a exclusão com `403`, mas sem indicar uso por Connector — provável falta de permissão de **edição em Environments** na credencial usada | Confirmar que o usuário Super Admin por trás da credencial (passo 2 acima) ainda está ativo e com permissão de Environments, depois reprocessar com `--retry-errors` |
| `delete_not_confirmed` | A exclusão foi aceita (HTTP OK), mas uma nova consulta ainda mostra a variável | Reprocessar com `--retry-errors`; se persistir, contatar a Sensedia |
| `key_mismatch_error` | A variável existe no ambiente, mas com uma chave (`key`) diferente da esperada pelo CSV — indica que o ambiente mudou desde a geração do CSV | Revisar manualmente antes de decidir se ainda deve ser excluída |
| `secured_value_masked_abort` | O ambiente tem alguma variável do tipo `SECURED` cujo valor parece mascarado nesta consulta. O script **não faz nada** nesse ambiente para não arriscar sobrescrever um segredo real | Contatar a Sensedia antes de reprocessar — precisa confirmar se as credenciais usadas enxergam o valor real dos segredos |
| `error` | Falha de rede ou HTTP inesperada | Ver a coluna `error` do relatório; reprocessar com `--retry-errors` após resolver a causa |

## 8. Sobre a validação de duplicidade de variáveis

A verificação de duplicidade de variáveis (solicitada após a exclusão em
massa) é feita reaproveitando o **script de identificação** — não há um terceiro script
para isso. Depois de concluir as exclusões aqui, rode o script de identificação novamente
para gerar um relatório atualizado de uso e duplicidade.

## 9. Limitações importantes

- O script cobre apenas o que a API do api-manager v5 valida automaticamente
  (uso por Connector). Uso em **interceptors customizados em Java** não é
  detectável por nenhuma automação — se o seu tenant usa esse tipo de
  interceptor, valide manualmente antes de confiar cegamente no CSV.
- Segurança de segredos: o mecanismo de exclusão sempre lê o ambiente inteiro
  e regrava ele de volta (não existe exclusão de variável individual na API).
  O script verifica isso antes de cada gravação (ver `secured_value_masked_abort`
  acima), mas a segurança final depende das credenciais usadas terem
  visibilidade real sobre valores `SECURED`.

## 10. Testando sem depender de dados reais do tenant

`testing/create_test_variables.py` cria variáveis de ambiente **descartáveis**
num ambiente real do seu tenant, para você validar o `sanitize_variables.py`
ponta a ponta antes de rodá-lo contra candidatas de verdade. Ele reaproveita o
mesmo `.env`/autenticação deste script e usa o mesmo mecanismo de
read-modify-write (`GET` → altera só o grupo de teste → `PUT`), então exercita
exatamente o mesmo caminho de risco, na direção inversa.

```bash
# descobre os environmentIds visíveis para esta credencial
python3 testing/create_test_variables.py --list-environments

# cria 5 variáveis de teste no ambiente 10 e gera um CSV no formato aceito
# pelo sanitize_variables.py
python3 testing/create_test_variables.py --environment-id 10

# valide o Script principal contra o CSV gerado
python3 sanitize_variables.py --input testing/test_candidates.csv --dry-run
python3 sanitize_variables.py --input testing/test_candidates.csv

# depois de validar, remova o grupo de teste inteiro
python3 testing/create_test_variables.py --environment-id 10 --cleanup --map-name sanitize-test-XXXXXX
```

Se algum `environmentId` do seu tenant for produção conhecida, informe-o em
`--known-production-env-ids` (ex: `--known-production-env-ids 6,14`) para
exigir uma confirmação extra antes de criar variáveis de teste nele. Por
padrão nenhum ambiente é tratado como produção — a checagem é totalmente
opt-in e local ao seu uso.

## 11. Solução de problemas

### `HTTP 500` / `CommunicationException` / "There was an error communicating with Access Control service"

Se o token OAuth2 foi gerado normalmente (você vê a mensagem `token OAuth2
renovado` no `--verbose`) mas uma chamada a `GET`/`PUT /environments/{id}`
falha com esse erro, **não é um erro de sintaxe do script**.

O script já tenta de novo automaticamente até 3 vezes (espera crescente: 1s,
2s, 4s) antes de repassar o erro, para o caso de ser uma falha intermitente
entre serviços do backend. **Se o erro persistir de forma idêntica em todas
as tentativas**, é um problema consistente — e há uma causa raiz conhecida:

**Causa raiz conhecida e confirmada empiricamente:** um token OAuth2
`client_credentials` gerado a partir de uma credencial de **Client App**
(`Account Settings → Credentials`) não tem usuário associado. Para ambientes
cuja visibilidade dependa de checagem de grupo do usuário atual (ex.:
visibilidade do tipo `GROUP`), o `api-manager` precisa resolver os grupos
desse usuário chamando um serviço interno — como não existe usuário por trás
desse token, essa chamada falha, e o `api-manager` trata isso como erro fatal
(`CommunicationException`/500) em vez de "sem grupos". **Não é** um problema
de escopo/permissão ajustável no Access Control — é o **tipo de credencial**
que precisa mudar.

**Solução:** gere uma **Credencial de Segurança** em `My Account Settings →
Credentials` (ver seção 2 acima) e atualize `CLIENT_ID`/`CLIENT_SECRET` no
`.env`. Ambientes com visibilidade `ORGANIZATION` não são afetados por este
bug — só os com visibilidade `GROUP` acionam a checagem que quebra com
credenciais de Client App.

### `401` (`invalid_client` / "does not exist or is inactive") ao gerar o token

Ver seção 3 acima — na maioria dos casos é `TOKEN_URL` apontando para o
endpoint errado (Client App em vez de Credencial de Segurança) ou um erro de
cópia do `Client Secret`.
