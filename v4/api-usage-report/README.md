# api-usage-report (APIM v4)

Gera um relatório (CSV) das APIs de um tenant APIM v4 com pouca ou nenhuma
utilização, cruzando cada API/ambiente com sua contagem de chamadas em
janelas de 7, 30 e 90 dias:

```
apiId,apiName,apiUrl,environmentId,environmentName,qtdeChamadas7d,qtdeChamadas30d,qtdeChamadas90d
```

Ordenado por `qtdeChamadas90d` crescente — as APIs com menos uso aparecem
no topo. Script **somente-leitura** — nunca altera nada no tenant.

## Como funciona

O relatório cruza duas fontes:

1. **Manager API** (`GET /apis` + `GET /apis/{id}`) — inventário completo de
   todas as APIs do tenant e, para cada uma, os ambientes onde está
   deployada (id, nome, `inboundUrl`). A listagem (`/apis`) sempre devolve
   `environments: []` vazio; só o detalhe (`/apis/{id}`) traz os ambientes
   reais — por isso o script faz uma chamada de detalhe por API (com cache
   local em `output/api_inventory.jsonl`, reaproveitado entre execuções e
   buscado com chamadas concorrentes — ver `--concurrency`).
   IDs negativos (ex: `-1` "API Manager", `-2` "API Metrics") são APIs
   internas da plataforma e são excluídos automaticamente. Deployments em
   `environmentId -1` ("Internal Environment") também são excluídos, mesmo
   quando a API em si é de cliente — é um ambiente interno da plataforma,
   não um ambiente de cliente. Na teoria nenhum usuário comum consegue
   listar isso pela UI, mas o filtro fica por defesa em profundidade.

2. **Sensedia Analytics API**
   (`POST /analytics/v1/products/api-gateway/calls/query`) — mesmo host e
   mesma autenticação do Manager (`Sensedia-Auth`/`userId`/XSRF), mas expõe
   uma Query DSL do OpenSearch. O script faz **uma única query de
   agregação** (filtros de data + `terms` aninhado por `sensedia.api.id` e
   `sensedia.environment.id`) cobrindo as três janelas de uma vez, em vez de
   somar contagens diárias via Manager API — essa alternativa foi descartada
   porque exigiria 1 chamada HTTP por dia por par API/ambiente (~90x mais
   cara), e os dois outros endpoints candidatos do Manager (`/calls` e
   `/metrics/calls`) não respeitam nenhum filtro de data nesta investigação
   (ver seção "Investigação" abaixo).

   Uma API/ambiente sem nenhuma chamada no período não aparece na agregação
   (não existe documento para agregar) — o script faz um LEFT JOIN entre o
   inventário (sempre completo) e a agregação (só cobre quem teve alguma
   chamada), tratando ausência como `0`.

### ⚠️ Pré-requisito não óbvio: plano da Analytics API

O endpoint da Analytics API só responde (`200`) se o **app dono do
access-token tiver o plano "Sensedia Analytics API" associado**, além do
plano "API Manager Front" que normalmente já vem associado. Sem esse plano,
a chamada devolve `401` com a **mesma mensagem genérica de token
inválido** que o Manager usa (`Access Token in the request... is invalid`)
— o que engana, porque parece um problema de token/credencial quando na
verdade é falta de plano associado ao app.

Se você tomar esse `401` na Analytics API mesmo com um `sensedia-auth`
válido (confirmado funcionando na Manager API normalmente), associe o
plano "Sensedia Analytics API" ao app correspondente no Access Control
antes de investigar mais a fundo. Para inspecionar os planos disponíveis no
tenant via API: `GET /plans` na Manager API (paginado; filtre pelo nome).

## Pré-requisitos

- Python 3.8+
- `pip install -r requirements.txt`
- Um token de autenticação (`Sensedia-Auth`) e `userId` válidos para o
  ambiente alvo, com o app tendo os planos "API Manager Front" **e**
  "Sensedia Analytics API" associados (ver aviso acima)
- A URL base do Manager do ambiente alvo (a Analytics API usa o mesmo host,
  só troca o base path para `/analytics`)

## Configuração

Copie o arquivo de exemplo:

```bash
cp .env.example .env
```

Para múltiplos ambientes/tenants, use um arquivo por ambiente (ex:
`.env.staging`, `.env.producao`) e passe via `--env-file`.

## Uso

```bash
# relatório completo do tenant
python3 scripts/report_low_usage_apis.py --env-file .env

# smoke test antes de rodar no tenant inteiro
python3 scripts/report_low_usage_apis.py --env-file .env --api-ids 123,456
python3 scripts/report_low_usage_apis.py --env-file .env --limit 20
```

Outras opções úteis:

| Opção | Para que serve |
|---|---|
| `--api-ids 123,456` | Restringe o inventário a estes `apiId`s |
| `--limit N` | Processa só as N primeiras APIs do inventário |
| `--refresh-inventory` | Ignora o cache `output/api_inventory.jsonl` e rebusca `/apis/{id}` para todas as APIs |
| `--concurrency 8` | Chamadas HTTP concorrentes na montagem do inventário (padrão: 8) |
| `--sleep-ms 20` | Pausa por chamada dentro de cada worker (padrão: 20ms) |
| `--verbose` | Mostra detalhes de cada chamada HTTP |

## Onde ficam os resultados

Em `output/` (criada automaticamente):

- **`output/report.csv`** — o relatório final, exatamente com as 8 colunas
  descritas no topo, ordenado por `qtdeChamadas90d` crescente.
- **`output/api_inventory.jsonl`** — cache do detalhe de cada API
  (id, nome, basePath, ambientes) — reaproveitado entre execuções para não
  refazer as chamadas de detalhe a cada rodada.

## Scripts

| Script | Função |
|---|---|
| `report_low_usage_apis.py` | Script principal — gera o relatório |
| `common.py` | Cliente HTTP compartilhado (autenticação Manager + Analytics, XSRF, redact de segredos) |

## Investigação (por que a Analytics API, e não a Manager API, para as contagens)

Testado empiricamente contra um tenant de testes:

- `GET /calls/count/{date}` (Manager API) filtra corretamente por dia/API/
  ambiente, mas só aceita **uma data por chamada** — somar 90 dias por par
  API/ambiente seria caro demais para tenants grandes (dezenas de milhares
  de chamadas HTTP).
- `GET /calls` e `GET /metrics/calls` (Manager API) **ignoram qualquer
  filtro de data testado** (`dateFrom`/`dateTo`, `startDate`/`endDate`,
  `initialDate`/`finalDate`, `days`) — sempre devolveram o mesmo total
  agregado, independente da janela pedida. Não são confiáveis para janelas
  específicas.
- `POST /analytics/v1/products/api-gateway/calls/query` (Analytics API)
  aceita Query DSL do OpenSearch — permite agregar por `sensedia.api.id` e
  `sensedia.environment.id` com filtros de data reais, cobrindo o tenant
  inteiro numa única chamada. É a fonte usada pelo script final.
- A documentação oficial (docs.sensedia.com, "Como obter respostas do antigo
  api-metrics usando a Analytics API") confirma que, na v4, a Base URL é a
  mesma do Manager e a autenticação é o mesmo header `sensedia-auth` — mas
  avisa que o endpoint `/traces/query`/`/calls/query` tem rate limit/timeout
  e é indicado só para "consultas pontuais"; para extração mais completa a
  documentação recomenda o recurso de Data Streaming. Como este script faz
  apenas uma query de agregação por execução, está dentro do uso pontual
  esperado.

## Performance

O passo mais lento é a montagem do inventário (`GET /apis/{id}`, uma
chamada por API do tenant — a listagem `/apis` não traz os ambientes). Em
tenants com centenas de APIs, isso pode ser bem mais lento que a query de
agregação em si; o script já paraleliza essas chamadas (`--concurrency`,
padrão 8) e cacheia o resultado entre execuções (`output/api_inventory.jsonl`),
mas ajuste `--concurrency` conforme a capacidade do ambiente-alvo.
