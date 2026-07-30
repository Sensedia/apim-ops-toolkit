# Identificação de variáveis de ambiente não utilizadas — API Manager v5

Este script é **somente-leitura** (nunca altera nada no seu tenant) e
**autossuficiente**: ele não depende de nenhuma lista externa de candidatas.
Ele mesmo descobre todos os ambientes e todas as variáveis do seu tenant e
classifica cada uma como em uso ou sem uso, cruzando com:

- **Interceptors JavaScript** (embutidos nas revisions e também os
  *custom interceptors* reutilizáveis), procurando o padrão
  `$call.environmentVariables.get('CHAVE')`;
- **destination** (URLs) dos componentes REVISION/RESOURCE/OPERATION de cada
  revision, procurando o padrão `$CHAVE`.

## Por que essa identificação é necessária

A API do API Manager v5 só bloqueia a exclusão de uma variável se ela estiver
em uso por um **Connector** — não cobre uso via interceptor ou destination.
Sem essa identificação, uma variável ainda referenciada por um interceptor ou
destination poderia ser apagada por engano. Este script existe para fechar
essa lacuna, gerando diretamente a lista final de variáveis seguras para
exclusão.

A saída dele — o CSV `confirmado_seguro_deletar.csv` — é o **input do script
de exclusão** (script irmão deste, no mesmo repositório), que faz a exclusão
de verdade.

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
>   nível de organização/app) — é o que a documentação mais antiga descreve,
>   e o que este script usava antes. Gera um token **sem usuário associado**,
>   o que causa `HTTP 500` em `GET /apis` e `GET /custom-interceptors` — um
>   bug conhecido do API Manager v5, confirmado empiricamente (ver seção 9).
> - **Credencial de Segurança** (`Access Control → [ícone no canto superior
>   direito] → My Account Settings → Credentials`, por usuário) — é a que
>   este script precisa. Gera um token associado ao usuário que a criou,
>   evitando o bug acima.

Passo a passo (documentação oficial: [docs.sensedia.com/pt-BR/docs/access-control/users/security-credentials](https://docs.sensedia.com/pt-BR/docs/access-control/users/security-credentials)):

1. Acesse o **API Manager** com um usuário **Super Admin**.
2. Clique no ícone no canto superior direito da tela.
3. Clique em **My Account Settings**.
4. Vá na aba **Credentials** e clique em **Generate Credentials**.
5. Anote o **Client ID** e o **Client Secret** exibidos — o secret **não é
   exibido novamente**.

Antes de gerar, confirme que a conta usada atende aos pré-requisitos (a
geração falha silenciosamente ou o token resultante não funciona se algum
destes não for atendido):

- É um usuário **Super Admin**.
- O login **não é federado** (SSO) — credenciais de segurança não podem ser
  geradas com login federado.
- **MFA está desabilitado** nessa conta — credenciais de segurança não
  funcionam com MFA habilitado.
- Não há já uma credencial de segurança ativa para esse usuário — só é
  permitida **uma por usuário**; se já existir uma, revogue-a antes (mesma
  aba **Credentials** → **Revoke Credentials** → **Remove**).

As credenciais expiram em 3650 dias (10 anos), mas cada **token** gerado com
elas tem vida útil padrão de 86400 segundos (24h) — igual ao fluxo anterior.

O endpoint de token (`TOKEN_URL`) e o host do API Manager (`BASE_URL`) **não**
mudam entre os dois tipos de credencial e **não** precisam ser buscados na
tela de credenciais — já vêm com o valor padrão em `.env.example` (ver passo
3). Só ajuste-os manualmente se o seu tenant usar um host dedicado.

> Credenciais já geradas para o script de exclusão **não devem ser
> reaproveitadas aqui** se forem do tipo Client App — gere uma Credencial de
> Segurança específica para este script.

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
2. Confira se `CLIENT_ID`/`CLIENT_SECRET` foram copiados **exatamente**
   (sem espaços, sem quebra de linha no meio, sem caracteres faltando) —
   erro de cópia é a causa mais comum, já que o `Client Secret` só é exibido
   uma vez.
3. Confira em **My Account Settings → Credentials** se essa credencial
   ainda aparece como ativa.
4. Se persistir, **revogue e gere uma credencial nova**, preferindo copiar
   com um botão de "copiar" (se disponível na tela) em vez de selecionar o
   texto manualmente.

## 4. Rodar o script

Não é preciso informar nenhum arquivo de entrada — por padrão o script mapeia
**todos os ambientes do tenant**:

```bash
python3 identify_unused_variables.py
```

Se preferir restringir a identificação a alguns ambientes específicos (por
exemplo, só os ambientes já conhecidos de uma análise anterior):

```bash
python3 identify_unused_variables.py --environment-ids 6,7,10,12,14
```

O script primeiro varre **todas** as APIs, revisions e custom interceptors do
tenant (isso é necessário mesmo restringindo `--environment-ids` — o uso pode
estar em qualquer API do tenant, não só nas dos ambientes escolhidos). Em
seguida, lista os ambientes, busca o detalhe completo de cada um e classifica
todas as variáveis encontradas. Dependendo do tamanho do tenant, a varredura
pode demorar alguns minutos; o script mostra o progresso no terminal.

Ao final, ele imprime um resumo e grava três arquivos na pasta `output/`.

### Outras opções úteis

| Opção | Para que serve |
|---|---|
| `--environment-ids 6,7,10` | Restringe a identificação a esses `environmentId`s (padrão: todos os ambientes do tenant) |
| `--output-dir DIR` | Onde gravar os relatórios (padrão: `./output`) |
| `--sleep-ms 100` | Pausa entre cada chamada HTTP da varredura, em milissegundos (padrão: 100ms — evita sobrecarregar a API) |
| `--verbose` | Mostra detalhes de cada chamada HTTP (útil para diagnosticar problemas) |
| `--allow-empty-scan` | Só use se tiver certeza de que seu tenant genuinamente não tem nenhuma API cadastrada — por padrão o script **aborta** se `GET /apis` não retornar nada, porque isso normalmente indica um problema de credenciais/permissões, não um tenant vazio |
| `--probe` | Testa rapidamente a conectividade com os endpoints principais (uma chamada cada) e sai, sem rodar a identificação completa — use para diagnosticar erros HTTP antes de rodar a varredura inteira (ver seção 9) |

## 5. Onde ficam os resultados

Tudo fica na pasta `output/` (criada automaticamente):

- **`output/confirmado_seguro_deletar.csv`** — todas as variáveis identificadas
  sem nenhuma referência encontrada em interceptors JS ou destinations.
  **É este arquivo que você deve usar como `--input` do script de
  exclusão.**
- **`output/identificacao_variaveis_report.csv`** — uma linha por **toda**
  variável encontrada em qualquer ambiente identificado (em uso ou não), com o
  status e, quando aplicável, a evidência do uso encontrado (em qual
  API/revision/interceptor e em que campo).
- **`output/duplicidade_variaveis.csv`** — variáveis cuja `key` aparece mais
  de uma vez no mesmo ambiente (checagem adicional solicitada após a
  exclusão em massa — ver seção 7).

## 6. Como interpretar o `status` no relatório

| Status | Significado | Ação recomendada |
|---|---|---|
| `confirmado_seguro_para_deletar` | Não foi encontrada nenhuma referência à variável em interceptors JS ou destinations | Segue para o Script B |
| `ainda_usada_interceptor_js` | A variável é referenciada por um interceptor JavaScript (`$call.environmentVariables.get(...)`) | **Não excluir** |
| `ainda_usada_destination` | A variável é referenciada num destination (`$CHAVE`) de algum componente REVISION/RESOURCE/OPERATION | **Não excluir** |

> A coluna `evidence` no `identificacao_variaveis_report.csv` mostra onde
> exatamente o uso foi encontrado (API, revision ou custom interceptor, e o
> campo/trecho do texto), para facilitar a revisão manual de qualquer status
> "ainda usada".

## 7. Sobre o relatório de duplicidade

Além de identificar as variáveis sem uso, o script também verifica — em
todos os ambientes identificados — se existe alguma variável com a mesma `key`
cadastrada mais de uma vez (em qualquer map daquele ambiente). Isso é útil
para validar duplicidade de variáveis depois de uma exclusão em massa: basta
rodar este mesmo script novamente depois que o script de exclusão concluir as
exclusões, e conferir `duplicidade_variaveis.csv`.

## 8. Limitações importantes

- **Interceptors customizados em Java não são cobertos.** A varredura deste
  script processa apenas interceptors **JavaScript** (embutidos em revisions
  e custom interceptors reutilizáveis) e destinations de
  REVISION/RESOURCE/OPERATION. Se o seu tenant usa interceptors custom em
  Java que referenciam variáveis de ambiente, essas referências **não são
  detectáveis** por este script. **Se você usa esse tipo de interceptor,
  valide manualmente o uso de variáveis neles antes de confiar no CSV final
  gerado aqui.**
- **A varredura é propositalmente conservadora.** O padrão de destination
  (`$CHAVE`) é verificado em todo o texto do payload de cada revision/
  interceptor, não só nos campos que você veria como "destination" na tela —
  isso evita perder um uso real por causa de um nome de campo diferente do
  esperado, ao custo de ocasionalmente marcar como "ainda usada" uma
  variável que na verdade não está. Quando isso acontecer, a coluna
  `evidence` do relatório mostra o trecho exato encontrado, para você
  confirmar se é ou não um uso real.
- **Variáveis reutilizáveis entre ambientes (custom interceptors).** Como um
  custom interceptor pode ser usado por APIs de mais de um ambiente, uma
  referência encontrada nele é tratada como válida para **todos os
  ambientes**, não só para aquele em que foi originalmente detectada — de
  novo, por segurança.
- **Nomes de campo não documentados no swagger.** O nome do map dentro de
  `mapVars[]` (`mapName`) é resolvido tentando os campos mais prováveis
  (`name`, `mapName`, `label`); se nenhum bater, o script usa um nome
  genérico (`map-<id>`) só para fins de leitura no relatório — isso não afeta
  a identificação da variável em si, que é sempre feita por `id`.

## 9. Solução de problemas

### Erro de certificado TLS (`SSLError`, `CERTIFICATE_VERIFY_FAILED`) atrás de proxy corporativo

Se sua rede passa o tráfego HTTPS por um proxy corporativo que faz TLS
interception (reemite os certificados com uma CA própria), o `requests` vai
rejeitar essa CA por não reconhecê-la, mesmo que o tráfego em si seja
legítimo.

**Solução recomendada:** aponte o `requests` para o certificado da CA do seu
proxy via a variável de ambiente `REQUESTS_CA_BUNDLE` (lida automaticamente
pela biblioteca, sem precisar de nenhuma mudança no script):

```bash
export REQUESTS_CA_BUNDLE=/caminho/para/ca-do-proxy-corporativo.pem
python3 identify_unused_variables.py
```

Peça esse arquivo `.pem` ao time de infraestrutura/segurança da sua empresa
(geralmente é a mesma CA que o navegador já confia nesse ambiente).

**Último recurso:** a flag `--insecure` desativa completamente a validação de
certificado TLS. Isso expõe o token OAuth2 e o `CLIENT_SECRET` a qualquer
interceptação de tráfego, não só a do proxy corporativo esperado — use
apenas se `REQUESTS_CA_BUNDLE` genuinamente não for uma opção, e nunca em
ambientes onde a rede não é totalmente confiável:

```bash
python3 identify_unused_variables.py --insecure
```

### `HTTP 500` / `CommunicationException` / "There was an error communicating with Access Control service"

Se o token OAuth2 foi gerado normalmente (você vê a mensagem `token OAuth2
renovado` no `--verbose`) mas uma chamada como `GET /apis` falha com esse
erro, o problema é uma falha de comunicação interna do backend do API
Manager com o Access Control — não um erro de sintaxe do script.

O script já tenta novamente automaticamente até 3 vezes (com espera
crescente: 1s, 2s, 4s) antes de desistir, para o caso desse erro ser
intermitente. **Se o erro persistir de forma idêntica em todas as
tentativas** (mesma mensagem, mesmo endpoint, sem variação), não é
instabilidade pontual — é um problema consistente que vale diagnosticar
antes de tentar de novo.

Rode o modo de diagnóstico rápido, que testa cada endpoint isoladamente
(sem rodar a identificação completa, que pode demorar minutos):

```bash
python3 identify_unused_variables.py --probe
```

Ele testa `/environments`, `/variables/values`, `/apps` (endpoints de
controle, que normalmente funcionam) junto com `/apis` e
`/custom-interceptors` (os dois usados na varredura de uso), e já indica a
conclusão mais provável:

- **Só `/apis` e/ou `/custom-interceptors` falham, os demais respondem
  200** — **causa raiz conhecida e confirmada empiricamente**: o token
  OAuth2 foi gerado a partir de uma credencial de **Client App**
  (`Account Settings → Credentials`, a nível de organização/app), que não
  tem usuário associado. O `api-manager`, ao processar `GET /apis` e
  `GET /custom-interceptors`, precisa resolver os grupos do usuário atual
  (RBAC de visibilidade) chamando um serviço interno de user-management —
  como não existe usuário por trás desse token, essa chamada recebe `404`,
  e o `api-manager` trata isso como erro fatal (`CommunicationException`/500)
  em vez de "sem grupos". **Não é** um problema de escopo/permissão
  ajustável no Access Control (confirmamos isso também trocando o perfil do
  Client ID para Super Admin, sem efeito) — é o **tipo de credencial** que
  precisa mudar.

  **Solução:** gere uma **Credencial de Segurança** em `My Account Settings
  → Credentials` (ver seção 2 acima) e atualize `CLIENT_ID`/`CLIENT_SECRET`
  no `.env`.
- **Todos os endpoints falham** — sugere um problema mais amplo (credenciais
  inválidas/revogadas, ou uma instabilidade generalizada do backend).
  Contate o suporte Sensedia com a saída do `--probe`.

> **Nota de segurança:** `--probe` nunca imprime o corpo de uma resposta
> `200` — só o status HTTP. Isso é proposital: `/variables/values` retorna
> valores reais de variáveis (potencialmente segredos) quando funciona, e o
> diagnóstico não deve expor esse conteúdo no terminal/logs.
