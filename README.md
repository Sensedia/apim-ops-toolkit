# apim-ops-toolkit

Coleção de scripts operacionais para manutenção e limpeza de tenants da
plataforma Sensedia APIM (v4 e v5), desenvolvidos e usados internamente pelo
time de Platform Engineering da Sensedia.

## Estrutura

```
apim-ops-toolkit/
├── v4/
│   └── app-cleanup/                # Remove APPs (client credentials) obsoletas via Manager API
└── v5/
    ├── env-var-identification/     # Identifica variáveis de ambiente sem uso (somente leitura)
    └── env-var-cleanup/            # Exclui com segurança as variáveis confirmadas como seguras
```

Cada ferramenta vive na sua própria pasta, com README, `requirements.txt` e
`.env.example` próprios — trate cada uma como um projeto Python independente.

## O par `env-var-identification` / `env-var-cleanup` (APIM v5)

Essas duas ferramentas formam um pipeline: a saída de uma alimenta a outra.
Rode sempre nesta ordem:

1. **`env-var-identification/identify_unused_variables.py`** — varre todo o
   tenant (somente leitura) e gera `confirmado_seguro_deletar.csv`, a lista
   de variáveis sem nenhuma referência encontrada em interceptors ou
   destinations.
2. **`env-var-cleanup/sanitize_variables.py`** — recebe esse CSV como
   `--input` e exclui as variáveis uma por uma, com backup e confirmação
   antes de marcar cada linha como concluída.

Veja o README de cada pasta para o passo a passo completo (geração de
credenciais, configuração do `.env`, como interpretar os relatórios gerados).

## `app-cleanup` (APIM v4)

Ferramenta independente para remover APPs (client credentials) obsoletas de
um ambiente APIM v4 via Manager API, com backup do payload completo antes de
cada exclusão. Veja `v4/app-cleanup/README.md`.

## Aviso

Estes scripts fazem alterações reais e **irreversíveis pela própria API**
(exclusão de variáveis/APPs) quando rodados sem `--dry-run`. Todos fazem
backup local antes de qualquer alteração, mas leia o README da ferramenta
específica antes de usar, e rode sempre em modo de simulação (`--dry-run`)
primeiro.

## Licença

TODO — pendente definição.
