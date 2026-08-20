# Relatório de Qualidade de Dados

Este relatório documenta a qualidade e as características do conjunto de
dados final (73.528 linhas, duas instituições), e as decisões de
processamento tomadas em resposta a características reais dos dados
brutos.

## 1. Robustez do processamento a variações de formato

Os ficheiros de extracção brutos (`data/raw/`) não têm um formato
uniforme entre execuções — três variações reais de formato ocorrem:
separador (vírgula ou ponto e vírgula), codificação (UTF-8 ou `cp1252`),
e separador decimal (ponto ou vírgula, em `latitude`/`longitude`).
`data/processed.py` detecta e trata as três automaticamente por
ficheiro, sem intervenção manual.

**Recomendação para extracções futuras**: evitar abrir ou gravar os
`.csv` brutos no Excel; usar um editor de texto simples ou o próprio
*script* de extracção directamente, para não introduzir estas variações.

## 2. Correcções de qualidade aplicadas

| Característica dos dados brutos | Tratamento aplicado |
|---|---|
| Linhas duplicadas dentro do mesmo ficheiro ou entre ficheiros (mesmo utilizador/rede/instante ao milissegundo) | Deduplicação por conteúdo (excepto `record_id`), com contagem reportada em cada execução |
| `record_id` reinicia em 1 a cada execução de extracção (`extract_suspicious_logins.py`) | `record_id` novo, sequencial, gerado após combinar todos os ficheiros |
| Nomes de país inconsistentes (`"Netherlands"` vs `"The Netherlands"`) | Normalização para grafia canónica (`COUNTRY_NAME_CANONICAL` em `processed.py`) |
| `ip_region` reflecte o código do país, não uma região real (ver `functions.py::getGeoFromPI`) | Documentado como não fiável; removido do esquema público, mantido no restrito só para auditoria |
| Países com poucos eventos, individualmente identificáveis | Generalizados para `"Other"` no esquema público (limiar de 5 eventos, recalculado a cada processamento); país real preservado no esquema restrito |

## 3. Cobertura temporal

19 de Dezembro de 2025 a 12 de Agosto de 2026, combinando duas
instituições de ensino superior.

**Julho e Agosto excluídos da avaliação de modelos**: correspondem a
férias lectivas em Angola, com queda acentuada tanto no volume de
eventos (~6.500-8.000/mês para 1.440-3.172/mês) como na proporção de
suspeitos (~7-9% para ~1,3-1,5%), sem alteração de políticas de
segurança nesse período. Estes dados permanecem no conjunto publicado,
mas são excluídos da divisão treino/validação/teste usada para o
`risk_score` e os modelos de referência — ver `RISK_SCORE_METHODOLOGY.md`
e `EVALUATION_CUTOFF_DATE` em `benchmark_ml.py`.

## 4. Distribuição da classe-alvo

| Linhas | Positivos (`label=1`) | Proporção |
|---|---|---|
| 73.528 | 5.578 | 7,59% |

A proporção mantém-se estável em torno de 6-8% em todos os subconjuntos
e escalas examinadas durante a construção do conjunto de dados —
característica consistente, não um artefacto de amostragem.

## 5. Concentração institucional e geográfica

| Métrica | Valor |
|---|---|
| Utilizadores distintos | 36.691 |
| País mais comum | Angola, 63,15% |
| Segundo país mais comum | Brasil, 23.528 eventos |
| Países distintos (esquema restrito) | 28 |
| Países distintos (esquema público, após generalização) | 23 (`"Other"` agrupa os 6 países com ≤5 eventos) |
| Evento(s) do utilizador mais activo | 1.846 (2,51% do total) |
| Utilizadores com um só evento observado | 96,3% |

Combinar duas instituições reduziu genuinamente a concentração
geográfica e a dominância de utilizadores individuais — resultado de
diversidade de fontes, não apenas de volume adicional (ver
`PRIVACY_ANONYMIZATION_REPORT.md`, secção 5).

## 6. Campos constantes, sem informação

`event_name` (sempre `login_success`) e `login_status` (sempre
`success`) — removidos do esquema público e restrito, por não
distinguirem nada dentro deste conjunto de dados.

## 7. Proveniência mista da geolocalização

`ip_country`/`ip_region`/`ip_city`/`continent` vêm, por linha, da
própria API do Google Workspace ou do recurso de contingência
`ip-api.com`, dependendo de qual estava disponível no momento da
extracção (ver `extract_suspicious_logins.py::flatten`). Esta
proveniência não está documentada por linha na versão actual —
limitação conhecida do conjunto de dados.
