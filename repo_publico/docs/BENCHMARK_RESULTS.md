# Resultados do Benchmark — Modelos de Referência

Resultados finais, verificados em 2026-08-12, sobre o conjunto de dados
completo (duas instituições, 73.528 linhas), com o período de férias
lectivas (Julho-Agosto) excluído da divisão treino/validação/teste —
ver `RISK_SCORE_METHODOLOGY.md` para a justificação completa.

## Metodologia

- **Divisão temporal** 70/15/15 (treino/validação/teste), nunca
  aleatória — 48.238 / 10.337 / 10.337 linhas, respectivamente
- **Limite por utilizador no treino**: 76 utilizadores excediam 80
  eventos, removidas 5.940 linhas (12,31% do treino) — o utilizador mais
  activo passou de 3,55% para 0,19% do treino, sem tocar em validação
  nem teste (ver `docs/BACKLOG.md`, e o código em `benchmark_ml.py`)
- **Limiar de decisão** escolhido por validação (maximizando F1), nunca
  no próprio conjunto de teste
- **`history_available`** incluído como característica (confirmado
  genuinamente preditivo: 2,69% de suspeitos entre utilizadores com
  histórico prévio, contra 7,69% no primeiro evento observado)
- Características de identificação (`actor_pseudo_id`) e a própria
  pontuação `risk_score`/`risk_level` **excluídas** das entradas dos
  modelos — são a referência de comparação, não uma entrada

## Tabela de resultados (conjunto de teste, nunca visto durante o ajuste)

| Modelo | AUC-ROC | PR-AUC | Precisão | Recall | F1 | Falsos positivos / 1000 logins |
|---|---|---|---|---|---|---|
| Regressão Logística | 0,918 | 0,698 | 0,633 | 0,632 | 0,633 | 24,96 |
| Árvore de Decisão | 0,946 | 0,767 | **0,950** | 0,624 | 0,753 | 2,23 |
| **Random Forest** | **0,959** | **0,810** | 0,948 | 0,598 | 0,733 | 2,23 |
| XGBoost | 0,940 | 0,783 | 0,845 | 0,651 | 0,735 | 8,13 |
| LightGBM | 0,947 | 0,787 | 0,801 | **0,669** | 0,729 | 11,32 |
| Isolation Forest (não supervisionado) | 0,766 | 0,175 | 0,256 | 0,517 | 0,342 | 102,54 |
| `risk_score` (referência empírica) | 0,624 | 0,095 | 0,106 | 0,050 | 0,068 | 28,44 |

## Leitura dos resultados

**O Random Forest tem o melhor equilíbrio geral** (`AUC-ROC=0,959`,
`PR-AUC=0,810`), com precisão muito alta (0,948) — poucos falsos
alarmes por cada alerta gerado. A Árvore de Decisão isolada chega a uma
precisão ainda maior (0,950), à custa de recall ligeiramente menor.

**Todos os modelos supervisionados superam claramente o `risk_score`**
— a diferença de `AUC-ROC` (0,918-0,959 contra 0,624) confirma o valor
de usar aprendizagem automática completa em vez de uma pontuação
simples baseada em poucas características, mesmo quando essa pontuação
já foi validada empiricamente (não é a fórmula ingénua original, que
tinha tido `AUC-ROC=0,375`).

**O Isolation Forest (não supervisionado) melhora substancialmente com
a diversidade institucional** — de um desempenho pior que aleatório
(`AUC-ROC<0,5`) em amostras anteriores, mais pequenas e menos diversas,
para `0,766` neste conjunto final. Ainda assim, fica bem abaixo dos
modelos supervisionados — esperado, dado que não usa o rótulo real
durante o treino.

**O `risk_score`, embora sistematicamente inferior aos modelos
completos, continua a servir o seu propósito**: uma referência
interpretável, de poucas variáveis, contra a qual medir o valor
acrescentado de modelos mais complexos — exactamente o papel que lhe
foi atribuído (ver `RISK_SCORE_METHODOLOGY.md`).

## Ficheiro de resultados bruto

`benchmark_results.csv` (gerado por `src/benchmark_ml.py`) contém esta
mesma tabela, com colunas adicionais (`brier_score`, contagens
`TP`/`FP`/`TN`/`FN`, limiar de decisão usado por modelo).
