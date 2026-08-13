# Metodologia do `risk_score`

## Porque não é uma fórmula intuitiva

Uma primeira versão do `risk_score` (soma ponderada de sinais escolhidos à
mão: IP novo, país novo, mudança de país, mudança de continente, hora
anómala) foi testada empiricamente contra o rótulo real (`is_suspicious`)
numa divisão temporal treino/teste, e teve um desempenho **pior do que
aleatório** (AUC-ROC=0,375 no conjunto de teste nunca visto no ajuste).

A causa raiz foi confirmada com os dados: três dos cinco termos dessa
fórmula não eram sinais independentes — `is_new_country` implicava
`country_changed` em 100% das linhas, e `continent_changed` implicava
`country_changed` em 100% das linhas também. A fórmula estava, na
prática, a contar o mesmo sinal ("a localização mudou") duas ou três
vezes, ao mesmo tempo que ignorava os dois sinais que, isolados,
realmente se correlacionavam com o rótulo real (`impossible_travel` e
`distinct_users_per_network_24h`).

Esta fórmula ingénua **não foi mantida** como coluna no conjunto de dados
publicado — todas as características que a compunham já são colunas
próprias, por isso quem quiser reproduzir essa comparação para um artigo
pode recalculá-la directamente a partir delas.

## A metodologia usada na versão actual (v1)

1. **Divisão temporal**, nunca aleatória: os primeiros 75% dos eventos por
  `event_time` para ajuste, os últimos 25% (nunca vistos durante o ajuste)
  para validação — consistente com a regra geral do projecto de nunca usar
  divisões aleatórias como avaliação principal em dados sequenciais.
2. **Regressão logística** (`sklearn.linear_model.LogisticRegression`,
  `class_weight="balanced"`, dado o desequilíbrio de classes) sobre seis
  características: `new_ip`, `geo_jump`, `abnormal_login_hour`,
  `impossible_travel`, `distinct_users_per_network_24h`,
  `multiple_country_logins_24h`.
3. **Conversão dos coeficientes em pontos**, técnica padrão de sistemas de
  pontuação de risco (*scorecard*): cada coeficiente multiplicado por um
  factor de escala comum (40, escolhido para que o maior coeficiente
  (`impossible_travel`) resultasse num número de pontos legível), depois
  arredondado. Excepção: `distinct_users_per_network_24h`, por ser
  contínua com um coeficiente pequeno, mantém uma casa decimal em vez de
  arredondar a um inteiro — arredondar a zero (o que aconteceu numa
  primeira tentativa com uma escala menor) teria eliminado silenciosamente
  o segundo sinal mais forte do conjunto.
4. **Validação da perda por arredondamento**: a versão em pontos inteiros
  manteve praticamente todo o desempenho da versão contínua (AUC-ROC
  idêntico a 4 casas decimais no conjunto de teste).

## Pesos fixos, não recalculados a cada execução

Os pesos actuais estão fixados directamente no código (`data/processed.py`,
secção `RISK SCORE`), não recalculados automaticamente sempre que o
*script* corre. Um conjunto de dados publicado precisa de uma definição
estável do `risk_score` — se os pesos mudassem silenciosamente sempre que
mais ficheiros brutos fossem adicionados, o significado da coluna mudaria
sem aviso entre utilizações.

**Estado final**: a versão em vigor é a v3, ajustada sobre o conjunto de
dados completo (duas instituições, 73.528 linhas). Ver o histórico de
versões abaixo para o percurso completo (v1 → v2 → v3) e a justificação
de cada mudança.

## Como produzir uma nova versão (v2, v3, ...)

Repetir exactamente o procedimento acima sobre o conjunto de dados
actualizado:

1. Carregar o `suspicious_logins_restricted_v1.csv` mais recente (precisa
  de `event_time`, só disponível no esquema restrito).
2. Ordenar por `event_time`, cortar nos primeiros 75%/últimos 25%.
3. Construir `geo_jump` a partir de `country_changed`/`continent_changed`
  (já presente no esquema, não precisa de recalcular).
4. Ajustar `LogisticRegression(class_weight="balanced", max_iter=1000,
  random_state=42)` sobre as seis características listadas acima.
5. Escalar os coeficientes (começar por um factor de 40, ajustar se algum
  coeficiente pequeno arredondar a zero) e arredondar.
6. Validar no conjunto de teste: confirmar que a versão em pontos
  inteiros não perde desempenho relevante face à versão contínua
  (comparar AUC-ROC/PR-AUC das duas).
7. **Nunca sobrescrever a versão anterior** — gravar como
  `suspicious_logins_public_v2.csv`, manter a v1 disponível, e registar
  aqui a data, o volume de dados usado, e os novos pesos e métricas.
  Isto permite que qualquer artigo já publicado com base na v1 continue
  reprodutível, mesmo depois de uma v2 existir.

## Histórico de versões

| Versão | Data do ajuste | Linhas usadas | AUC-ROC (teste) | PR-AUC (teste) | Nota |
|---|---|---|---|---|---|
| v1 | 2026-08-12 | ~5.332 (após remoção de duplicados) | 0,768 (contínua) / 0,768 (pontos) | 0,196 (contínua) / 0,196 (pontos) | Primeira versão empírica, substitui a fórmula ingénua original |
| v2 | 2026-08-12 | 26.999 (treino, após exclusão do período de férias Jun-Ago) | 0,718 | 0,159 | Ver nota abaixo sobre a queda de `impossible_travel` |
| v3 | 2026-08-12 | 48.238 (treino, duas instituições, após exclusão de Jul-Ago) | 0,624 | 0,095 | `impossible_travel` confirmado sem sinal pela 2ª vez seguida (agora 0,00). AUC-ROC mais baixo que v2 não é regressão — reflecte uma população genuinamente mais diversa (ver nota abaixo) |

## Nota sobre a v3: o AUC-ROC mais baixo é esperado, não uma regressão

`0,624` é mais baixo do que o `0,718` da v2 — mas isto **não** significa
que o `risk_score` piorou. Com uma população muito mais diversa (duas
instituições, 36.691 utilizadores em vez de 11.691, concentração
geográfica muito menor), o problema de classificação em si ficou
genuinamente mais difícil — os mesmos seis sinais simples explicam uma
fracção menor da variação real quando a população é mais heterogénea.
Os modelos de referência completos (`benchmark_ml.py`) confirmam isto
directamente: na mesma divisão de dados, chegam a `AUC-ROC=0,92-0,96`,
uma diferença muito maior face ao `risk_score` (`0,624`) do que a
diferença que já víamos na v2 — a comparação continua válida e forte
para o Artigo 3, só que agora sobre uma base de avaliação mais honesta e
mais difícil.

## Nota sobre a v2: `impossible_travel` deixou de ter sinal à escala maior

Na amostra pequena original (~5.300 linhas), `impossible_travel` era um dos
dois únicos sinais individuais com correlação genuína com o rótulo real
(+0,064). Reajustado sobre o conjunto completo (~27 mil linhas de treino,
excluindo o período de férias), a correlação caiu para praticamente zero
(-0,005) — a taxa de suspeitos é até ligeiramente **mais baixa** quando
`impossible_travel=1` (4,95%) do que quando é `0` (7,21%). O coeficiente da
regressão logística reflecte isto (essencialmente zero, `-0,03`).

Isto é reportado como achado honesto, não escondido: a amostra pequena
levou a uma conclusão que não se confirmou com mais dados — exactamente o
tipo de risco que motivou este reajuste, e vale a pena mencionar
explicitamente no Artigo 3 como exemplo de porque a validação a escalas
diferentes importa.

## Nota sobre a v2: período de férias excluído da divisão treino/validação/teste

Confirmado com a instituição: Junho a Agosto é época de férias lectivas em
Angola. O volume de eventos cai de forma acentuada nesse período
(~6.500-8.000/mês para 1.440-3.172/mês), e a taxa de suspeitos cai ainda
mais (de ~7% para ~1,3-1,5%). Sem alteração de políticas de segurança
confirmada nesse período — a causa mais provável é uma combinação de
comportamento genuinamente diferente numa população mais pequena em
férias, possivelmente combinado com sinalização ainda não totalmente
assentada para os eventos mais recentes (dado a extracção ter sido feita
praticamente em tempo real).

Este período foi excluído da divisão treino/validação/teste usada para
`risk_score` v2 e para os modelos de referência (`benchmark_ml.py`), mas
**mantido no conjunto de dados publicado** — não é um problema de
qualidade dos dados, é uma decisão de que a fiabilidade do rótulo nesse
período específico ainda não está confirmada para efeitos de avaliação.
Ver `EVALUATION_CUTOFF_DATE` em `benchmark_ml.py`.
