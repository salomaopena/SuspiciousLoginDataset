# Título projeto

**SuspiciousLogin Dataset e Benchmark de Detecção de Autenticação Suspeita em Google Workspace**

Este artefato acompanha o artigo "Benchmarking Machine Learning Approaches for Suspicious Login Detection in Google Workspace", que compara sete estratégias de detecção de autenticações suspeitas, seis modelos de aprendizado de máquina e uma pontuação de risco, sobre o *SuspiciousLogin Dataset*, um conjunto real de 73.528 eventos de autenticação bem-sucedida no Google Workspace, coletados ao longo de oito meses em duas instituições de ensino superior. O artefato inclui o conjunto de dados público, o código de processamento e treinamento, e os cadernos computacionais que reproduzem os resultados relatados no artigo, incluindo a comparação entre modelos, o estudo de ablação por grupo de atributos, a segmentação por histórico de usuário, e a afinação de hiperparâmetros via Optuna.

## Estrutura do readme.md

Este documento segue a estrutura exigida pelo Comitê Técnico de Artefatos do SBSEG 2026: informações básicas do ambiente, dependências, preocupações de segurança, instalação, um teste mínimo, e os experimentos que reproduzem as principais reivindicações do artigo, cada uma em sua própria subseção.

## Selos Considerados

Os selos considerados são: **Disponíveis (SeloD)**, **Funcionais (SeloF)**, **Sustentáveis (SeloS)** e **Experimentos Reprodutíveis (SeloR)**.

## Informações básicas

O artefato é composto por dados tabulares (arquivos `.csv`) e código Python (scripts e cadernos Jupyter). Não é necessário hardware especializado.

- **Sistema operacional**: qualquer um com suporte a Python 3.10 ou superior (testado em Linux; deve funcionar sem alterações em macOS e Windows).
- **Hardware mínimo**: 2 GB de RAM livre e 200 MB de espaço em disco. Nenhuma GPU é necessária.
- **Tempo total estimado**: entre 10 e 15 minutos para o teste mínimo e as reivindicações principais; a afinação completa de hiperparâmetros (opcional, Reivindicação #3) pode levar até 10 minutos adicionais.
- **Acesso à rede**: necessário apenas na instalação, para baixar as dependências Python.

## Dependências

| Dependência | Versão mínima | Finalidade |
|---|---|---|
| Python | 3.10 | Linguagem de execução |
| pandas | 2.0 | Manipulação tabular |
| numpy | 1.24 | Operações numéricas |
| scikit-learn | 1.3 | Regressão logística, árvore de decisão, random forest, isolation forest |
| xgboost | 2.0 | Modelo XGBoost |
| lightgbm | 4.0 | Modelo LightGBM |
| optuna | 4.0 | Afinação de hiperparâmetros (Reivindicação #3) |
| jupyter / nbformat | mais recente | Execução do caderno computacional |

Todas as dependências são pacotes públicos do PyPI, sem necessidade de credenciais ou acesso a serviços de terceiros. O arquivo `requirements.txt`, na raiz do repositório, fixa as versões exatas testadas pelos autores.

## Preocupações com segurança

Nenhuma. O artefato não executa código com privilégios elevados, não acessa rede além do necessário para instalar dependências públicas, e não interage com nenhum sistema de produção. Os dados distribuídos já estão pseudonimizados e generalizados; nenhuma credencial, chave de API ou informação de acesso ao Google Workspace está presente neste repositório público.

## Structure, in two repositories

Following the rule that raw/sensitive data and code/documentation live
in separate repositories:

```text
suspiciouslogin-dataset/              (PUBLIC -- this repository)
├── README.md
├── LICENSE-DATASET.txt               (CC BY-NC 4.0, for the data)
├── LICENSE-CODE.txt                  (MIT, for the code)
├── CITATION.cff
├── codemeta.json
├── .zenodo.json
├── data/
│   ├── suspicious_logins_public_v1.csv
│   ├── suspicious_logins_demo_sample.csv     (500-row sample)
│   ├── benchmark_results.csv                 (Article 3)
│   ├── article1_summary_statistics.csv
│   └── article2_odds_ratios.csv
├── notebooks/
│   ├── benchmark_notebook.ipynb        (Article 3, Kaggle-ready, with plots)
│   ├── article1_statistics.ipynb       (coverage, Gini, Lorenz curve, data quality)
│   └── article2_empirical_patterns.ipynb (temporal/geographic patterns, statistical tests)
├── src/
│   ├── processed.py                  (processing pipeline)
│   └── benchmark_ml.py               (reference models)
├── tests/
│   └── test_processed.py             (23 automated tests)
└── docs/
    ├── DATA_DICTIONARY_EN.md
    ├── SCHEMA_EN.md
    ├── RISK_SCORE_METHODOLOGY_EN.md
    ├── PRIVACY_ANONYMIZATION_REPORT_EN.md
    ├── DATA_AUDIT_REPORT_EN.md
    ├── BENCHMARK_RESULTS_EN.md
    └── figures/                       (PNGs referenced by the two statistics notebooks)

suspiciouslogin-dataset-private/       (PRIVATE -- never published)
├── .env                               (HMAC_SECRET_KEY_* keys, never committed)
├── .gitignore
├── credentials.json                   (Google API credentials, never committed)
├── data/
│   ├── raw/
│   │   ├── <institution_a>/           (that institution's extraction CSVs)
│   │   └── <institution_b>/
│   └── processed/
│       └── suspicious_logins_restricted_v1.csv
├── src/
│   ├── processed.py
│   ├── benchmark_ml.py
│   ├── extract_suspicious_logins.py
│   └── functions.py
└── tests/
    └── test_processed.py
```

## Instalação

```bash
# 1. Clonar o repositório público
git clone https://github.com/salomaopena/SuspiciousLoginDataset.git
cd SuspiciousLoginDataset

# 2. Criar um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate      # no Windows: venv\Scripts\activate

# 3. Instalar as dependências
pip install -r requirements.txt
```

Ao final deste processo, os scripts em `src/` e o caderno em `notebooks/benchmark_notebook.ipynb` já podem ser executados.

## Teste mínimo

Confirma que o conjunto de dados público carrega corretamente e que o ambiente está pronto para os experimentos.

```bash
python3 -c "
import pandas as pd
df = pd.read_csv('data/suspicious_logins_public_v1.csv')
assert len(df) == 73528, 'número de linhas inesperado'
assert abs(df[\"label\"].mean() - 0.0759) < 0.001, 'taxa de suspeita inesperada'
print('Teste mínimo passou:', len(df), 'linhas,', round(df[\"label\"].mean()*100, 2), '% suspeitas')
"
```

**Resultado esperado**: `Teste mínimo passou: 73528 linhas, 7.59 % suspeitas`. Tempo esperado: menos de 5 segundos.

## Experimentos

As três reivindicações abaixo cobrem os resultados centrais do artigo. Cada uma pode ser reproduzida isoladamente, sem depender das demais.

## Reivindicação #1 — Random Forest e XGBoost empatam no melhor desempenho (AUC-ROC 0,963)

**O que reproduz**: a Tabela 1 do artigo, com o desempenho comparativo dos sete modelos sobre o conjunto de teste.

**Comando**:

```bash
python3 src/benchmark_ml.py
```

**Arquivo de configuração**: nenhum a alterar; os hiperparâmetros padrão já estão fixados no próprio script.

**Tempo esperado**: aproximadamente 2 minutos.

**Recursos esperados**: menos de 1 GB de RAM.

**Resultado esperado**: uma tabela impressa no terminal com sete linhas (Regressão Logística, Árvore de Decisão, Random Forest, XGBoost, LightGBM, Isolation Forest, Risk Score) e seis colunas de métricas. Random Forest e XGBoost devem apresentar AUC-ROC de 0,963, superando os demais.

## Reivindicação #2 — Atributos temporais e de autenticação sustentam a maior parte do sinal discriminativo (estudo de ablação)

**O que reproduz**: a Figura 2 do artigo (estudo de ablação) e a afirmação de que o subconjunto basal de atributos atinge AUC-ROC próxima de 0,94, contra 0,96 do conjunto completo.

**Comando**: abrir e executar as células da seção "Estudo de ablação" em `notebooks/benchmark_notebook.ipynb`.

**Tempo esperado**: aproximadamente 3 minutos.

**Resultado esperado**: quatro valores crescentes de AUC-ROC (aproximadamente 0,940, 0,947, 0,9495 e 0,9592), confirmando que o ganho marginal de cada grupo de atributos adicional é pequeno frente ao desempenho já alcançado pelos atributos temporais e de autenticação isolados.

## Reivindicação #3 — A afinação de hiperparâmetros produz ganhos modestos e legítimos, não próximos de 100%

**O que reproduz**: a Tabela do apêndice que compara desempenho original e afinado, e o argumento do artigo de que um conjunto de dados de segurança não deve apresentar desempenho quase perfeito.

**Comando**: executar as células da Seção 15 ("Hyperparameter tuning via Optuna") em `notebooks/benchmark_notebook.ipynb`.

**Tempo esperado**: até 10 minutos, dado o número de tentativas de otimização (40 para Random Forest, 30 para XGBoost e LightGBM, 25 para Regressão Logística e Árvore de Decisão).

**Recursos esperados**: menos de 1 GB de RAM; nenhuma GPU.

**Resultado esperado**: ganhos de AUC-ROC entre 0,004 e 0,028 conforme o modelo, nunca ultrapassando 0,963. Um resultado próximo de 1,0 indicaria vazamento de dados entre treino e teste, não sucesso do método.

## Citation

Consulte `CITATION.cff` e `.zenodo.json`.

## LICENSE

- **Conjunto de dados** (`data/suspicious_logins_public_v1.csv` e documentação): Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) — ver `LICENSE-DATASET.txt`.
- **Código** (`src/processed.py`, `src/benchmark_ml.py`, `notebooks/benchmark_notebook.ipynb`, testes): Licença MIT — ver `LICENSE-CODE.txt`.
