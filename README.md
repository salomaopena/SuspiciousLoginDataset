# Project Title

**SuspiciousLogin Dataset and Suspicious Authentication Detection Benchmark in Google Workspace**

This artifact accompanies the article "Benchmarking Machine Learning Approaches for Suspicious Login Detection in Google Workspace," which compares seven detection strategies, six machine learning models and one reference risk score, over the *SuspiciousLogin Dataset*, a real collection of 73,528 successful authentication events in Google Workspace, gathered over eight months across two higher education institutions. The artifact includes the public dataset, the processing and training code, and the computational notebooks that reproduce the results reported in the article, including the model comparison, the feature-group ablation study, the user-history segmentation, and the hyperparameter tuning via Optuna.

## README structure

This document follows the structure required by the SBSEG 2026 Artifact Technical Committee: basic environment information, dependencies, security concerns, installation, a minimal test, and the experiments that reproduce the article's main claims, each in its own subsection.

## Badges Considered

The badges considered are: **Available**, **Functional**, **Sustainable**, and **Reproducible Experiments**.

## Basic information

The artifact consists of tabular data (`.csv` files) and Python code (scripts and Jupyter notebooks). No specialized hardware is required.

- **Operating system**: any system supporting Python 3.10 or later (tested on Linux; should work unchanged on macOS and Windows).
- **Minimum hardware**: 2 GB of free RAM and 200 MB of disk space. No GPU is required.
- **Estimated total time**: 10 to 15 minutes for the minimal test and the main claims; the full hyperparameter tuning run (optional, Claim #3) may take up to 10 additional minutes.
- **Network access**: required only during installation, to download Python dependencies.

## Dependencies

| Dependency | Minimum version | Purpose |
|---|---|---|
| Python | 3.10 | Runtime language |
| pandas | 2.0 | Tabular data manipulation |
| numpy | 1.24 | Numerical operations |
| scikit-learn | 1.3 | Logistic regression, decision tree, random forest, isolation forest |
| xgboost | 2.0 | XGBoost model |
| lightgbm | 4.0 | LightGBM model |
| optuna | 4.0 | Hyperparameter tuning (Claim #3) |
| jupyter / nbformat | latest | Notebook execution |

All dependencies are public PyPI packages; no credentials or third-party service access are required. The `requirements.txt` file at the repository root pins the exact versions tested by the authors.

## Security concerns

None. The artifact does not execute code with elevated privileges, does not access the network beyond installing public dependencies, and does not interact with any production system. The distributed data is already pseudonymized and generalized; no credential, API key, or Google Workspace access information is present in this public repository.

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

## Installation

```bash
# 1. Clone the public repository
git clone https://github.com/salomaopena/SuspiciousLoginDataset.git
cd SuspiciousLoginDataset

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate      # on Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

After this process, the scripts under `src/` and the notebook at `notebooks/benchmark_notebook.ipynb` are ready to run.

## Minimal test

Confirms that the public dataset loads correctly and that the environment is ready for the experiments.

```bash
python3 -c "
import pandas as pd
df = pd.read_csv('data/suspicious_logins_public_v1.csv')
assert len(df) == 73528, 'unexpected row count'
assert abs(df[\"label\"].mean() - 0.0759) < 0.001, 'unexpected suspicion rate'
print('Minimal test passed:', len(df), 'rows,', round(df[\"label\"].mean()*100, 2), '% suspicious')
"
```

**Expected result**: `Minimal test passed: 73528 rows, 7.59 % suspicious`. Expected time: under 5 seconds.

## Experiments

The three claims below cover the article's central results. Each can be reproduced independently, without depending on the others.

## Claim #1 — Random Forest and XGBoost tie for best performance (AUC-ROC 0.963)

**What it reproduces**: Table 1 of the article, with the comparative performance of the seven models on the test set.

**Command**:

```bash
python3 src/benchmark_ml.py
```

**Configuration file**: none to change; default hyperparameters are already fixed in the script itself.

**Expected time**: approximately 2 minutes.

**Expected resources**: under 1 GB of RAM.

**Expected result**: a table printed to the terminal with seven rows (Logistic Regression, Decision Tree, Random Forest, XGBoost, LightGBM, Isolation Forest, Risk Score) and six metric columns. Random Forest and XGBoost should show AUC-ROC of 0.963, outperforming the rest.

## Claim #2 — Temporal and authentication attributes carry most of the discriminative signal (ablation study)

**What it reproduces**: Figure 2 of the article (ablation study) and the claim that the baseline attribute subset reaches AUC-ROC close to 0.94, against 0.96 for the complete set.

**Command**: open and run the cells in the "Estudo de ablação" section of `notebooks/benchmark_notebook.ipynb`.

**Expected time**: approximately 3 minutes.

**Expected result**: four increasing AUC-ROC values (approximately 0.940, 0.947, 0.9495, and 0.9592), confirming that each additional attribute group's marginal gain is small compared to the performance already achieved by temporal and authentication attributes alone.

## Claim #3 — Hyperparameter tuning yields modest, legitimate gains, not close to 100%

**What it reproduces**: the appendix table comparing original and tuned performance, and the article's argument that a security dataset should not show near-perfect performance.

**Command**: run the cells in Section 15 ("Hyperparameter tuning via Optuna") of `notebooks/benchmark_notebook.ipynb`.

**Expected time**: up to 10 minutes, given the number of optimization trials (40 for Random Forest, 30 for XGBoost and LightGBM, 25 for Logistic Regression and Decision Tree).

**Expected resources**: under 1 GB of RAM; no GPU.

**Expected result**: AUC-ROC gains between 0.004 and 0.028 depending on the model, never exceeding 0.963. A result close to 1.0 would indicate data leakage between training and test, not method success.

## Citation

See `CITATION.cff` and `.zenodo.json`. The DOI will be added to both
once the Zenodo record is published.

## LICENSE

- **Dataset** (`data/suspicious_logins_public_v1.csv` and documentation): Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) — see `LICENSE-DATASET.txt`.
- **Code** (`src/processed.py`, `src/benchmark_ml.py`, `notebooks/benchmark_notebook.ipynb`, tests): MIT License — see `LICENSE-CODE.txt`.
