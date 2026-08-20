# Data Quality Report

This report documents the quality and characteristics of the final
dataset (73,528 rows, two institutions), and the processing decisions
taken in response to real characteristics of the raw data.

## 1. Processing robustness to format variation

Raw extraction files (`data/raw/`) do not have a uniform format across
runs — three real format variations occur: delimiter (comma or
semicolon), encoding (UTF-8 or `cp1252`), and decimal separator (period
or comma, in `latitude`/`longitude`). `data/processed.py` detects and
handles all three automatically per file, with no manual intervention
needed.

**Recommendation for future extractions**: avoid opening or saving the
raw `.csv` files in Excel; use a plain text editor or the extraction
script's own output directly, to avoid introducing these variations.

## 2. Quality corrections applied

| Raw data characteristic | Handling applied |
|---|---|
| Duplicate rows within or across files (same user/network/millisecond timestamp) | Content-based deduplication (except `record_id`), with a count reported on every run |
| `record_id` restarts at 1 on every extraction run (`extract_suspicious_logins.py`) | A fresh, sequential `record_id` generated after combining all files |
| Inconsistent country names (`"Netherlands"` vs `"The Netherlands"`) | Normalized to a canonical spelling (`COUNTRY_NAME_CANONICAL` in `processed.py`) |
| `ip_region` reflects the country code, not a real region (see `functions.py::getGeoFromPI`) | Documented as unreliable; removed from the public schema, kept in the restricted schema for audit purposes only |
| Countries with few events, individually identifiable | Generalized to `"Other"` in the public schema (5-event threshold, recomputed on every processing run); real country preserved in the restricted schema |

## 3. Temporal coverage

December 19, 2025 to August 12, 2026, combining two higher-education
institutions.

**July and August excluded from model evaluation**: these correspond to
the academic vacation period in Angola, with a sharp drop in both event
volume (~6,500-8,000/month to 1,440-3,172/month) and the suspicious
proportion (~7-9% to ~1.3-1.5%), with no security policy change during
this period. This data remains in the published dataset, but is
excluded from the train/validation/test split used for `risk_score` and
the reference models — see `RISK_SCORE_METHODOLOGY_EN.md` and
`EVALUATION_CUTOFF_DATE` in `benchmark_ml.py`.

## 4. Target class distribution

| Rows | Positives (`label=1`) | Proportion |
|---|---|---|
| 73,528 | 5,578 | 7.59% |

The proportion stays stable around 6-8% across every subset and scale
examined while building the dataset — a consistent characteristic, not
a sampling artifact.

## 5. Institutional and geographic concentration

| Metric | Value |
|---|---|
| Distinct users | 36,691 |
| Most common country | Angola, 63.15% |
| Second most common country | Brazil, 23,528 events |
| Distinct countries (restricted schema) | 28 |
| Distinct countries (public schema, after generalization) | 23 (`"Other"` groups the 6 countries with ≤5 events) |
| Most active user's event(s) | 1,846 (2.51% of total) |
| Users with a single observed event | 96.3% |

Combining two institutions genuinely reduced geographic concentration
and the dominance of individual users — a result of source diversity,
not just additional volume (see `PRIVACY_ANONYMIZATION_REPORT_EN.md`,
section 5).

## 6. Constant, uninformative fields

`event_name` (always `login_success`) and `login_status` (always
`success`) — removed from both the public and restricted schema, since
they distinguish nothing within this dataset.

## 7. Mixed geolocation provenance

`ip_country`/`ip_region`/`ip_city`/`continent` come, per row, from
either Google Workspace's own API or the `ip-api.com` fallback,
depending on which was available at extraction time (see
`extract_suspicious_logins.py::flatten`). This provenance is not
documented on a per-row basis in the current version — a known
limitation of the dataset.

## 8. Countries with a 100% suspicious rate — investigated, not an artifact

Four countries with non-trivial event counts show an exact 100%
suspicious rate: Argentina (449 events), Chile (603), Colombia (411),
and Mexico (293). This was investigated in detail rather than taken at
face value, given a near-identical earlier finding in this project
traced back to an extraction filter bug (see the institution B
correction, no longer present in this dataset).

Confirmed directly in the raw extraction (not introduced by
`processed.py`): every event in each of these four countries comes
from a distinct pseudonymized user and a distinct network — no
repeated actor or IP within any of the four — concentrated in a single
major city per country (Buenos Aires, Santiago, Bogotá, Mexico City),
with varied authentication challenge methods. This pattern is
inconsistent with a bot-driven or mass-compromise signature, and
consistent instead with each event being a genuinely distinct person's
first-ever login from a country this dataset's institutional traffic
almost never includes (97% of all events originate in Angola or
Brazil). Google's own detection appears to flag "country essentially
unseen for this institution" close to deterministically — an extreme
case of the broader `is_new_country` pattern already confirmed with a
moderate, non-extreme odds ratio (1.51, 95% CI [1.43, 1.60]) across the
dataset as a whole (see Article 2's empirical analysis).

**Interpretation note for downstream use**: this reflects institutional
traffic novelty relative to this specific dataset's baseline, not a
property of the countries or the people logging in from them. Any
reporting of this finding should state that explicitly, given how
easily a bare "100% suspicious from country X" statistic could be
misread out of context.
