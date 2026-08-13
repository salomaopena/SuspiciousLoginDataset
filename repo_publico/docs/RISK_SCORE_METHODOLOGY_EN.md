# `risk_score` Methodology

## Why it isn't an intuitive formula

An initial version of `risk_score` (a weighted sum of hand-picked
signals: new IP, new country, country change, continent change,
abnormal hour) was empirically tested against the real label
(`is_suspicious`) on a chronological train/test split, and performed
**worse than random** (AUC-ROC=0.375 on the test set, never seen during
fitting).

The root cause was confirmed with the data: three of that formula's
five terms were not independent signals — `is_new_country` implied
`country_changed` in 100% of rows, and `continent_changed` implied
`country_changed` in 100% of rows too. The formula was, in practice,
counting the same signal ("location changed") two or three times over,
while ignoring the two signals that, on their own, genuinely correlated
with the real label (`impossible_travel` and
`distinct_users_per_network_24h`).

This naive formula was **not kept** as a column in the published
dataset — every feature that made it up is already its own column, so
anyone wanting to reproduce that comparison for a paper can recompute it
directly from them.

## Methodology used in the current version

1. **Chronological split**, never random: the first 70% of events by
  `event_time` for fitting, the next 15% for validation, the last 15%
  (never seen during fitting or validation) for test — consistent with
  the project's general rule of never using random splits as the main
  evaluation on sequential data.
2. **Logistic regression** (`sklearn.linear_model.LogisticRegression`,
  `class_weight="balanced"`, given the class imbalance) over six
  features: `new_ip`, `geo_jump`, `abnormal_login_hour`,
  `impossible_travel`, `distinct_users_per_network_24h`,
  `multiple_country_logins_24h`.
3. **Converting the coefficients to points**, a standard technique from
  risk-scoring systems (*scorecards*): each coefficient multiplied by a
  common scale factor (40, chosen so the largest coefficient
  (`impossible_travel`, in earlier versions) would result in a readable
  point count), then rounded. Exception: `distinct_users_per_network_24h`,
  being continuous with a small coefficient, keeps one decimal place
  instead of rounding to an integer — rounding to zero (which happened
  in an earlier attempt with a smaller scale) would have silently
  eliminated the dataset's second-strongest signal.
4. **Validating the rounding loss**: the integer-point version kept
  practically all of the continuous version's performance (AUC-ROC
  identical to 4 decimal places on the test set).

## Weights are frozen, not recomputed on every run

The current weights are fixed directly in the code (`data/processed.py`,
`RISK SCORE` section), not automatically recomputed every time the
script runs. A published dataset needs a stable `risk_score` definition
— if the weights silently changed every time more raw files were added,
the column's meaning would shift without warning between uses.

## How to produce a new version (v4, v5, ...)

Repeat exactly the procedure above on the updated dataset:

1. Load the latest `suspicious_logins_restricted_v1.csv` (needs
  `event_time`, only available in the restricted schema).
2. Sort by `event_time`, cut at the first 70%/next 15%/last 15%
  (excluding any confirmed-unreliable period, per the institution —
  currently July-August, see `EVALUATION_CUTOFF_DATE` in
  `benchmark_ml.py`).
3. Build `geo_jump` from `country_changed`/`continent_changed` (already
  present in the schema, no need to recompute).
4. Fit `LogisticRegression(class_weight="balanced", max_iter=1000,
  random_state=42)` on the six features listed above.
5. Scale the coefficients (start with a factor of 40, adjust if any
  small coefficient rounds to zero) and round.
6. Validate on the test split: confirm the integer-point version
  doesn't lose meaningful performance versus the continuous version
  (compare AUC-ROC/PR-AUC for both).
7. **Never overwrite the previous version** — save as
  `suspicious_logins_public_v4.csv`, keep v3 available, and record the
  date, data volume used, and the new weights and metrics here. This
  keeps any paper already published based on an earlier version
  reproducible, even after a newer one exists.

## Version history

| Version | Fit date | Rows used | AUC-ROC (test) | PR-AUC (test) | Note |
|---|---|---|---|---|---|
| v1 | 2026-08-12 | ~5,332 (after duplicate removal) | 0.768 (continuous) / 0.768 (points) | 0.196 (continuous) / 0.196 (points) | First empirical version, replaces the original naive formula |
| v2 | 2026-08-12 | 26,999 (training, after excluding the Jun-Aug vacation period) | 0.718 | 0.159 | See the note below on the `impossible_travel` drop |
| v3 | 2026-08-12 | 48,238 (training, two institutions, after excluding Jul-Aug) | 0.624 | 0.095 | `impossible_travel` confirmed to have no signal for a 2nd time in a row (now 0.00). The lower AUC-ROC vs v2 is not a regression — it reflects a genuinely more diverse population (see note below) |

## Note on v3: the lower AUC-ROC is expected, not a regression

`0.624` is lower than v2's `0.718` — but this does **not** mean
`risk_score` got worse. With a much more diverse population (two
institutions, 36,691 users instead of 11,691, much lower geographic
concentration), the classification problem itself became genuinely
harder — the same six simple signals explain a smaller share of the
real variation when the population is more heterogeneous. The full
reference models (`benchmark_ml.py`) confirm this directly: on the same
data split, they reach `AUC-ROC=0.92-0.96`, a much larger gap over
`risk_score` (`0.624`) than the gap already seen in v2 — the comparison
remains valid and strong for Article 3, just now on a more honest and
harder evaluation basis.

## Note on v2: `impossible_travel` lost its signal at larger scale

In the original small sample (~5,300 rows), `impossible_travel` was one
of only two individual signals with genuine correlation to the real
label (+0.064). Refit on the full dataset (~27,000 training rows,
excluding the vacation period), the correlation dropped to essentially
zero (-0.005) — the suspicious rate is even slightly **lower** when
`impossible_travel=1` (4.95%) than when it's `0` (7.21%). The logistic
regression coefficient reflects this (essentially zero, `-0.03`).

This is reported as an honest finding, not hidden: the small sample led
to a conclusion that didn't hold up with more data — exactly the kind of
risk that motivated this refit, and worth mentioning explicitly in
Article 3 as an example of why validating at different scales matters.

## Note on v2: vacation period excluded from the train/validation/test split

Confirmed with the institution: June through August is the academic
vacation period in Angola. Event volume drops sharply during this period
(~6,500-8,000/month to 1,440-3,172/month), and the suspicious rate drops
even further (from ~7% to ~1.3-1.5%). No confirmed security policy
change during this period — the most likely cause is a combination of
genuinely different behavior in a smaller population on break, possibly
combined with labeling not yet fully settled for the most recent events
(given the extraction was done nearly in real time).

This period was excluded from the train/validation/test split used for
`risk_score` v2 and for the reference models (`benchmark_ml.py`), but
**kept in the published dataset** — this is not a data quality problem,
it is a decision that the label's reliability in that specific period is
not yet confirmed for evaluation purposes. See `EVALUATION_CUTOFF_DATE`
in `benchmark_ml.py`.
