# Article 4 — Cross-Source Correlation: Methodology and Results

**Status**: internal documentation, `repo_privado` only. The underlying
correlation features (`article4_full_dataset.csv`,
`login_correlation_features.csv`) contain `actor_email_hash` and
`event_time` and must never be published, per
`docs/PRIVACY_ANONYMIZATION_REPORT_EN.md`. This document may be
adapted for public release once/if a decision is made to publish an
Article 4 dataset artifact — not yet done.

## 1. Research question

Article 3 asked: from a login event's own features alone, how well can
a suspicious login be detected? Article 4 asks a different question:
**does knowing what happened after a login improve on that?** —
specifically, activity in Drive, Admin console, OAuth token grants,
Gmail, Meet, and Classroom in the minutes/hours following each login.

## 2. Data sources

| Source | Rows (deduplicated) | Role |
|---|---|---|
| Drive | 3,845,754 | High priority |
| Admin | 9,607 | High priority |
| Token (OAuth) | 1,309,100 | High priority |
| Gmail | 1,749,598 | High priority |
| Meet | 63,799 | Low priority (simple counts only) |
| Classroom | 24,064 | Low priority (simple counts only) |

Extracted via `extract_multi_source.py` from the Google Workspace Admin
Reports API, using the same actor pseudonymization scheme
(HMAC-SHA256, unsalted at the raw-hash stage) as the login pipeline —
confirmed to produce byte-identical `actor_email_hash` values for the
same real person across both pipelines, which is what makes
correlation possible at all.

**Retention constraint**: Google Workspace audit logs are retained for
approximately 180 days. Login events before the earliest available
source data cannot be correlated — of 73,528 total login events,
53,906–73,527 fall within a correlatable window depending on how far
back the source extraction reaches (see `EVALUATION_WINDOW_START` in
`correlate_login_sources.py` for the exact cutoff in use).

## 3. Correlation methodology

**Matching key**: `actor_email_hash` (identical across the login
pipeline and the multi-source pipeline, confirmed by construction) +
event time.

**Time windows**: three tiers after each login, chosen to capture
different plausible reaction speeds rather than a single arbitrary
window:
- **5 minutes** — immediate/automated reaction
- **30 minutes** — short-term human action
- **2 hours** — extended session activity

**Performance**: a naive row-by-row cross join was impractical at this
scale (Drive alone: 3.8M rows). Implemented instead as a per-actor
binary search (`np.searchsorted` on time-sorted, per-actor grouped
arrays) — O(log n) per login per source rather than O(n).

## 4. Features produced

For each of the four high-priority sources (admin, token, drive,
gmail): event counts in each of the three windows
(`{source}_events_{5min,30min,2h}`).

Gmail additionally gets a risk-specific count:
`gmail_risky_action_{5min,30min,2h}` — occurrences of
`mail_event_type` in {15, 16, 17, 32} (link clicked, attachment
clicked/downloaded/downloaded), per the official Gmail activity
reference.

Meet and Classroom (low priority): a single count in the widest window
only, `{source}_events_2h`.

**`immediacy_ratio`** (added after reviewing the correlation results,
see section 5): the share of a login's 2-hour high-priority activity
(admin+token+drive+gmail) that occurred within the first 5 minutes.
0 when there is no 2-hour activity to compute a ratio from.

18 new numeric features in total.

## 5. Key exploratory finding, before any model training

Raw activity counts turned out **lower** for suspicious logins than
normal ones, not higher:

- **93.7%** of suspicious logins have **zero** follow-up activity
  across all six sources, vs **79.1%** of normal logins.
- Even among logins that DO have some follow-up activity, suspicious
  ones still show lower counts across every single source (ratios of
  0.30–0.89 vs normal logins in the same subset).
- The naive "attacker actively exploiting the account" hypothesis does
  **not** hold up in aggregate. This is consistent with suspicious
  logins skewing toward cold-start/low-engagement accounts (already
  established in Article 3 — cold-start logins: 9.02% suspicious rate
  vs mature-profile logins: 2.27%), not toward active post-compromise
  behavior.

**But a real, distinct signal exists in timing, not volume**: among
logins with any follow-up activity, suspicious ones show it
concentrated earlier — **59.7%** within the first 5 minutes, vs
**42.1%** for normal logins. This is what `immediacy_ratio` captures.

The Gmail risky-action ratio specifically (risky actions / all Gmail
events, among logins with Gmail activity) was checked and found
**lower**, not higher, for suspicious logins (3.1% vs 6.5%) — reported
here as a negative result for that specific angle, not omitted.

## 6. Benchmark results

Same methodology as Article 3 (chronological 70/15/15 split, the same
academic-vacation evaluation exclusion, the same per-user training cap
at 80 events, decision thresholds selected on validation only). Two
feature sets compared directly:

- **Article 3 only**: the 36 original login-derived numeric features
- **Article 3 + 4**: the above, plus the 18 correlation features

| Model | AUC-ROC (Art. 3) | AUC-ROC (Art. 3+4) | F1 (Art. 3) | F1 (Art. 3+4) |
|---|---|---|---|---|
| Logistic Regression | 0.9181 | 0.9039 | 0.6326 | 0.6284 |
| Decision Tree | 0.9455 | 0.9449 | 0.7530 | 0.7388 |
| **Random Forest** | **0.9582** | 0.9565 | 0.7382 | 0.7101 |
| XGBoost | 0.9398 | 0.9447 | 0.7352 | 0.7274 |
| **LightGBM** | 0.9474 | **0.9513** | 0.7291 | **0.7567** |

Full table with PR-AUC, precision, recall: `article4_benchmark_results.csv`.

## 7. Interpretation

For most models, adding the correlation features makes **no
meaningful difference, or a small negative one** — consistent with
the exploratory finding that raw post-login activity is a weak,
mostly-zero signal for the population that matters most (suspicious
logins).

**LightGBM is the clear exception**: it improves on both AUC-ROC and
PR-AUC with the extended feature set, and produces the best F1 score
of all ten model/feature-set combinations (0.7567). A plausible
explanation is LightGBM's leaf-wise (rather than level-wise) tree
growth, which may exploit sparse, mostly-zero features like these more
effectively than the other tree-based methods — this is a hypothesis
worth stating explicitly in the article, not a proven mechanism.
Feature importance analysis (not yet done) could help confirm whether
`immediacy_ratio` specifically drives this improvement, matching the
exploratory finding in section 5, or whether it's the raw counts.

**Headline conclusion for Article 4**: cross-source correlation, at
least with these specific features and time windows, does not broadly
improve suspicious-login detection over login-only features — but the
question is more nuanced than a flat "no": the *timing* of post-login
activity (not its volume) carries real signal, and at least one modern
gradient-boosting algorithm can extract value from the correlation
features that others cannot. Both points are worth reporting as
genuine findings, not treated as a negative result to downplay.

## 8. Known limitations

- Meet/Classroom were only ever given simple counts (no risk-specific
  flags engineered), per the project's own risk-based prioritization
  decision — not because they were checked and found unhelpful.
- The 5min/30min/2h window choice was a reasoned default (see the
  original design discussion), not tuned or validated against
  alternatives — a sensitivity analysis on window size is a natural
  extension, not yet done.
- `immediacy_ratio` was defined after seeing the exploratory results
  that motivated it (a post-hoc feature, clearly documented as such
  here) — its performance on the held-out test set is still a fair,
  untouched evaluation, but the FEATURE'S EXISTENCE was informed by
  looking at the data first, worth disclosing plainly in the article's
  methodology section.
- CatBoost, Bayesian hyperparameter optimization, and FT-Transformer/
  SAINT were considered and deliberately not pursued for this dataset
  scale, given this project's compute constraints and the literature
  on tree-based methods generally matching or exceeding deep tabular
  models at this data volume (Grinsztajn et al.) — noted for
  completeness, not because they were tried and failed.

## 9. Reproducibility

```
python src/correlate_login_sources.py     # produces login_correlation_features.csv
# merge with suspicious_logins_restricted_v1.csv on record_id
# (see the merge step in the Article 4 working session, not yet its own script)
python src/run_article4_isolated.py       # produces article4_benchmark_results.csv
```

`run_article4_isolated.py` trains each (model, feature set) combination
in its own subprocess via `train_one_model.py`, rather than one long
process — needed in constrained environments (confirmed: repeated
silent OOM kills training multiple models in one process here), and
harmless overhead anywhere else.
