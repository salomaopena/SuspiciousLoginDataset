"""
Benchmark ML models for suspicious login detection.

Trains and evaluates the baseline models agreed for Article 3: Logistic
Regression, Decision Tree, Random Forest, XGBoost, LightGBM, and Isolation
Forest -- compared against the empirical risk_score (see
docs/RISK_SCORE_METHODOLOGY.md) on the SAME held-out temporal test split,
so the comparison is apples-to-apples.

Requires the RESTRICTED dataset (needs event_time for the chronological
split, which does not exist in the public schema). Never commit or publish
this script's output CSVs/plots if they reveal per-row restricted-schema
details -- aggregate metrics (the printed tables) are safe to publish,
row-level predictions are not.

Methodology notes, per the project's own rules:
- Temporal split, never random: first 70% of events (by event_time) for
  training, next 15% for validation (hyperparameter/threshold selection),
  last 15% for test (reported metrics only, never used to tune anything).
- risk_score / risk_level are EXCLUDED from the model input features.
  They were themselves fit using label information (see
  RISK_SCORE_METHODOLOGY.md), so using them as inputs to a new model
  trained on overlapping data would be a form of leakage; they are the
  BASELINE being compared against, not a feature.
- actor_pseudo_id is excluded (an identifier, not a predictive feature).
- Categorical encoders (ip_country, continent, login_type) are fit on the
  TRAIN split only; categories never seen in training map to an explicit
  "unseen" bucket in validation/test, rather than crashing or leaking
  information about the val/test distribution back into encoding.
- login_challenge_method (pipe-separated, high cardinality) is converted
  to a small set of interpretable binary flags instead of one-hot
  encoding every combination.
- Reported metrics: PR-AUC, precision, recall, F1, confusion matrix,
  Brier score (calibration), and false positives per 1,000 logins -- never
  only accuracy, given the ~7% positive rate.
"""

import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore", category=UserWarning)

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

try:
    from lightgbm import LGBMClassifier
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False


RESTRICTED_FILE = Path("data/processed/suspicious_logins_restricted_v1.csv")

# Confirmed with the (first) institution: June-August is the Angolan
# academic vacation period. Login volume drops sharply (from
# ~6,500-8,000/month to 1,440-3,172/month) and the suspicious rate drops
# even more sharply (from ~7-9% to ~1.3-1.5%) starting specifically in
# July -- confirmed NOT caused by any security policy change during this
# period. After adding a second institution (whose extraction does not
# extend into July-August), June's rate returned to a normal-looking
# range (6.97%, vs ~1.3-1.5% for July-August) -- consistent with June
# being genuinely fine and only July-August remaining suspect. Two
# plausible, not mutually exclusive causes remain for the July-August
# anomaly: (a) genuinely different, more routine behavior from the
# smaller population still active during a break, and/or (b)
# is_suspicious may not be set instantaneously -- very recent events may
# not have had time to receive a label Google would eventually assign
# retroactively. Excluded from the train/val/test split used for model
# evaluation until this is resolved with more confidence -- NOT removed
# from the published dataset itself, since these are real, valid events,
# just ones whose suspicious rate isn't yet trusted as a fair evaluation
# target. Revisit this cutoff once July-August data has had time to
# mature, or once the ambiguity above is otherwise resolved.
EVALUATION_CUTOFF_DATE = "2026-07-01"

# Features actually fed to the models. Deliberately excludes:
#   actor_pseudo_id  -- identifier, not a predictive feature
#   risk_score, risk_level -- the baseline being compared against
#   label -- the target
#   event_time -- used only for the split, not as a feature (a raw
#     timestamp would let a model "memorize" specific dates rather than
#     learn generalizable behavioral patterns)
NUMERIC_FEATURES = [
    "event_hour", "day_of_week", "month", "quarter",
    "is_weekend", "is_business_hours", "is_night_login",
    "ip_version", "new_ip", "distinct_ips_7d", "distinct_ips_30d",
    "is_new_country", "is_new_region", "is_new_city",
    "distinct_countries_cumulative", "distinct_regions_cumulative",
    "distinct_cities_cumulative", "country_changed", "continent_changed",
    "countries_seen_30d", "regions_seen_30d", "cities_seen_30d",
    "logins_24h", "logins_7d", "logins_30d", "avg_logins_per_day",
    "hours_since_last_login", "days_since_first_login",
    "abnormal_login_hour", "abnormal_weekday",
    "impossible_travel", "travel_distance_km", "travel_speed_kmh",
    "multiple_country_logins_24h", "distinct_users_per_network_24h",
    "geo_jump", "history_available",
]
CATEGORICAL_FEATURES = ["ip_country", "continent", "login_type"]
TOP_K_CATEGORIES = 10  # per categorical column; rarer values -> "_other_"


def engineer_challenge_method_flags(df):
    """login_challenge_method -> a handful of interpretable binary flags,
    instead of one-hot encoding every distinct pipe-separated combination
    (which would blow up dimensionality on a genuinely high-cardinality,
    largely uninformative-per-combination field)."""
    methods = df["login_challenge_method"].fillna("").astype(str)
    out = pd.DataFrame(index=df.index)
    for flag_name, token in [
        ("uses_password", "password"),
        ("uses_passkey", "passkey"),
        ("uses_device_prompt", "device_prompt"),
        ("uses_preregistered_phone", "idv_preregistered_phone"),
        ("uses_preregistered_email", "idv_preregistered_email"),
    ]:
        out[flag_name] = methods.str.contains(token, regex=False).astype(int)
    out["num_challenge_methods"] = methods.apply(
        lambda v: len(set(v.split("|"))) if v else 0)
    return out


def fit_category_encoder(train_series, top_k):
    """Returns the set of categories to keep as their own one-hot column
    (the top_k most frequent IN TRAIN ONLY); anything else, in any split,
    maps to '_other_'. Fitting on train only is what prevents a category
    that's only common in val/test from leaking distributional information
    back into the encoding."""
    return set(train_series.value_counts().head(top_k).index)


def apply_category_encoder(series, keep_categories, prefix):
    capped = series.where(series.isin(keep_categories), other="_other_")
    return pd.get_dummies(capped, prefix=prefix, dtype=int)


def build_features(df, keep_categories_by_col):
    df = df.copy()
    # history_available: whether this user has any PRIOR event at all,
    # derived from hours_since_last_login (which processed.py sets to 0
    # specifically and only for a user's first-ever observed event, via
    # .diff().fillna(0) -- any later event has a real, positive elapsed
    # time). Added because 88.5% of users in the full dataset have only a
    # single event: every "historical" feature (avg_logins_per_day,
    # distinct_countries_cumulative, etc.) is trivially 0/1/degenerate for
    # that majority, and confirmed genuinely predictive on its own, not
    # just a helper flag -- the real suspicious rate measured on this
    # dataset is 2.69% among users with prior history vs 7.69% among
    # users on their first-ever observed event.
    df["history_available"] = (df["hours_since_last_login"] > 0).astype(int)

    numeric = df[NUMERIC_FEATURES].copy()
    # A small number of rows have missing geo data at the source (see
    # docs/DATA_AUDIT_REPORT.md -- confirmed 4 rows with all geo fields
    # missing, 6 more missing only ip_region), which cascades into NaN in
    # every derived feature that depends on ip_region/ip_country/etc.
    # Filled with 0 here: for count-like features (distinct_*_cumulative,
    # *_seen_30d) this means "no known distinct value counted," which is
    # the correct behavior for a row with unknown geo, not a guess at a
    # real value. Documented here rather than silently handled, since a
    # more careful imputation strategy (e.g. a dedicated "geo_missing"
    # flag) is a reasonable future refinement, not done in this first
    # working baseline.
    numeric = numeric.fillna(0)
    challenge_flags = engineer_challenge_method_flags(df)
    cat_frames = [
        apply_category_encoder(df[col], keep_categories_by_col[col], col)
        for col in CATEGORICAL_FEATURES
    ]
    return pd.concat([numeric, challenge_flags] + cat_frames, axis=1)


def cap_dominant_users_in_training(train_df, max_events_per_user=80, random_state=42):
    """Subsamples any user's events DOWN to max_events_per_user, applied
    ONLY to the training split -- validation and test are never touched,
    since they need to reflect the real, honest distribution the model
    will actually be judged against.

    Why this matters, confirmed with real data on this dataset: a single
    user contributed 5.04% of ALL training rows (1,836 of ~36,000) at the
    time this was written -- enough for a model to plausibly learn that
    one person's specific behavioral quirks rather than genuinely
    generalizable patterns. More importantly, repeat/prolific users have
    a MUCH lower suspicious rate (2.69%) than users on their first-ever
    observed event (7.69%) -- since prolific users dominate raw training
    volume, the uncapped training set systematically underweights the
    population where the suspicious signal actually concentrates.

    max_events_per_user=80 is not an arbitrary round number: it is the
    99th percentile of events-per-user within the training split at the
    time this was chosen (confirmed: only 136 of 8,718 training users
    exceeded it) -- a deliberately surgical cut affecting only the most
    extreme outliers, not moderately active users.
    """
    counts = train_df["actor_pseudo_id"].value_counts()
    over_cap = counts[counts > max_events_per_user]
    if len(over_cap) == 0:
        print(f"No user exceeds {max_events_per_user} events in training -- nothing to cap.")
        return train_df

    keep_indices = []
    rng = np.random.RandomState(random_state)
    for user, group in train_df.groupby("actor_pseudo_id"):
        if len(group) > max_events_per_user:
            keep_indices.extend(
                rng.choice(group.index, size=max_events_per_user, replace=False))
        else:
            keep_indices.extend(group.index)

    capped = train_df.loc[sorted(keep_indices)].reset_index(drop=True)
    n_removed = len(train_df) - len(capped)
    print(f"Capped {len(over_cap)} user(s) exceeding {max_events_per_user} events "
         f"in training -- removed {n_removed} rows ({n_removed/len(train_df)*100:.2f}% "
         f"of training), validation/test untouched")
    top_user_pct_before = counts.max() / len(train_df) * 100
    top_user_pct_after = min(counts.max(), max_events_per_user) / len(capped) * 100
    print(f"  most active user's share of training: "
         f"{top_user_pct_before:.2f}% -> {top_user_pct_after:.2f}%")
    return capped


def align_columns(train_X, other_X):
    """Ensures val/test have exactly the same columns as train (a category
    combination absent from a smaller val/test split would otherwise
    silently produce a different column set than train, breaking every
    sklearn model's .predict())."""
    return other_X.reindex(columns=train_X.columns, fill_value=0)


def false_positives_per_1000(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return (fp / len(y_true)) * 1000


def select_threshold_on_validation(y_val, val_scores):
    """Chooses the score threshold that maximizes F1 on the VALIDATION
    split, never the test split -- this is what the validation split is
    actually for (previously built and passed around but never used for
    anything, which defeated its stated purpose). Scans candidate
    thresholds at every distinct value the model actually produced on
    validation, which is more precise than a fixed grid and guarantees at
    least one candidate exists regardless of the score's scale."""
    candidates = np.unique(val_scores)
    best_threshold, best_f1 = 0.5, -1.0
    for t in candidates:
        y_pred = (val_scores >= t).astype(int)
        f1 = f1_score(y_val, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1, best_threshold = f1, t
    return best_threshold


def evaluate(name, y_true, scores, threshold):
    y_pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "model": name,
        "threshold_used": threshold,
        "AUC-ROC": roc_auc_score(y_true, scores),
        "PR-AUC": average_precision_score(y_true, scores),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "F1": f1_score(y_true, y_pred, zero_division=0),
        "brier_score": brier_score_loss(y_true, scores),
        "FP_per_1000_logins": false_positives_per_1000(y_true, y_pred),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
    }


def main():
    if not RESTRICTED_FILE.exists():
        raise FileNotFoundError(
            f"{RESTRICTED_FILE} not found. This script needs the RESTRICTED "
            f"dataset (for event_time, required for the temporal split) -- "
            f"run data/processed.py first."
        )

    df = pd.read_csv(RESTRICTED_FILE)
    df["event_time"] = pd.to_datetime(df["event_time"], format="ISO8601")
    df = df.sort_values("event_time").reset_index(drop=True)

    n_before_cutoff = len(df)
    df = df[df["event_time"] < EVALUATION_CUTOFF_DATE].reset_index(drop=True)
    print(f"Excluded {n_before_cutoff - len(df)} row(s) on/after {EVALUATION_CUTOFF_DATE} "
         f"(Angolan academic vacation period, see EVALUATION_CUTOFF_DATE docstring) "
         f"from the train/val/test split -- still present in the published dataset itself")
    print()

    # Drop any row with a missing value in a column this script actually
    # uses (features, label, or the timestamp needed for the split) --
    # deliberately NOT applied to the published dataset itself
    # (data/processed.py): missingness there is real information (e.g.
    # "this IP could not be geolocated") that a published research
    # artifact should keep visible, not silently discard. Restricted to
    # the columns actually fed into these models rather than every column
    # in the restricted file, since e.g. a missing ip_city (not a model
    # input) shouldn't force dropping a row that's otherwise complete.
    # history_available is DERIVED inside build_features() from
    # hours_since_last_login (not a raw column in the CSV yet at this
    # point) -- excluded here since checking a column that doesn't exist
    # yet would raise, not because it's exempt from the missing-value
    # discipline: hours_since_last_login itself IS checked below, and
    # history_available is deterministically derived from it afterward,
    # so it can never introduce a gap this check would have missed.
    relevant_columns = ([c for c in NUMERIC_FEATURES if c != "history_available"]
                        + CATEGORICAL_FEATURES
                        + ["login_challenge_method", "label", "event_time"])
    n_before = len(df)
    rows_with_gaps = df[relevant_columns].isna().any(axis=1)
    n_dropped = int(rows_with_gaps.sum())
    if n_dropped:
        # Sanity check before dropping: confirm this doesn't skew the
        # target class balance (e.g. if missing geo data happened to
        # correlate with is_suspicious for some reason, dropping those
        # rows would bias the benchmark, not just clean it up).
        rate_dropped = df.loc[rows_with_gaps, "label"].mean()
        rate_kept = df.loc[~rows_with_gaps, "label"].mean()
        print(f"Dropping {n_dropped} of {n_before} rows with a missing value "
             f"in a used column ({n_dropped/n_before*100:.2f}%)")
        print(f"  positive rate in dropped rows: {rate_dropped*100:.2f}%  "
             f"vs kept rows: {rate_kept*100:.2f}%")
    df = df.loc[~rows_with_gaps].reset_index(drop=True)

    n = len(df)
    train_end = int(n * 0.70)
    val_end = int(n * 0.85)
    train_df = df.iloc[:train_end]
    val_df = df.iloc[train_end:val_end]
    test_df = df.iloc[val_end:]

    print(f"train: {len(train_df)} ({train_df['event_time'].min()} to {train_df['event_time'].max()})")
    print(f"val:   {len(val_df)} ({val_df['event_time'].min()} to {val_df['event_time'].max()})")
    print(f"test:  {len(test_df)} ({test_df['event_time'].min()} to {test_df['event_time'].max()})")
    print(f"positive rate -- train: {train_df['label'].mean()*100:.2f}%  "
         f"val: {val_df['label'].mean()*100:.2f}%  test: {test_df['label'].mean()*100:.2f}%")
    print()

    train_df = cap_dominant_users_in_training(train_df, max_events_per_user=80)
    print()

    keep_categories_by_col = {
        col: fit_category_encoder(train_df[col], TOP_K_CATEGORIES)
        for col in CATEGORICAL_FEATURES
    }

    X_train = build_features(train_df, keep_categories_by_col)
    X_val = align_columns(X_train, build_features(val_df, keep_categories_by_col))
    X_test = align_columns(X_train, build_features(test_df, keep_categories_by_col))
    y_train, y_val, y_test = train_df["label"], val_df["label"], test_df["label"]

    pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

    models = {
        "LogisticRegression": LogisticRegression(
            class_weight="balanced", max_iter=1000, random_state=42),
        "DecisionTree": DecisionTreeClassifier(
            class_weight="balanced", max_depth=8, random_state=42),
        "RandomForest": RandomForestClassifier(
            class_weight="balanced", n_estimators=200, max_depth=10,
            random_state=42, n_jobs=-1),
    }
    if HAS_XGBOOST:
        models["XGBoost"] = XGBClassifier(
            scale_pos_weight=pos_weight, n_estimators=200, max_depth=6,
            eval_metric="logloss", random_state=42)
    if HAS_LIGHTGBM:
        models["LightGBM"] = LGBMClassifier(
            class_weight="balanced", n_estimators=200, max_depth=6,
            random_state=42, verbosity=-1)

    results = []
    for name, model in models.items():
        model.fit(X_train, y_train)
        val_scores = model.predict_proba(X_val)[:, 1]
        test_scores = model.predict_proba(X_test)[:, 1]
        threshold = select_threshold_on_validation(y_val, val_scores)
        results.append(evaluate(name, y_test, test_scores, threshold))

    # Isolation Forest: genuinely unsupervised (fit without y at all), its
    # anomaly score is negated so higher = more anomalous = more suspicious,
    # matching the other models' score direction for a fair AUC comparison.
    # Normalization range (min/max) is fit on VALIDATION and applied to
    # BOTH val and test with that same range -- normalizing each split
    # independently against its own min/max would make a threshold chosen
    # on validation meaningless when applied to test (a score of, say,
    # 0.9 would not mean the same thing in each split).
    iso = IsolationForest(
        n_estimators=200, contamination=max(y_train.mean(), 0.01), random_state=42)
    iso.fit(X_train)
    iso_scores_val_raw = -iso.score_samples(X_val)
    iso_scores_test_raw = -iso.score_samples(X_test)
    iso_min, iso_max = iso_scores_val_raw.min(), iso_scores_val_raw.max()
    # Clipped to [0, 1] after normalizing: since the range is fit on
    # VALIDATION (needed for the threshold to mean the same thing in both
    # splits, see the comment above), a genuinely more extreme test-split
    # value can fall outside [0, 1] -- valid for threshold comparison, but
    # brier_score_loss requires bounded probabilities. Clipping treats
    # "more extreme than anything seen in validation" as maximally
    # confident in that direction, which is the correct interpretation
    # here, not a data error.
    iso_scores_val = np.clip((iso_scores_val_raw - iso_min) / (iso_max - iso_min + 1e-9), 0, 1)
    iso_scores_test = np.clip((iso_scores_test_raw - iso_min) / (iso_max - iso_min + 1e-9), 0, 1)
    iso_threshold = select_threshold_on_validation(y_val, iso_scores_val)
    results.append(evaluate("IsolationForest", y_test, iso_scores_test, iso_threshold))

    # risk_score baseline, same normalization discipline: range fit on
    # validation, applied to both splits, threshold chosen on validation.
    risk_val_raw = val_df["risk_score"].to_numpy()
    risk_test_raw = test_df["risk_score"].to_numpy()
    risk_min, risk_max = risk_val_raw.min(), risk_val_raw.max()
    # Same clipping rationale as IsolationForest above.
    risk_scores_val = np.clip((risk_val_raw - risk_min) / (risk_max - risk_min + 1e-9), 0, 1)
    risk_scores_test = np.clip((risk_test_raw - risk_min) / (risk_max - risk_min + 1e-9), 0, 1)
    risk_threshold = select_threshold_on_validation(y_val, risk_scores_val)
    results.append(evaluate("risk_score (baseline)", y_test, risk_scores_test, risk_threshold))

    results_df = pd.DataFrame(results).set_index("model")
    pd.set_option("display.width", 140)
    pd.set_option("display.max_columns", 20)
    print(results_df.round(4))

    results_df.to_csv("benchmark_results.csv")
    print("\nSaved benchmark_results.csv")


if __name__ == "__main__":
    main()
