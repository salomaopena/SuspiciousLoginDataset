"""
Build ML dataset from Google Workspace suspicious login logs.

CORRECTED VERSION -- fixes applied after audit (see THESIS_NOTES / audit
report for the full reasoning behind each one):

1. Pseudonymization was built (unique_users mapping) but never applied --
   the raw, unsalted SHA-256 hash was leaking straight into the output.
   Fixed: HMAC-SHA256 with a secret key (HMAC_SECRET_KEY, from .env) is
   applied on top of the already-hashed actor_email_hash/ip_hash, giving
   deterministic pseudonyms (same user/network -> same pseudonym across the
   dataset) that are NOT reversible by dictionary attack without the key.
   Important caveat, stated explicitly rather than hidden: the RAW CSV
   (suspicious_login_logs13.csv) already contains an UNSALTED hash from the
   extraction step (extract_suspicious_logins.py's `h()` function) -- this
   script cannot retroactively re-salt data that already left the source
   system unsalted. The raw CSV must stay in the restricted/private tier
   regardless of what this script does; only the PUBLIC output produced
   here is protected by the HMAC layer. For future extractions, the
   extraction script itself should be fixed to HMAC at the source.

2. abnormal_login_hour leaked future information: the per-user mean/std of
   event_hour was computed over the user's ENTIRE history (past AND
   future events relative to each row), via `.transform("mean"/"std")`.
   Fixed: replaced with an expanding (past-only) mean/std per user, so a
   row's "is this hour abnormal" only ever uses events strictly before it.

3. new_country / new_region / new_city were CUMULATIVE COUNTS (confirmed
   against the real generated dataset: new_country=2 contributed 60 points
   to risk_score via 2*30, not a clean 30-point "yes, first time in a new
   country" signal) despite being fed into risk_score as if they were
   binary flags. Fixed: added TRUE binary first-occurrence flags
   (is_new_country / is_new_region / is_new_city, same `~s.duplicated()`
   pattern already correctly used for new_ip), used in risk_score instead.
   The cumulative counts are kept as separate, clearly-named features
   (distinct_countries_cumulative, etc.) since they have real analytical
   value on their own -- just not as risk_score inputs.

4. ip_region was silently just the ISO country code, duplicated
   (getGeoFromPI sets `data["ip_region"] = data.get("countryCode")`,
   confirmed 100% of real rows: ip_region == 2-letter code matching
   ip_country). Dropped from the public schema as redundant/misleading
   under its current name; kept in the restricted schema for audit trail.

5. ip_city, latitude, longitude are still used INTERNALLY to compute
   travel_distance_km / travel_speed_kmh / impossible_travel (legitimate,
   already-safe derived signals), but are no longer written to the PUBLIC
   output -- only to the restricted one. This was already the agreed plan
   from the original prompt; the previous version's final_columns list
   contradicted it by including them directly.

6. Network identifier (ip_hash) was dropped entirely from the previous
   output (not pseudonymized, not kept -- just absent), losing a
   legitimate UEBA signal. Fixed: pseudonymized (network_pseudo_id, same
   HMAC scheme) and a derived, leakage-safe feature
   (distinct_users_per_network_24h) is computed and included in the
   PUBLIC schema. The raw network_pseudo_id itself is only in the
   restricted schema, to avoid adding a second freely-correlatable
   identifier to the public release without a clear analytical need for
   it there specifically (the derived count feature carries the UEBA
   signal without that added correlation surface).

7. login_challenge_method sometimes repeats the same value consecutively
   (e.g. "password|password", confirmed a real, source-side pattern from
   the Google Admin API's own multiValue field, not an extraction bug).
   Normalized in the public schema by collapsing to the set of distinct
   methods actually present, in original order, joined the same way.

8. Multi-file input: extract_suspicious_logins.py resets record_id=1 at
   the start of EVERY run, so raw extraction files are named
   suspicious_login_logs0.csv, suspicious_login_logs1.csv, etc. (one per
   run) rather than a single accumulating file. This script now reads
   ALL matching files from data/raw/, refuses to proceed if they don't
   share the same column schema (rather than silently concatenating
   mismatched columns into NaNs), deduplicates rows that are identical
   in every column except record_id (an overlapping extraction window
   across two runs would otherwise double-count those events), and
   replaces the per-file record_id with one fresh, globally sequential
   id over the combined result.

9. Two real raw files needed defensive parsing, not the defaults pandas
   assumes. One turned out to be semicolon-delimited instead of comma-
   delimited (a common side effect of a CSV having passed through Excel
   under certain regional settings) -- read with a hard-coded comma, this
   silently produced a single column containing the whole header/row
   text, which then surfaced as a confusing "different column set"
   schema-mismatch error instead of the real, simple cause. Another
   failed to decode as UTF-8 entirely (an accented character saved under
   cp1252, Excel's Windows "ANSI" default in Portuguese/Western-European
   locales). Fixed: each raw file's delimiter is auto-detected
   individually, and its encoding is tried as a fallback chain
   (utf-8 -> cp1252 -> latin-1, the last of which always succeeds but
   is not guaranteed correct -- worth a manual spot-check if a file
   needed it) rather than either being assumed.
"""

import hashlib
import hmac
import math
import os
from pathlib import Path

import numpy as np
import pandas as pd
from dotenv import load_dotenv

# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data/raw"
RAW_FILE_PATTERN = "suspicious_login_logs*.csv"
PUBLIC_FILE = BASE_DIR / "data/processed/suspicious_logins_public_v1.csv"
RESTRICTED_FILE = BASE_DIR / "data/processed/suspicious_logins_restricted_v1.csv"

# ============================================================
# PSEUDONYMIZATION KEYS (single institution, or multiple)
# ============================================================
# Single-institution mode (unchanged from before): loose CSV files
# directly in data/raw/, one shared HMAC_SECRET_KEY from .env/environment.
#
# Multi-institution mode: data/raw/ contains SUBDIRECTORIES instead of
# loose files, one per institution (e.g. data/raw/institution_a/,
# data/raw/institution_b/), each with its own raw CSVs. Each subdirectory
# requires its OWN key, read from an environment variable named
# HMAC_SECRET_KEY_<FOLDER NAME UPPERCASED, non-alphanumerics -> '_'> --
# e.g. folder "institution_a" needs HMAC_SECRET_KEY_INSTITUTION_A.
#
# Why separate keys per institution, not one shared key for everything:
# if the same real person has an account at two different institutions
# (plausible -- someone who studied at one and now works at another) and
# both institutions' data were pseudonymized with the SAME key, that
# person would get the SAME pseudonym in both, silently correlating their
# behavior across institutions -- not the intent of combining datasets
# for more statistical power. Separate keys make that correlation
# impossible even in principle.
#
# Despite using different keys per institution, the FINAL short pseudonym
# IDs (U000001, U000002, ...) are assigned once, globally, AFTER
# combining all institutions' data (see the PSEUDONYMS section below) --
# never per-institution. Numbering per institution first and merging
# afterward would either collide (both institutions independently
# producing a "U000001") or require a prefix that reveals which
# institution each row came from, defeating a documented project rule:
# no institution-identifying column in the public schema, since that
# would recreate a small, identifiable subgroup within the merged
# population.

load_dotenv(BASE_DIR / ".env")


def env_var_name_for_institution(folder_name):
    return "HMAC_SECRET_KEY_" + "".join(
        c.upper() if c.isalnum() else "_" for c in folder_name)


def discover_raw_files_with_keys():
    """Returns a list of (file_path, hmac_key_bytes) tuples covering every
    raw CSV under data/raw/, whichever mode is in use. Fails loudly,
    naming the exact missing environment variable, rather than silently
    falling back to a shared/default key for a subdirectory whose own key
    isn't set -- a silent fallback here would quietly reintroduce the
    exact cross-institution correlation risk this design exists to
    prevent.
    """
    subdirs = sorted(p for p in RAW_DIR.iterdir() if p.is_dir())
    if not subdirs:
        # Single-institution mode: unchanged behavior.
        key = os.environ.get("HMAC_SECRET_KEY")
        if not key:
            raise RuntimeError(
                "HMAC_SECRET_KEY is not set. Put it in your .env (loaded "
                "elsewhere via python-dotenv, matching the pattern already "
                "used in extract_suspicious_logins.py) or export it in the "
                "shell before running this script. Never commit this key "
                "or store it in the repository -- anyone with it can "
                "re-derive the mapping between pseudonyms and the "
                "already-hashed raw identifiers."
            )
        key_bytes = key.encode("utf-8")
        files = sorted(RAW_DIR.glob(RAW_FILE_PATTERN))
        return [(f, key_bytes) for f in files]

    # Multi-institution mode: one key per subdirectory.
    pairs = []
    for subdir in subdirs:
        env_name = env_var_name_for_institution(subdir.name)
        key = os.environ.get(env_name)
        if not key:
            raise RuntimeError(
                f"{env_name} is not set (needed for data/raw/{subdir.name}/). "
                f"Every institution subdirectory under data/raw/ needs its "
                f"own HMAC_SECRET_KEY_<FOLDER NAME> environment variable, "
                f"in .env or the shell -- never shared between "
                f"institutions, and never committed to the repository."
            )
        key_bytes = key.encode("utf-8")
        files = sorted(subdir.glob(RAW_FILE_PATTERN))
        pairs.extend((f, key_bytes) for f in files)
    return pairs


def pseudonymize(raw_hash_value, key_bytes):
    """HMAC-SHA256 the already-hashed raw value with a secret key, keeping
    only the first 16 hex chars (matches the raw hash's own length, plenty
    of collision resistance for a population of a few thousand entities).
    Deterministic: the same input always produces the same pseudonym,
    which is required for correlation to work (e.g. counting how many
    events belong to the same user) -- it is pseudonymization, not
    anonymization; re-identification is only prevented for someone WITHOUT
    the key, not impossible in principle for someone who has it.
    """
    if pd.isna(raw_hash_value) or raw_hash_value in (None, ""):
        return None
    return hmac.new(key_bytes, str(raw_hash_value).encode("utf-8"),
                    hashlib.sha256).hexdigest()[:16]


def make_short_id_map(pseudonyms, prefix):
    """Map a collection of HMAC pseudonyms to short sequential IDs
    (U000001, N000001, ...) in first-appearance order, for readability in
    the public release. The HMAC pseudonym itself is not exposed."""
    seen = {}
    for p in pseudonyms:
        if p is not None and p not in seen:
            seen[p] = f"{prefix}{len(seen) + 1:06d}"
    return seen


# ============================================================
# HAVERSINE DISTANCE (no external dependency)
# ============================================================

def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance in km. Pure stdlib, no extra dependency for a
    public research artifact -- one less thing a reader needs to install
    or trust the provenance of."""
    r = 6371.0088  # mean Earth radius, km
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2)
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# ============================================================
# LOAD -- one or more raw extraction files (fix #8: extract_suspicious_
# logins.py resets record_id=1 at the start of EVERY run, so simply
# concatenating files would produce duplicate record_id values across
# them. Handled below by discarding the per-file record_id entirely and
# generating one fresh, globally sequential id after combining everything.
# ============================================================

raw_files_with_keys = discover_raw_files_with_keys()
if not raw_files_with_keys:
    raise FileNotFoundError(
        f"No raw files found under {RAW_DIR}. Expected either loose files "
        f"like suspicious_login_logs0.csv directly in data/raw/ (single "
        f"institution), or subdirectories like data/raw/institution_a/ "
        f"each containing their own such files (multiple institutions)."
    )

print(f"Found {len(raw_files_with_keys)} raw file(s):")
for f, _ in raw_files_with_keys:
    print(f"  {f.relative_to(RAW_DIR)}")

frames = []
expected_columns = None
for f, hmac_key_bytes in raw_files_with_keys:
    # Delimiter is auto-detected PER FILE rather than assumed to be a
    # comma: a real file in this exact situation (suspicious_login_logs1
    # .csv) turned out to be semicolon-delimited -- a common side effect
    # of a CSV having passed through Excel under certain regional settings
    # (frequent in Portuguese-language locales, where Excel's default CSV
    # export uses ";" instead of ","). Reading it with a hard-coded comma
    # silently produced ONE column containing the entire header/row text,
    # which then surfaced as a confusing "different column set" error
    # rather than the real, simple cause. sep=None with the python engine
    # asks pandas to sniff the actual delimiter used in each file.
    #
    # Encoding is also tried as a fallback chain, not assumed to be UTF-8:
    # another real file (suspicious_login_logs2.csv) failed to decode as
    # UTF-8 on a byte that is typical of an accented character (e.g. a, a,
    # c) saved under cp1252 -- Excel's default "ANSI" encoding on Windows
    # in Portuguese/Western-European locales, not UTF-8. cp1252 is tried
    # first as the most likely real cause here; latin-1 never raises a
    # decode error (it maps every byte to something) so it is the final,
    # always-succeeding fallback rather than a guaranteed-correct decode --
    # if a file needed latin-1 to load at all, its text fields are worth a
    # manual spot-check afterward.
    frame = None
    last_error = None
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            frame = pd.read_csv(f, sep=None, engine="python", encoding=encoding)
            if encoding != "utf-8":
                print(f"  (note: {f.name} was not valid UTF-8, read as {encoding} instead)")
            break
        except Exception as e:
            last_error = e
            continue
    if frame is None:
        raise ValueError(
            f"Could not parse {f.name} (tried auto-detecting the "
            f"delimiter, and utf-8/cp1252/latin-1 encodings). Open it in "
            f"a text editor and confirm it's a well-formed CSV. "
            f"Original error: {last_error}"
        )
    if expected_columns is None:
        expected_columns = set(frame.columns)
    elif set(frame.columns) != expected_columns:
        # Fail loudly rather than silently introduce NaN columns from a
        # schema mismatch between extraction runs (e.g. an older run
        # missing a field a newer version of extract_suspicious_logins.py
        # added). A silent concat here would be much harder to notice
        # than a clear error at load time.
        missing = expected_columns - set(frame.columns)
        extra = set(frame.columns) - expected_columns
        raise ValueError(
            f"{f.name} has a different column set than the other raw "
            f"files. Missing: {sorted(missing)}. Extra: {sorted(extra)}. "
            f"All raw files must come from the same version of the "
            f"extraction script."
        )
    frame["_source_file"] = f.name
    frame["_hmac_key_bytes"] = [hmac_key_bytes] * len(frame)
    frames.append(frame)

df = pd.concat(frames, ignore_index=True)

# Numeric columns are coerced explicitly rather than trusted from the CSV
# parse, for the same regional-format reason as the delimiter/encoding
# issues above: a real file produced latitude/longitude as TEXT, not
# numbers, because it used a comma as the DECIMAL separator (e.g. "48,8566"
# instead of "48.8566") -- common in Portuguese/European-formatted
# spreadsheet exports, and especially likely alongside a semicolon field
# delimiter (both are the same regional convention: comma is reserved for
# decimals, so semicolon takes over as the field separator). Left
# uncorrected, this doesn't fail at load time -- pandas happily keeps the
# column as text -- it only surfaces much later as a cryptic TypeError
# the moment arithmetic (haversine_km) is attempted on it. Any value that
# still can't be parsed as a number after the comma/point fix (genuinely
# malformed data, not just a regional format difference) becomes NaN
# rather than crashing the whole run -- the existing NaN-handling in the
# travel-distance calculation already treats that correctly (skips the
# distance calculation for that row rather than guessing).
for numeric_col in ("latitude", "longitude", "ip_version"):
    if numeric_col in df.columns:
        df[numeric_col] = pd.to_numeric(
            df[numeric_col].astype(str).str.replace(",", ".", regex=False),
            errors="coerce",
        )

# Country names are normalized to a single canonical spelling per country.
# Confirmed against the real, larger extraction: "Netherlands" (4 rows) and
# "The Netherlands" (32 rows) were being treated as TWO DIFFERENT
# countries -- almost certainly because different geo sources disagree on
# naming (extract_suspicious_logins.py prefers Google Workspace's own
# geoLocation.country, falling back to ip-api.com's `country` field only
# when that's missing -- the two providers don't always agree on country
# name formatting). This silently corrupted every feature derived from
# ip_country for anyone who appeared under both spellings: is_new_country,
# country_changed, geo_jump (and therefore risk_score) would have recorded
# a "country change" for someone who never actually left the Netherlands.
# This mapping is intentionally small and explicit (add to it if another
# variant is ever found) rather than a fuzzy-matching approach, which
# risks silently merging two DIFFERENT countries that happen to have
# similar names.
COUNTRY_NAME_CANONICAL = {
    "The Netherlands": "Netherlands",
}
if "ip_country" in df.columns:
    df["ip_country"] = df["ip_country"].replace(COUNTRY_NAME_CANONICAL)

if "actor_email_hash" not in df.columns:
    raise ValueError("actor_email_hash column is required")
if "ip_hash" not in df.columns:
    raise ValueError("ip_hash column is required")

# Two separate runs' date ranges may have overlapped (e.g. a cautious
# re-extraction covering a few of the same days twice) -- deduplicate on
# every column EXCEPT the per-file record_id and the tracking column just
# added, since the same real event extracted twice would be identical in
# everything else. Report how many were found so this is never silent.
content_columns = [c for c in df.columns
                  if c not in ("record_id", "_source_file", "_hmac_key_bytes")]
n_before = len(df)
df = df.drop_duplicates(subset=content_columns, keep="first").reset_index(drop=True)
n_duplicates = n_before - len(df)
if n_duplicates:
    print(f"Removed {n_duplicates} duplicate row(s) found across raw files "
         f"(overlapping extraction windows)")

# The original per-file record_id is no longer meaningful once multiple
# files are combined (each file restarts at 1) -- replace it with a fresh,
# globally unique sequential id over the combined, deduplicated data.
df = df.drop(columns=["record_id"], errors="ignore")
df.insert(0, "record_id", range(1, len(df) + 1))

print(f"Combined dataset: {len(df)} records from {len(raw_files_with_keys)} file(s)")

# ============================================================
# PSEUDONYMS (fix #1, #6)
# ============================================================

df["actor_pseudo_hmac"] = [
    pseudonymize(v, k) for v, k in zip(df["actor_email_hash"], df["_hmac_key_bytes"])
]
df["network_pseudo_hmac"] = [
    pseudonymize(v, k) for v, k in zip(df["ip_hash"], df["_hmac_key_bytes"])
]
df = df.drop(columns=["_hmac_key_bytes"])

user_id_map = make_short_id_map(df["actor_pseudo_hmac"], "U")
network_id_map = make_short_id_map(df["network_pseudo_hmac"], "N")

df["actor_pseudo_id"] = df["actor_pseudo_hmac"].map(user_id_map)
df["network_pseudo_id"] = df["network_pseudo_hmac"].map(network_id_map)

# ============================================================
# DATETIME
# ============================================================

df["event_time"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")

# Sort by the PSEUDONYM now, not the raw hash -- behaviorally identical
# (same grouping), but keeps the raw hash out of any intermediate state
# a careless future edit might accidentally write out.
df = df.sort_values(["actor_pseudo_id", "event_time"]).reset_index(drop=True)

# ============================================================
# TEMPORAL FEATURES
# ============================================================

df["event_hour"] = df["event_time"].dt.hour
df["day_of_week"] = df["event_time"].dt.dayofweek
df["month"] = df["event_time"].dt.month
df["quarter"] = df["event_time"].dt.quarter
df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
df["is_business_hours"] = df["event_hour"].between(8, 18).astype(int)
df["is_night_login"] = ((df["event_hour"] <= 6) | (df["event_hour"] >= 22)).astype(int)


def rolling_unique_count(group, column, days=30):
    """Count of distinct `column` values in the trailing `days`-day window
    up to and including each row's own event_time. Already past-only by
    construction (the window only ever looks backward from `current_time`),
    kept as-is from the original script -- this one was correct."""
    result = []
    for current_time in group["event_time"]:
        mask = ((group["event_time"] >= current_time - pd.Timedelta(days=days))
                & (group["event_time"] <= current_time))
        result.append(group.loc[mask, column].nunique())
    return pd.Series(result, index=group.index)


def apply_per_group(df_all, group_col, func, *func_args):
    """Robust replacement for
    `df.groupby(group_col, group_keys=False).apply(lambda g: func(g, *args))`
    for any `func` that returns a Series aligned to its group's index.

    Real, confirmed pandas quirk: that `.groupby().apply()` pattern can
    return a DataFrame instead of a Series in some cases -- reproduced
    with as little as ONE group (e.g. a single user, or a small raw file
    used for testing): it raises "Cannot set a DataFrame with multiple
    columns to the single column X" rather than assigning cleanly. This
    never showed up against the full multi-thousand-row real dataset (many
    groups, no ambiguity), but surfaced immediately once a validation test
    suite exercised small inputs -- exactly what such a suite is for. An
    explicit per-group loop with direct .loc assignment has no such
    ambiguity, regardless of how many groups exist.
    """
    result = pd.Series(index=df_all.index, dtype="float64")
    for _, group in df_all.groupby(group_col):
        result.loc[group.index] = func(group, *func_args)
    return result


def expanding_past_only(group, column, stat):
    """Per-row mean or std of `column` using ONLY events strictly BEFORE
    that row (never the row itself, never future rows) -- fixes the
    abnormal_login_hour leakage (issue #2). The first event for a user has
    no prior history, so its stat is NaN (handled by the caller: NaN mean
    can never be flagged abnormal, which is the only sane behavior for a
    user's very first observed login)."""
    shifted = group[column].shift(1)
    if stat == "mean":
        return shifted.expanding().mean()
    return shifted.expanding().std()


# ============================================================
# NEW IP / NEW COUNTRY / NEW REGION / NEW CITY -- true binary flags (fix #3)
# ============================================================
# `~s.duplicated()` marks the FIRST time a value is seen for that user as
# True (not yet a duplicate) and every later repeat as False -- a clean
# binary "have I never used this before" signal. new_ip already used this
# correctly; the same pattern now applies to country/region/city too.

df["new_ip"] = (
    df.groupby("actor_pseudo_id")["network_pseudo_id"]
      .transform(lambda s: ~s.duplicated())
      .astype(int)
)
df["is_new_country"] = (
    df.groupby("actor_pseudo_id")["ip_country"]
      .transform(lambda s: ~s.duplicated())
      .astype(int)
)
df["is_new_region"] = (
    df.groupby("actor_pseudo_id")["ip_region"]
      .transform(lambda s: ~s.duplicated())
      .astype(int)
)
df["is_new_city"] = (
    df.groupby("actor_pseudo_id")["ip_city"]
      .transform(lambda s: ~s.duplicated())
      .astype(int)
)

# ============================================================
# DISTINCT NETWORKS (rolling, unchanged logic from the original -- correct)
# ============================================================

df["distinct_ips_7d"] = apply_per_group(df, "actor_pseudo_id", rolling_unique_count, "network_pseudo_id", 7)
df["distinct_ips_30d"] = apply_per_group(df, "actor_pseudo_id", rolling_unique_count, "network_pseudo_id", 30)

# ============================================================
# CUMULATIVE DISTINCT COUNTS -- kept as their own features, no longer fed
# into risk_score (fix #3)
# ============================================================

for col, out_name in [("ip_country", "distinct_countries_cumulative"),
                      ("ip_region", "distinct_regions_cumulative"),
                      ("ip_city", "distinct_cities_cumulative")]:
    df[out_name] = (
        df.groupby("actor_pseudo_id")[col]
          .transform(lambda s: pd.Series(
              [len(set(s.iloc[:i + 1].dropna())) for i in range(len(s))],
              index=s.index))
    )

# ============================================================
# CHANGES
# ============================================================

df["country_changed"] = (
    df.groupby("actor_pseudo_id")["ip_country"]
      .shift().ne(df["ip_country"]).fillna(False).astype(int)
)
df["continent_changed"] = (
    df.groupby("actor_pseudo_id")["continent"]
      .shift().ne(df["continent"]).fillna(False).astype(int)
)

# ============================================================
# COUNTRIES / REGIONS / CITIES SEEN (rolling window, unchanged -- correct)
# ============================================================

df["countries_seen_30d"] = apply_per_group(df, "actor_pseudo_id", rolling_unique_count, "ip_country", 30)
df["regions_seen_30d"] = apply_per_group(df, "actor_pseudo_id", rolling_unique_count, "ip_region", 30)
df["cities_seen_30d"] = apply_per_group(df, "actor_pseudo_id", rolling_unique_count, "ip_city", 30)

# ============================================================
# NETWORK SHARING -- new feature (fix #6): how many distinct users have
# used this same network recently. Past-only by construction (same
# trailing-window pattern as rolling_unique_count, just grouped by network
# instead of by user).
# ============================================================

def rolling_unique_count_by(df_all, group_col, value_col, days):
    result = pd.Series(index=df_all.index, dtype="float64")
    for _, group in df_all.groupby(group_col):
        result.loc[group.index] = rolling_unique_count(group, value_col, days)
    return result


df = df.sort_values(["network_pseudo_id", "event_time"])
df["distinct_users_per_network_24h"] = rolling_unique_count_by(
    df, "network_pseudo_id", "actor_pseudo_id", days=1)
df = df.sort_values(["actor_pseudo_id", "event_time"]).reset_index(drop=True)

# ============================================================
# LOGIN HISTORY
# ============================================================

df["hours_since_last_login"] = (
    df.groupby("actor_pseudo_id")["event_time"]
      .diff().dt.total_seconds().div(3600).fillna(0).round(2)
)
df["days_since_first_login"] = (
    (df["event_time"] - df.groupby("actor_pseudo_id")["event_time"].transform("min"))
    .dt.days.round(2)
)

# ============================================================
# LOGIN COUNTERS (unchanged logic -- correct, already past-only via
# searchsorted on sorted per-user timestamps)
# ============================================================

df["logins_24h"] = 0
df["logins_7d"] = 0
df["logins_30d"] = 0

for user, group in df.groupby("actor_pseudo_id"):
    times = group["event_time"].dt.tz_convert(None).to_numpy(dtype="datetime64[ns]")
    idx_24h = np.searchsorted(times, times - np.timedelta64(24, "h"), side="left")
    idx_7d = np.searchsorted(times, times - np.timedelta64(7, "D"), side="left")
    idx_30d = np.searchsorted(times, times - np.timedelta64(30, "D"), side="left")
    df.loc[group.index, "logins_24h"] = np.arange(len(times)) + 1 - idx_24h
    df.loc[group.index, "logins_7d"] = np.arange(len(times)) + 1 - idx_7d
    df.loc[group.index, "logins_30d"] = np.arange(len(times)) + 1 - idx_30d

window_days = np.minimum(df["days_since_first_login"] + 1, 30)
df["avg_logins_per_day"] = (df["logins_30d"] / window_days).round(2)

# ============================================================
# ABNORMAL LOGIN HOUR -- past-only now (fix #2)
# ============================================================

hour_mean_past = apply_per_group(df, "actor_pseudo_id", expanding_past_only, "event_hour", "mean")
hour_std_past = apply_per_group(df, "actor_pseudo_id", expanding_past_only, "event_hour", "std").fillna(0)

# A user's first-ever login has no prior history (hour_mean_past is NaN)
# -- it cannot be judged abnormal relative to a baseline that does not yet
# exist, so it is explicitly NOT flagged, rather than silently comparing
# against NaN (which pandas would just evaluate as False anyway, but doing
# it explicitly documents the intent instead of relying on that quirk).
has_baseline = hour_mean_past.notna()
df["abnormal_login_hour"] = (
    has_baseline & (abs(df["event_hour"] - hour_mean_past) > 2 * hour_std_past)
).astype(int)

# ============================================================
# ABNORMAL WEEKDAY
# ============================================================

df["abnormal_weekday"] = (df["is_weekend"] == 1).astype(int)

# ============================================================
# IMPOSSIBLE TRAVEL -- lat/long used internally only, never in the output
# (fix #5)
# ============================================================

df["_prev_latitude"] = df.groupby("actor_pseudo_id")["latitude"].shift(1)
df["_prev_longitude"] = df.groupby("actor_pseudo_id")["longitude"].shift(1)


def calculate_distance(row):
    if (pd.isna(row["_prev_latitude"]) or pd.isna(row["_prev_longitude"])
            or pd.isna(row["latitude"]) or pd.isna(row["longitude"])):
        return np.nan
    return haversine_km(row["_prev_latitude"], row["_prev_longitude"],
                        row["latitude"], row["longitude"])


df["travel_distance_km"] = df.apply(calculate_distance, axis=1).fillna(0).round(2)
df["travel_speed_kmh"] = np.where(
    df["hours_since_last_login"] > 0,
    df["travel_distance_km"] / df["hours_since_last_login"],
    np.nan,
)
df["travel_speed_kmh"] = df["travel_speed_kmh"].fillna(0).round(2)
df["impossible_travel"] = (df["travel_speed_kmh"] > 900).astype(int)

df = df.drop(columns=["_prev_latitude", "_prev_longitude"])

# ============================================================
# MULTIPLE COUNTRIES
# ============================================================

df["multiple_country_logins_24h"] = (df["countries_seen_30d"] > 1).astype(int)

# ============================================================
# RISK SCORE (fix #9)
# ============================================================
# An earlier hand-weighted version (new_ip*20 + is_new_country*30 +
# country_changed*20 + continent_changed*30 + abnormal_login_hour*20) was
# tested empirically against the real label (is_suspicious) and scored
# AUC-ROC=0.375 on a chronological held-out split -- WORSE than random,
# not just uninformative. Root cause, confirmed with the real data: three
# of its five terms were not independent signals at all -- is_new_country
# implies country_changed in 100% of rows (715/715), and continent_changed
# implies country_changed in 100% of rows too (0 counter-examples) -- so
# the formula was really counting one "did location change" signal two or
# three times over, while new_ip individually correlates NEGATIVELY with
# the real label (-0.138), the opposite of the +20 it was assigned.
# Deliberately NOT kept as a column here (it would sit right next to a
# correctly-working risk_score under a very similar name, and its features
# -- new_ip, is_new_country, country_changed, continent_changed,
# abnormal_login_hour -- are all already independently in this dataset, so
# anyone wanting to reproduce that exact comparison for a paper can
# recompute it from those columns directly). The formula and its
# AUC-ROC=0.375 result are documented here and in the data dictionary /
# methodology notes instead.
#
# risk_score is a genuinely empirical scorecard: a logistic regression fit
# on a chronological 70/15/15 train/val/test split (val used to confirm
# the fit generalizes; only test numbers are reported), fit on data BEFORE
# the Angolan academic vacation period (Jun-Aug 2026 excluded from
# fitting/evaluation, see docs/RISK_SCORE_METHODOLOGY.md).
#
# Version history (full detail in docs/RISK_SCORE_METHODOLOGY.md):
#   v1 (~5.3k rows): AUC-ROC=0.768, PR-AUC=0.196 on held-out test.
#   v2 (~27k training rows, current): AUC-ROC=0.718, PR-AUC=0.159 on
#     held-out test. Notably, impossible_travel's weight collapsed from a
#     strong +122 (v1) to essentially 0 -- its correlation with the real
#     label vanished at this scale (-0.005, down from +0.064 in v1),
#     reported as an honest finding, not a bug.
# Converting coefficients to rounded integer points preserves nearly all
# of the continuous model's discrimination in both versions (rounding
# cost negligible).
#
# The weights below are FROZEN, not re-fit on every run: a published
# dataset's risk_score needs a stable, documented definition, not one that
# silently changes every time new raw files are added via the multi-file
# loading in this script (fix #8). To produce a v3, repeat the same
# procedure: chronological 70/15/15 split (excluding any similarly
# unreliable period, confirmed with the institution first),
# LogisticRegression(class_weight="balanced") on [new_ip, geo_jump,
# abnormal_login_hour, impossible_travel, distinct_users_per_network_24h,
# multiple_country_logins_24h], scale coefficients by ~40 and round -- and
# version the output filename (suspicious_logins_public_v3.csv) rather
# than overwriting v2, so anything built on v2 keeps working.
#
# geo_jump replaces the three collinear flags with one clean ordinal:
# 0 = no country/continent change since the previous login, 1 = country
# changed, 2 = continent also changed (a strictly bigger jump) -- fixes
# the triple-counting without discarding the underlying signal.

df["geo_jump"] = 0
df.loc[df["country_changed"] == 1, "geo_jump"] = 1
df.loc[df["continent_changed"] == 1, "geo_jump"] = 2

df["risk_score"] = (
    df["new_ip"] * -41
    + df["geo_jump"] * 39
    + df["abnormal_login_hour"] * 30
    + df["impossible_travel"] * 0
    + df["distinct_users_per_network_24h"] * 1.03
    + df["multiple_country_logins_24h"] * -28
).round(2)

# v3 weights (2026-08-12), refit on the combined two-institution dataset
# (~68.9k rows before the evaluation cutoff), chronological 70/15/15 split
# excluding July-August 2026 (see EVALUATION_CUTOFF_DATE in
# benchmark_ml.py and docs/RISK_SCORE_METHODOLOGY.md for why). AUC-ROC on
# held-out test: 0.624 (down from v2's 0.718 -- see the methodology doc
# for why this is a fairer, not worse, number: v2 was fit on a
# single-institution population with much less genuine diversity).
# impossible_travel's weight is now exactly 0 -- confirmed AGAIN,
# independently, that this feature carries no real signal at this scale
# (a third consecutive refit reaching the same conclusion, v1 through v3).
# Cutoffs from the v3 distribution: p50 and p75 coincided exactly (both
# 38.0, the distribution is heavily clustered there) so p50/p90 are used
# instead of the usual p50/p75, to get a real separation between levels.
df["risk_level"] = pd.cut(
    df["risk_score"], bins=[-1000, 38, 58, 1000], labels=["low", "medium", "high"]
)

# ============================================================
# LABEL
# ============================================================

df["label"] = (
    df["is_suspicious"].astype(str).str.lower()
    .map({"true": 1, "false": 0}).fillna(0).astype(int)
)

# ============================================================
# LOGIN CHALLENGE METHOD -- collapse consecutive/duplicate entries (fix #7)
# ============================================================


def dedupe_pipe_field(value):
    if pd.isna(value):
        return value
    parts = str(value).split("|")
    seen, out = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return "|".join(out)


df["login_challenge_method"] = df["login_challenge_method"].map(dedupe_pipe_field)

# ============================================================
# FINAL DATASETS -- two schemas (fix #1, #5, #6)
# ============================================================

public_columns = [
    "actor_pseudo_id",
    "event_hour", "day_of_week", "month", "quarter",
    "is_weekend", "is_business_hours", "is_night_login",
    "ip_country", "continent", "ip_version",
    "login_type", "login_challenge_method",
    "new_ip", "distinct_ips_7d", "distinct_ips_30d",
    "is_new_country", "is_new_region", "is_new_city",
    "distinct_countries_cumulative", "distinct_regions_cumulative",
    "distinct_cities_cumulative",
    "country_changed", "continent_changed",
    "countries_seen_30d", "regions_seen_30d", "cities_seen_30d",
    "logins_24h", "logins_7d", "logins_30d", "avg_logins_per_day",
    "hours_since_last_login", "days_since_first_login",
    "abnormal_login_hour", "abnormal_weekday",
    "impossible_travel", "travel_distance_km", "travel_speed_kmh",
    "multiple_country_logins_24h", "distinct_users_per_network_24h",
    "geo_jump",
    "risk_score", "risk_level",
    "label",
]

restricted_columns = public_columns + [
    "event_time",
    "network_pseudo_id", "ip_region", "ip_city", "latitude", "longitude",
]

public_dataset = df[public_columns].copy()
restricted_dataset = df[restricted_columns].copy()

# Rare-country generalization (public schema ONLY, restricted keeps full
# detail). Confirmed across every audit of this dataset so far, at every
# scale tried (5k, 30k, 48k, 73k rows): a small number of countries with
# very few events (threshold below) persist as identifiable outliers no
# matter how much the dataset otherwise grows -- adding more data dilutes
# concentration in the DOMINANT countries but does essentially nothing
# for these specific rare cases, since they are genuinely rare events
# (e.g. a single login from a country visited once), not an artifact of
# small sample size. Generalizing them to "Other" in the public release
# removes the identifying signal while keeping every row (no data lost)
# and keeping the real value available in the restricted schema for
# legitimate internal analysis.
#
# Threshold is data-driven (RARE_COUNTRY_MAX_EVENTS), not a hard-coded
# list of country names, so this stays correct as more data/institutions
# are added -- a country that used to be rare but has since accumulated
# enough events on its own no longer gets generalized, automatically.
RARE_COUNTRY_MAX_EVENTS = 5
country_counts = df["ip_country"].value_counts()
rare_countries = set(country_counts[country_counts <= RARE_COUNTRY_MAX_EVENTS].index)
if rare_countries:
    print(f"Generalizing {len(rare_countries)} rare country/countries in the "
         f"PUBLIC schema only (<= {RARE_COUNTRY_MAX_EVENTS} events each): "
         f"{sorted(rare_countries)}")
    public_dataset["ip_country"] = public_dataset["ip_country"].where(
        ~public_dataset["ip_country"].isin(rare_countries), "Other")

PUBLIC_FILE.parent.mkdir(parents=True, exist_ok=True)
def save_csv_with_clear_error(dataframe, path):
    """Wraps to_csv with a specific, actionable message for the most
    common real-world cause of a write failure here: the output file
    still being open in Excel (or another program) from a previous run,
    which Windows locks against writes from anywhere else. The raw
    PermissionError traceback doesn't say this anywhere -- it just looks
    like a generic, intimidating crash."""
    try:
        dataframe.to_csv(path, index=False)
    except PermissionError as e:
        raise PermissionError(
            f"Could not write {path.name} -- the file is likely still "
            f"open in Excel or another program (Windows locks it against "
            f"writes from here while that's the case). Close it wherever "
            f"it's open and run this script again. Original error: {e}"
        ) from e


save_csv_with_clear_error(public_dataset, PUBLIC_FILE)
save_csv_with_clear_error(restricted_dataset, RESTRICTED_FILE)

print(f"Public dataset saved to:     {PUBLIC_FILE}")
print(f"Records: {len(public_dataset)}")
print(f"Restricted dataset saved to: {RESTRICTED_FILE}")
print(f"Records: {len(restricted_dataset)}")
