"""
SuspiciousLogin Dataset v2 processing pipeline.

Core principles
---------------
- compact public schema (20 columns);
- public/restricted separation;
- explicit history_available/prior_event_count;
- exact-time login windows and publicly reproducible country-diversity windows;
- public time generalized to hourly UTC;
- provider_suspicious is strictly binary (0/1);
- public ip_country preserves the normalized country value (no release-time Other grouping);
- deterministic HMAC pseudonyms and event_id;
- restricted-only lineage and fine-grained geolocation.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
RAW_FILE_PATTERN = "suspicious_login_logs*.csv"

PUBLIC_FILE = PROCESSED_DIR / "suspicious_logins_public_v2.csv"
RESTRICTED_FILE = PROCESSED_DIR / "suspicious_logins_restricted_v2.csv"
MANIFEST_FILE = PROCESSED_DIR / "dataset_manifest_v2.json"

DATASET_VERSION = "2.0"
SCHEMA_VERSION = "2.0"
CANONICAL_ORDERING = "event_time_utc_asc_then_event_id_asc"

EXPECTED_PUBLIC_COLUMNS = 20
EXPECTED_RESTRICTED_COLUMNS = 35
IMPOSSIBLE_TRAVEL_THRESHOLD_KMH = 900.0

load_dotenv(BASE_DIR / ".env")


def env_var_name_for_institution(folder_name: str) -> str:
    safe = "".join(c.upper() if c.isalnum() else "_" for c in folder_name)
    return f"HMAC_SECRET_KEY_{safe}"


def hmac_hex(value: str, key_bytes: bytes, length: int = 16) -> str:
    return hmac.new(
        key_bytes,
        str(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:length]


def pseudonymize(value, key_bytes: bytes, prefix: str, length: int = 16):
    if pd.isna(value) or value in (None, ""):
        return pd.NA
    return prefix + hmac_hex(str(value), key_bytes, length)


def _canonical_event_value(value) -> str:
    """Canonical string representation used only to build event_id."""
    if value is None or value is pd.NA:
        return "<NA>"
    try:
        if pd.isna(value):
            return "<NA>"
    except (TypeError, ValueError):
        pass

    if isinstance(value, (float, np.floating)):
        # Stable representation without losing distinctions relevant to the
        # already-normalized raw row.
        return format(float(value), ".17g")
    return str(value).strip()


def build_event_ids(df: pd.DataFrame, event_columns) -> list[str]:
    """Bulk HMAC event IDs without slow DataFrame.apply row objects."""
    cols = sorted(event_columns)
    values = df[cols].to_numpy(dtype=object)
    keys = df["_hmac_key_bytes"].to_numpy(dtype=object)
    out = []
    for row_values, key in zip(values, keys):
        payload = "\x1f".join(
            f"{col}={_canonical_event_value(value)}"
            for col, value in zip(cols, row_values)
        )
        out.append("E" + hmac_hex(payload, key, 32))
    return out


def institution_pseudo_id(folder_name: str, key_bytes: bytes) -> str:
    return "I" + hmac_hex(folder_name, key_bytes, 10)


def source_file_id(filename: str, key_bytes: bytes) -> str:
    return "F" + hmac_hex(filename, key_bytes, 12)


def discover_raw_files_with_keys():
    if not RAW_DIR.exists():
        raise FileNotFoundError(f"Raw directory not found: {RAW_DIR}")

    subdirs = sorted(p for p in RAW_DIR.iterdir() if p.is_dir())

    if subdirs:
        pairs = []
        for subdir in subdirs:
            env_name = env_var_name_for_institution(subdir.name)
            key = os.environ.get(env_name)
            if not key:
                raise RuntimeError(
                    f"{env_name} is not set for {subdir.name}. "
                    "Each institution must have its own HMAC key."
                )
            key_bytes = key.encode("utf-8")
            files = sorted(subdir.glob(RAW_FILE_PATTERN))
            if not files:
                print(f"WARNING: no raw CSVs found under {subdir}")
            for path in files:
                pairs.append((path, key_bytes, subdir.name))
        return pairs

    key = os.environ.get("HMAC_SECRET_KEY")
    if not key:
        raise RuntimeError(
            "HMAC_SECRET_KEY is not set. For multiple institutions, use "
            "subdirectories and HMAC_SECRET_KEY_<INSTITUTION>."
        )
    key_bytes = key.encode("utf-8")
    return [(p, key_bytes, "single_institution")
            for p in sorted(RAW_DIR.glob(RAW_FILE_PATTERN))]


def read_raw_csv(path: Path) -> pd.DataFrame:
    """Fast, defensive CSV loader with per-file delimiter/encoding detection."""
    last_error = None
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as fh:
                sample = fh.read(8192)
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
            except csv.Error:
                first_line = sample.splitlines()[0] if sample else ""
                delimiter = ";" if first_line.count(";") > first_line.count(",") else ","

            # ISO territory code NA is Namibia, not a missing value.
            frame = pd.read_csv(path, sep=delimiter, encoding=encoding, low_memory=False,
                                keep_default_na=False, na_values=[""],
                                dtype={"record_id": "string", "source_event_key": "string",
                                       "actor_email_hash": "string", "ip_hash": "string"})
            if encoding != "utf-8":
                print(f"NOTE: {path.name} decoded as {encoding}")
            return frame
        except Exception as exc:
            last_error = exc
    raise ValueError(f"Could not parse {path}: {last_error}")


def normalize_numeric_column(series: pd.Series) -> pd.Series:
    return pd.to_numeric(
        series.astype(str).str.replace(",", ".", regex=False),
        errors="coerce",
    )


def valid_latitude(value) -> bool:
    return pd.notna(value) and -90 <= float(value) <= 90


def valid_longitude(value) -> bool:
    return pd.notna(value) and -180 <= float(value) <= 180


def sanitize_coordinates(df: pd.DataFrame) -> pd.DataFrame:
    if "latitude" in df.columns:
        df["latitude"] = normalize_numeric_column(df["latitude"])
    if "longitude" in df.columns:
        df["longitude"] = normalize_numeric_column(df["longitude"])

    if {"latitude", "longitude"}.issubset(df.columns):
        invalid = (
            df["latitude"].notna() & ~df["latitude"].between(-90, 90)
        ) | (
            df["longitude"].notna() & ~df["longitude"].between(-180, 180)
        )
        if invalid.any():
            print(
                f"WARNING: {int(invalid.sum())} row(s) contain out-of-range "
                "coordinates; latitude/longitude set to NA."
            )
            df.loc[invalid, ["latitude", "longitude"]] = np.nan
    return df


COUNTRY_NAME_CANONICAL = {
    "The Netherlands": "Netherlands",
}


def normalize_countries(df: pd.DataFrame) -> pd.DataFrame:
    if "ip_country" in df.columns:
        df["ip_country"] = df["ip_country"].replace(COUNTRY_NAME_CANONICAL)
    return df


def rolling_distinct_public_country_window(df, window):
    """
    Count distinct countries for each actor in [t_hour-window, t_hour],
    including the current event. The calculation intentionally uses only
    fields available in the public schema: actor_pseudo_id,
    prior_event_count, event_time_hour_utc and ip_country.

    Sorting by prior_event_count preserves the published per-actor event order
    when multiple events fall in the same public hour. This makes the released
    value exactly recomputable from the public CSV.
    """
    required = [
        "actor_pseudo_id", "prior_event_count",
        "event_time_hour_utc", "ip_country",
    ]
    work = df[required].sort_values(
        ["actor_pseudo_id", "prior_event_count"]
    )

    indices = work.index.to_numpy()
    groups = work["actor_pseudo_id"].astype("object").to_numpy()
    # Normalize explicitly to datetime64[ns] before integer conversion.
    # Pandas may internally store timezone-aware datetimes at microsecond
    # resolution; mixing microsecond timestamp integers with nanosecond
    # Timedelta integers silently inflates the effective window by 1000x.
    times = (
        work["event_time_hour_utc"]
        .dt.tz_convert(None)
        .to_numpy(dtype="datetime64[ns]")
        .astype("int64")
    )
    values = work["ip_country"].astype("object").to_numpy()
    out = np.zeros(len(work), dtype=np.int64)
    window_ns = int(
        window.to_timedelta64()
        .astype("timedelta64[ns]")
        .astype("int64")
    )

    start = 0
    n = len(work)
    while start < n:
        end = start + 1
        while end < n and groups[end] == groups[start]:
            end += 1

        # Public hourly timestamps must not move backwards in published
        # per-actor order. Exact event_time was already used to construct
        # prior_event_count, so equality within an hour is expected.
        actor_times = times[start:end]
        if len(actor_times) > 1 and np.any(actor_times[1:] < actor_times[:-1]):
            raise RuntimeError(
                f"Non-monotonic public hourly time for actor {groups[start]}"
            )

        counts = Counter()
        left = start
        for right in range(start, end):
            cutoff = times[right] - window_ns
            while left <= right and times[left] < cutoff:
                old = values[left]
                if not pd.isna(old):
                    key = str(old)
                    counts[key] -= 1
                    if counts[key] <= 0:
                        del counts[key]
                left += 1

            value = values[right]
            if not pd.isna(value):
                counts[str(value)] += 1
            out[right] = len(counts)

        start = end

    result = pd.Series(index=indices, data=pd.array(out, dtype="Int64"))
    return result.reindex(df.index)

def is_first_occurrence_for_user(df, value_col):
    valid = df[value_col].notna()
    duplicated = df.duplicated(subset=["actor_pseudo_id", value_col], keep="first")
    out = pd.Series(pd.NA, index=df.index, dtype="Int64")
    out.loc[valid] = (~duplicated.loc[valid]).astype("int64")
    return out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def haversine_km(lat1, lon1, lat2, lon2):
    if not all(map(pd.notna, [lat1, lon1, lat2, lon2])):
        return np.nan
    if not (
        valid_latitude(lat1) and valid_latitude(lat2)
        and valid_longitude(lon1) and valid_longitude(lon2)
    ):
        return np.nan

    r = 6371.0088
    p1, p2 = math.radians(float(lat1)), math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlambda = math.radians(float(lon2) - float(lon1))
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    )
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def normalize_provider_signal(series):
    """Normalize the provider signal and enforce the binary release contract."""
    normalized = series.astype("string").str.strip().str.lower()
    mapped = normalized.map({
        "true": 1, "1": 1, "yes": 1,
        "false": 0, "0": 0, "no": 0,
    })

    invalid = mapped.isna()
    if invalid.any():
        examples = sorted(normalized.loc[invalid].dropna().unique().tolist())[:10]
        raise RuntimeError(
            f"provider_suspicious must be binary for every retained event; "
            f"found {int(invalid.sum())} unmapped/missing value(s). "
            f"Examples={examples}"
        )
    return mapped.astype("Int64")


def dedupe_pipe_field(value):
    if pd.isna(value):
        return pd.NA
    parts = [p.strip() for p in str(value).split("|") if p.strip()]
    seen, out = set(), []
    for part in parts:
        if part not in seen:
            seen.add(part)
            out.append(part)
    return "|".join(out) if out else pd.NA


def process(raw_files=None, output_dir=None, strict_country_window_guard=True):
    """Build the existing v2 schemas; importing this module performs no processing.

    raw_files accepts (csv_path, hmac_key_bytes, institution_name) tuples.
    An explicit output_dir keeps new extractions separate from the legacy corpus.
    The returned working frame preserves input lineage for restricted enrichment.
    """
    PROCESSED_DIR = Path(output_dir) if output_dir is not None else BASE_DIR / "data" / "processed"
    PUBLIC_FILE = PROCESSED_DIR / "suspicious_logins_public_v2.csv"
    RESTRICTED_FILE = PROCESSED_DIR / "suspicious_logins_restricted_v2.csv"
    MANIFEST_FILE = PROCESSED_DIR / "dataset_manifest_v2.json"

    if raw_files is None:
        raw_files = discover_raw_files_with_keys()
    if not raw_files:
        raise FileNotFoundError(f"No raw files found under {RAW_DIR}")

    frames = []
    expected_columns = None
    removed_empty_rows = 0
    print(f"Found {len(raw_files)} raw file(s).")

    for path, key_bytes, institution_name in raw_files:
        frame = read_raw_csv(path)

        # Remove physically/logically empty CSV rows immediately.
        empty_rows = frame.isna().all(axis=1)
        if empty_rows.any():
            n_empty = int(empty_rows.sum())
            removed_empty_rows += n_empty
            print(f"REMOVED: {n_empty} completely empty row(s) from {path.name}")
            frame = frame.loc[~empty_rows].copy()

        if expected_columns is None:
            expected_columns = set(frame.columns)
        elif set(frame.columns) != expected_columns:
            missing = sorted(expected_columns - set(frame.columns))
            extra = sorted(set(frame.columns) - expected_columns)
            raise ValueError(
                f"{path.name} has a different raw schema. "
                f"Missing={missing}; Extra={extra}"
            )

        frame["_source_file"] = path.name
        frame["_institution_name_internal"] = institution_name
        frame["_hmac_key_bytes"] = [key_bytes] * len(frame)
        frames.append(frame)

    df = pd.concat(frames, ignore_index=True)
    df["_stable_row_order"] = np.arange(len(df), dtype=np.int64)

    required = {
        "event_time", "actor_email_hash", "ip_hash", "is_suspicious",
        "login_type", "login_challenge_method", "ip_country", "ip_version",
    }
    missing_required = required - set(df.columns)
    if missing_required:
        raise ValueError(f"Missing required raw column(s): {sorted(missing_required)}")

    # Remove rows that cannot participate in the longitudinal dataset at all.
    # event_time identifies when the authentication occurred; actor_email_hash is
    # required to build a stable user pseudonym/history. Missing either makes the
    # row unusable for the public analytical dataset.
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True, format="mixed", errors="coerce")
    invalid_core = df["event_time"].isna() | df["actor_email_hash"].isna()
    removed_invalid_core_rows = int(invalid_core.sum())
    if invalid_core.any():
        n_invalid_core = removed_invalid_core_rows
        print(
            f"REMOVED: {n_invalid_core} row(s) missing/invalid event_time or "
            "actor_email_hash (cannot build longitudinal history)."
        )
        df = df.loc[~invalid_core].copy().reset_index(drop=True)

    df = sanitize_coordinates(df)
    df = normalize_countries(df)

    if "ip_version" in df.columns:
        df["ip_version"] = normalize_numeric_column(df["ip_version"]).astype("Int64")
        invalid_ip_version = ~df["ip_version"].isin([4, 6]) & df["ip_version"].notna()
        if invalid_ip_version.any():
            print(
                f"WARNING: {int(invalid_ip_version.sum())} row(s) have invalid "
                "ip_version; set to NA."
            )
            df.loc[invalid_ip_version, "ip_version"] = pd.NA

    content_columns = [
        c for c in df.columns
        if c not in {
            "record_id", "_source_file", "_institution_name_internal",
            "_hmac_key_bytes", "_stable_row_order",
        }
    ]

    before = len(df)
    df = df.drop_duplicates(subset=content_columns, keep="first").reset_index(drop=True)
    removed_duplicate_rows = before - len(df)
    print(f"Removed duplicate rows: {removed_duplicate_rows}")
    df["_stable_row_order"] = np.arange(len(df), dtype=np.int64)

    df["actor_pseudo_id"] = [
        pseudonymize(v, k, "U", 16)
        for v, k in zip(df["actor_email_hash"], df["_hmac_key_bytes"])
    ]

    df["network_pseudo_id"] = [
        pseudonymize(v, k, "N", 16)
        for v, k in zip(df["ip_hash"], df["_hmac_key_bytes"])
    ]

    df["institution_pseudo_id"] = [
        institution_pseudo_id(n, k)
        for n, k in zip(df["_institution_name_internal"], df["_hmac_key_bytes"])
    ]

    df["source_file_id"] = [
        source_file_id(n, k)
        for n, k in zip(df["_source_file"], df["_hmac_key_bytes"])
    ]

    event_id_columns = tuple(sorted(content_columns))
    df["event_id"] = build_event_ids(df, event_id_columns)

    if df["event_id"].duplicated().any():
        dup_mask = df["event_id"].duplicated(keep=False)
        duplicate_ids = df.loc[dup_mask, "event_id"].nunique()
        duplicate_rows = int(dup_mask.sum())
        raise RuntimeError(
            f"Duplicate/colliding event_id detected after full-content hashing: "
            f"{duplicate_ids} duplicated id(s) across {duplicate_rows} row(s). "
            "This should be cryptographically negligible after content "
            "deduplication; inspect the affected rows before publication."
        )

    df["event_time"] = pd.to_datetime(df["event_time"], utc=True, format="mixed", errors="coerce")
    if df["event_time"].isna().any():
        print(f"WARNING: {int(df['event_time'].isna().sum())} invalid/missing event_time row(s).")

    df["event_time_hour_utc"] = df["event_time"].dt.floor("h")

    df = df.sort_values(
        ["actor_pseudo_id", "event_time", "event_id"],
        na_position="last",
    ).reset_index(drop=True)

    # Explicit history.
    df["prior_event_count"] = df.groupby("actor_pseudo_id").cumcount().astype("Int64")
    df["history_available"] = (df["prior_event_count"] > 0).astype("Int64")

    df["hours_since_last_login"] = (
        df.groupby("actor_pseudo_id")["event_time"]
          .diff().dt.total_seconds().div(3600).round(4)
    )

    first_time = df.groupby("actor_pseudo_id")["event_time"].transform("min")
    df["days_since_first_observed_login"] = (
        (df["event_time"] - first_time).dt.total_seconds() / 86400.0
    ).round(4)

    # Login counts.
    for col in ("logins_24h", "logins_7d", "logins_30d"):
        df[col] = pd.Series(np.nan, index=df.index, dtype="float64").astype("Int64")

    window_map = {
        "logins_24h": np.timedelta64(24, "h"),
        "logins_7d": np.timedelta64(7, "D"),
        "logins_30d": np.timedelta64(30, "D"),
    }

    for _, group in df.groupby("actor_pseudo_id"):
        valid_group = group.loc[group["event_time"].notna()]
        if valid_group.empty:
            continue
        times = valid_group["event_time"].dt.tz_convert(None).to_numpy(dtype="datetime64[ns]")
        for col, delta in window_map.items():
            left = np.searchsorted(times, times - delta, side="left")
            counts = np.arange(len(times)) + 1 - left
            df.loc[valid_group.index, col] = pd.array(counts, dtype="Int64")

    # IP novelty. The source-IP pseudonym remains restricted, while is_new_ip is
    # released as a derived event-level novelty indicator.
    df["is_new_ip"] = is_first_occurrence_for_user(df, "network_pseudo_id")

    # Country history.
    df["is_new_country"] = is_first_occurrence_for_user(df, "ip_country")
    previous_country = df.groupby("actor_pseudo_id")["ip_country"].shift(1)
    df["country_changed"] = (
        (df["history_available"] == 1)
        & previous_country.notna()
        & df["ip_country"].notna()
        & previous_country.ne(df["ip_country"])
    ).astype("Int64")
    df.loc[df["history_available"] == 0, "country_changed"] = 0

    # Geographic diversity windows are deliberately based on the public hourly
    # timestamp, so they can be recomputed exactly from the public release.
    df["countries_seen_24h"] = rolling_distinct_public_country_window(
        df, pd.Timedelta(hours=24)
    )
    df["countries_seen_30d"] = rolling_distinct_public_country_window(
        df, pd.Timedelta(days=30)
    )

    # Continent change remains restricted/audit-only.
    if "continent" in df.columns:
        previous_continent = df.groupby("actor_pseudo_id")["continent"].shift(1)
        df["continent_changed"] = (
            (df["history_available"] == 1)
            & previous_continent.notna()
            & df["continent"].notna()
            & previous_continent.ne(df["continent"])
        ).astype("Int64")
        df.loc[df["history_available"] == 0, "continent_changed"] = 0
    else:
        df["continent_changed"] = pd.Series(np.nan, index=df.index, dtype="float64").astype("Int64")

    # Travel-derived fields are restricted only. Computed vectorially for scale.
    df["travel_distance_km"] = np.nan
    df["travel_speed_kmh"] = np.nan
    df["is_impossible_travel"] = pd.Series(pd.NA, index=df.index, dtype="Int64")

    if {"latitude", "longitude"}.issubset(df.columns):
        prev_lat = df.groupby("actor_pseudo_id")["latitude"].shift(1)
        prev_lon = df.groupby("actor_pseudo_id")["longitude"].shift(1)

        valid = (
            (df["history_available"] == 1)
            & prev_lat.notna() & prev_lon.notna()
            & df["latitude"].notna() & df["longitude"].notna()
        )

        if valid.any():
            lat1 = np.radians(prev_lat.loc[valid].astype(float).to_numpy())
            lon1 = np.radians(prev_lon.loc[valid].astype(float).to_numpy())
            lat2 = np.radians(df.loc[valid, "latitude"].astype(float).to_numpy())
            lon2 = np.radians(df.loc[valid, "longitude"].astype(float).to_numpy())
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = np.sin(dlat / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
            distances = 2 * 6371.0088 * np.arcsin(np.minimum(1.0, np.sqrt(a)))
            df.loc[valid, "travel_distance_km"] = distances

            hours = df.loc[valid, "hours_since_last_login"].astype(float)
            speed_valid = hours > 0
            speed_index = hours.index[speed_valid]
            df.loc[speed_index, "travel_speed_kmh"] = (
                df.loc[speed_index, "travel_distance_km"] / hours.loc[speed_index]
            )
            df.loc[speed_index, "is_impossible_travel"] = (
                df.loc[speed_index, "travel_speed_kmh"] > IMPOSSIBLE_TRAVEL_THRESHOLD_KMH
            ).astype(int).to_numpy()

        df["travel_distance_km"] = df["travel_distance_km"].round(2)
        df["travel_speed_kmh"] = df["travel_speed_kmh"].round(2)

    # Provider signal: strictly binary for every retained event.
    df["provider_suspicious"] = normalize_provider_signal(df["is_suspicious"])
    df["login_challenge_method"] = df["login_challenge_method"].map(dedupe_pipe_field)

    # Canonical release ordering. History features were computed in per-user
    # chronological order above; from this point onward every release is written
    # globally from the oldest event to the newest, with event_id as deterministic
    # tie-breaker. Never hard-code a starting month/date.
    df = df.sort_values(["event_time", "event_id"], ascending=[True, True]).reset_index(drop=True)

    # Public country policy: preserve the normalized country value. Rare-country
    # grouping (for example, "Other") is an analysis/presentation choice and is
    # not applied to the released row-level dataset.

    # Compact public schema.
    public_dataset = pd.DataFrame({
        "event_id": df["event_id"],
        "actor_pseudo_id": df["actor_pseudo_id"],
        "event_time_hour_utc": df["event_time_hour_utc"],
        "ip_country": df["ip_country"],
        "ip_version": df["ip_version"],
        "login_type": df["login_type"],
        "login_challenge_method": df["login_challenge_method"],
        "prior_event_count": df["prior_event_count"],
        "history_available": df["history_available"],
        "hours_since_last_login": df["hours_since_last_login"],
        "days_since_first_observed_login": df["days_since_first_observed_login"],
        "logins_24h": df["logins_24h"],
        "logins_7d": df["logins_7d"],
        "logins_30d": df["logins_30d"],
        "is_new_ip": df["is_new_ip"],
        "is_new_country": df["is_new_country"],
        "country_changed": df["country_changed"],
        "countries_seen_24h": df["countries_seen_24h"],
        "countries_seen_30d": df["countries_seen_30d"],
        "provider_suspicious": df["provider_suspicious"],
    })

    # Restricted schema: public fields + exact/lineage/fine-grained fields.
    restricted_dataset = pd.DataFrame({
        "event_id": df["event_id"],
        "actor_pseudo_id": df["actor_pseudo_id"],
        "event_time_hour_utc": df["event_time_hour_utc"],
        "ip_country": df["ip_country"],
        "ip_version": df["ip_version"],
        "login_type": df["login_type"],
        "login_challenge_method": df["login_challenge_method"],
        "prior_event_count": df["prior_event_count"],
        "history_available": df["history_available"],
        "hours_since_last_login": df["hours_since_last_login"],
        "days_since_first_observed_login": df["days_since_first_observed_login"],
        "logins_24h": df["logins_24h"],
        "logins_7d": df["logins_7d"],
        "logins_30d": df["logins_30d"],
        "is_new_ip": df["is_new_ip"],
        "is_new_country": df["is_new_country"],
        "country_changed": df["country_changed"],
        "countries_seen_24h": df["countries_seen_24h"],
        "countries_seen_30d": df["countries_seen_30d"],
        "provider_suspicious": df["provider_suspicious"],
        "event_time": df["event_time"],
        "institution_pseudo_id": df["institution_pseudo_id"],
        "source_file_id": df["source_file_id"],
        "network_pseudo_id": df["network_pseudo_id"],
        "actor_email_hash": df["actor_email_hash"],
        "ip_hash": df["ip_hash"],
        "ip_region": df["ip_region"] if "ip_region" in df.columns else pd.NA,
        "ip_city": df["ip_city"] if "ip_city" in df.columns else pd.NA,
        "continent": df["continent"] if "continent" in df.columns else pd.NA,
        "latitude": df["latitude"] if "latitude" in df.columns else pd.NA,
        "longitude": df["longitude"] if "longitude" in df.columns else pd.NA,
        "continent_changed": df["continent_changed"],
        "travel_distance_km": df["travel_distance_km"],
        "travel_speed_kmh": df["travel_speed_kmh"],
        "is_impossible_travel": df["is_impossible_travel"],
    })

    # Invariants.
    assert public_dataset["event_id"].is_unique
    assert restricted_dataset["event_id"].is_unique
    assert len(public_dataset) == len(restricted_dataset)
    assert len(public_dataset.columns) == EXPECTED_PUBLIC_COLUMNS
    assert len(restricted_dataset.columns) == EXPECTED_RESTRICTED_COLUMNS
    assert not public_dataset["provider_suspicious"].isna().any()
    assert set(public_dataset["provider_suspicious"].unique()).issubset({0, 1})
    assert public_dataset["ip_country"].equals(restricted_dataset["ip_country"])
    assert public_dataset["countries_seen_24h"].equals(restricted_dataset["countries_seen_24h"])
    assert public_dataset["countries_seen_30d"].equals(restricted_dataset["countries_seen_30d"])

    # Semantic release guard. In this multi-month dataset, complete row-by-row
    # equality between the 24h and 30d diversity features is a strong indication
    # that the temporal window collapsed into a cumulative count.
    if strict_country_window_guard and len(public_dataset) > 1 and public_dataset["event_time_hour_utc"].nunique() > 24:
        if public_dataset["countries_seen_24h"].equals(public_dataset["countries_seen_30d"]):
            raise RuntimeError(
                "countries_seen_24h and countries_seen_30d are identical for every "
                "row. Inspect timestamp units/window implementation before release."
            )

    first_mask = public_dataset["history_available"] == 0
    assert (public_dataset.loc[first_mask, "prior_event_count"] == 0).all()
    assert (public_dataset.loc[first_mask, "country_changed"] == 0).all()

    for forbidden in [
        "event_time", "network_pseudo_id", "actor_email_hash", "ip_hash",
        "institution_pseudo_id", "source_file_id", "ip_region", "ip_city",
        "latitude", "longitude", "travel_distance_km", "travel_speed_kmh",
        "is_impossible_travel", "risk_score", "risk_level", "label",
    ]:
        assert forbidden not in public_dataset.columns

    for forbidden in [
        "risk_score", "risk_level", "label",
        "distinct_ips_7d", "distinct_ips_30d",
        "distinct_users_per_network_24h", "geo_source",
    ]:
        assert forbidden not in restricted_dataset.columns

    # Public and restricted rows must be perfectly aligned and chronologically ordered.
    assert public_dataset["event_id"].tolist() == restricted_dataset["event_id"].tolist()
    assert restricted_dataset["event_time"].is_monotonic_increasing

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    public_dataset.to_csv(PUBLIC_FILE, index=False)
    restricted_dataset.to_csv(RESTRICTED_FILE, index=False)

    # Release manifest: machine-readable provenance for every generated release.
    provider_known = public_dataset["provider_suspicious"].notna()
    provider_positive = int((public_dataset["provider_suspicious"] == 1).sum())
    user_event_counts = public_dataset["actor_pseudo_id"].value_counts()
    manifest = {
        "dataset_name": "SuspiciousLogin",
        "dataset_version": DATASET_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "ordering": CANONICAL_ORDERING,
        "history_tie_breaker": "event_id_asc_for_equal_actor_and_event_time",
        "timezone": "UTC",
        "time_min": restricted_dataset["event_time"].min().isoformat(),
        "time_max": restricted_dataset["event_time"].max().isoformat(),
        "rows": int(len(public_dataset)),
        "unique_users": int(public_dataset["actor_pseudo_id"].nunique()),
        "singleton_users": int((user_event_counts == 1).sum()),
        "provider_suspicious_domain": [0, 1],
        "provider_suspicious_known": int(provider_known.sum()),
        "provider_suspicious_positive": provider_positive,
        "provider_suspicious_prevalence_known": (
            provider_positive / int(provider_known.sum()) if int(provider_known.sum()) else None
        ),
        "raw_file_count": int(len(raw_files)),
        "removed_empty_rows": int(removed_empty_rows),
        "removed_invalid_core_rows": int(removed_invalid_core_rows),
        "removed_duplicate_rows": int(removed_duplicate_rows),
        "institution_count_restricted": int(restricted_dataset["institution_pseudo_id"].nunique()),
        "public_columns": list(public_dataset.columns),
        "restricted_columns": list(restricted_dataset.columns),
        "public_column_count": int(len(public_dataset.columns)),
        "restricted_column_count": int(len(restricted_dataset.columns)),
        "public_country_policy": "normalized country preserved; no release-time rare-country grouping",
        "country_diversity_window_basis": "event_time_hour_utc + actor_pseudo_id + prior_event_count + ip_country",
        "removed_features_v2_consolidation": [
            "distinct_ips_7d",
            "distinct_ips_30d",
            "distinct_users_per_network_24h",
            "geo_source",
        ],
        "impossible_travel_threshold_kmh_restricted": IMPOSSIBLE_TRAVEL_THRESHOLD_KMH,
        "files": {
            PUBLIC_FILE.name: {
                "sha256": sha256_file(PUBLIC_FILE),
                "rows": int(len(public_dataset)),
                "columns": int(len(public_dataset.columns)),
            },
            RESTRICTED_FILE.name: {
                "sha256": sha256_file(RESTRICTED_FILE),
                "rows": int(len(restricted_dataset)),
                "columns": int(len(restricted_dataset.columns)),
            },
        },
    }

    with MANIFEST_FILE.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)

    print("SuspiciousLogin v2 processing complete.")
    print(f"Canonical ordering: {CANONICAL_ORDERING}")
    print(f"Public: {PUBLIC_FILE} -> {len(public_dataset):,} rows, {len(public_dataset.columns)} columns")
    print(f"Restricted: {RESTRICTED_FILE} -> {len(restricted_dataset):,} rows, {len(restricted_dataset.columns)} columns")
    print(f"Manifest: {MANIFEST_FILE}")
    print("provider_suspicious domain: binary {0, 1}")

    return public_dataset, restricted_dataset, manifest, df


if __name__ == "__main__":
    process()
