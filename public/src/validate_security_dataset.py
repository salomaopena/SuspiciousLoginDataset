"""Independently reproduce the structural and longitudinal notebook checks."""

import argparse
import json
from collections import Counter, deque
from pathlib import Path

import numpy as np
import pandas as pd

from restricted.src.processed import sha256_file


PUBLIC = [
    "event_id", "actor_pseudo_id", "event_time_hour_utc", "ip_country",
    "ip_version", "login_type", "login_challenge_method", "prior_event_count",
    "history_available", "hours_since_last_login", "hours_since_first_observed_login",
    "logins_24h", "logins_7d", "logins_30d", "is_new_ip", "is_new_country",
    "country_changed", "countries_seen_24h", "countries_seen_30d", "provider_suspicious",
]
RESTRICTED = PUBLIC + [
    "event_time", "institution_pseudo_id", "source_file_id", "network_pseudo_id",
    "actor_email_hash", "ip_hash", "ip_region", "ip_city", "continent", "latitude",
    "longitude", "continent_changed", "travel_distance_km", "travel_speed_kmh",
    "is_impossible_travel",
]


def validate(folder):
    folder = Path(folder)
    manifest = json.loads((folder / "dataset_manifest_v2.json").read_text(encoding="utf-8"))
    tables = []
    for name, schema in [("suspicious_logins_public_v2.csv", PUBLIC),
                         ("suspicious_logins_restricted_v2.csv", RESTRICTED)]:
        frame = pd.read_csv(folder / name, keep_default_na=False, na_values=[""])
        assert list(frame.columns) == schema, f"Schema: {name}"
        assert len(frame) == manifest["rows"], f"Rows: {name}"
        assert frame["event_id"].is_unique, f"Duplicate event_id: {name}"
        tables.append(frame)
    for name, description in manifest["files"].items():
        assert sha256_file(folder / name) == description["sha256"], f"Hash: {name}"
    public, restricted = tables
    assert manifest["public_columns"] == PUBLIC and manifest["restricted_columns"] == RESTRICTED
    assert manifest["public_column_count"] == 20 and manifest["restricted_column_count"] == 35
    pd.testing.assert_frame_equal(public, restricted[PUBLIC])
    assert public["provider_suspicious"].notna().all()
    assert set(public["provider_suspicious"].unique()).issubset({0, 1})
    assert not public["ip_country"].eq("Other").any()
    if "extended_schema" in manifest:
        schema = manifest["extended_schema"]
        expanded_public = pd.read_csv(folder / "suspicious_logins_public_extended.csv",
                                      keep_default_na=False, na_values=[""], low_memory=False)
        expanded_restricted = pd.read_csv(folder / "suspicious_logins_restricted_extended.csv",
                                          keep_default_na=False, na_values=[""], low_memory=False)
        assert list(expanded_public.columns) == schema["public_columns"]
        assert list(expanded_restricted.columns) == schema["restricted_columns"]
        assert len(expanded_public) == len(expanded_restricted) == len(public)
        pd.testing.assert_frame_equal(expanded_public[PUBLIC], public)
        pd.testing.assert_frame_equal(expanded_restricted[RESTRICTED], restricted)
        pd.testing.assert_frame_equal(expanded_public, expanded_restricted[expanded_public.columns])
        assert expanded_public["event_id"].is_unique
        for name, count in schema["additional_public_non_null_counts"].items():
            assert int(expanded_public[name].notna().sum()) == count, name
        for forbidden in ("actor_email_hash", "source_record_id", "directory_metadata_json",
                          "inventory_associated_model_values_json", "inventory_associated_os_version_values_json"):
            assert forbidden not in expanded_public.columns
    for frame in tables:
        frame["event_time_hour_utc"] = pd.to_datetime(frame["event_time_hour_utc"], utc=True, format="mixed")
    restricted["event_time"] = pd.to_datetime(restricted["event_time"], utc=True, format="mixed")
    assert restricted["event_time"].is_monotonic_increasing
    ordered = restricted.sort_values(["event_time", "event_id"])
    assert ordered["event_id"].tolist() == restricted["event_id"].tolist()
    assert restricted["event_time"].dt.floor("h").equals(restricted["event_time_hour_utc"])

    # This uses independent per-actor queues/sets instead of the pipeline's
    # vectorized searchsorted implementation. Counts include the current event;
    # exact-time ties use event_id, as in article1_statistics.ipynb.
    expected = {name: {} for name in PUBLIC[7:19]}
    for _, group in restricted.groupby("actor_pseudo_id", sort=False):
        group = group.sort_values(["event_time", "event_id"])
        first, previous, previous_country = None, None, None
        ips, countries = set(), set()
        login_windows = {name: deque() for name in ("logins_24h", "logins_7d", "logins_30d")}
        deltas = {"logins_24h": pd.Timedelta(hours=24), "logins_7d": pd.Timedelta(days=7),
                  "logins_30d": pd.Timedelta(days=30)}
        country_windows = {name: (deque(), Counter()) for name in ("countries_seen_24h", "countries_seen_30d")}
        for prior, (idx, row) in enumerate(group.iterrows()):
            t, hour = row["event_time"], row["event_time_hour_utc"]
            ip, country = row["network_pseudo_id"], row["ip_country"]
            if first is None:
                first = t
            values = {"prior_event_count": prior, "history_available": int(prior > 0),
                      "hours_since_last_login": np.nan if previous is None else np.round((t - previous).total_seconds() / 3600, 4),
                      "hours_since_first_observed_login": np.round((t - first).total_seconds() / 86400, 4),
                      "is_new_ip": np.nan if pd.isna(ip) else int(ip not in ips),
                      "is_new_country": np.nan if pd.isna(country) else int(country not in countries),
                      "country_changed": int(previous is not None and pd.notna(country) and
                                             pd.notna(previous_country) and country != previous_country)}
            for name, queue in login_windows.items():
                while queue and queue[0] < t - deltas[name]:
                    queue.popleft()
                queue.append(t)
                values[name] = len(queue)
            for name, (queue, counter) in country_windows.items():
                delta = pd.Timedelta(hours=24) if name.endswith("24h") else pd.Timedelta(days=30)
                while queue and queue[0][0] < hour - delta:
                    _, old = queue.popleft()
                    if pd.notna(old):
                        counter[old] -= 1
                        if counter[old] == 0:
                            del counter[old]
                if pd.notna(country):
                    counter[country] += 1
                queue.append((hour, country))
                values[name] = len(counter)
            for name, value in values.items():
                expected[name][idx] = value
            if pd.notna(ip):
                ips.add(ip)
            if pd.notna(country):
                countries.add(country)
            previous, previous_country = t, country
    checks = {}
    for name, values in expected.items():
        actual = pd.to_numeric(public[name], errors="raise").to_numpy(dtype=float)
        predicted = pd.Series(values).reindex(public.index).to_numpy(dtype=float)
        checks[name] = int((~np.isclose(actual, predicted, equal_nan=True, atol=1e-9, rtol=0)).sum())
    assert all(value == 0 for value in checks.values()), checks
    report = {"status": "PASS", "rows": len(public), "public_columns": len(PUBLIC),
              "restricted_columns": len(RESTRICTED), "semantic_mismatches": checks,
              "country_windows_identical": public["countries_seen_24h"].equals(public["countries_seen_30d"])}
    # Identical country windows can legitimately occur in small/one-country
    # extractions; it is a diagnostic, not evidence that values are incorrect.
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    report = validate(args.folder)
    (args.folder / "semantic_validation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
