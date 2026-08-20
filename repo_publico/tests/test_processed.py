"""
Validation tests for data/processed.py.

These run the script as a REAL subprocess against small, synthetic raw
CSV files in an isolated temporary directory -- the same way it's
actually used (`py data/processed.py`) -- rather than importing internal
functions. processed.py is a top-to-bottom script, not a function
library, and testing it as it's really run also means these tests
exercise the exact same code path as production use, not a simplified
stand-in for it.

Run with: pytest tests/test_processed.py -v
Requires: pytest (pip install pytest --break-system-packages)
"""
import csv
import os
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_SCRIPT = REPO_ROOT / "data" / "processed.py"

BASE_COLUMNS = [
    "record_id", "event_time", "actor_email_hash", "ip_hash", "ip_version",
    "ip_country", "ip_region", "ip_city", "continent", "latitude", "longitude",
    "event_name", "is_suspicious", "login_type", "login_challenge_method",
    "login_status",
]

TEST_HMAC_KEY = "test-key-never-use-in-production"


def make_row(record_id, hour_minute_second, actor="aaaa1111bbbb2222", ip="1111aaaa2222bbbb",
            country="Angola", region="AO", city="Luanda", continent="Africa",
            lat=-8.8371, lon=13.2333, is_suspicious="False",
            login_type="google_password", challenge="password", day="01"):
    return {
        "record_id": record_id,
        "event_time": f"2026-05-{day}T{hour_minute_second}Z",
        "actor_email_hash": actor,
        "ip_hash": ip,
        "ip_version": 4,
        "ip_country": country,
        "ip_region": region,
        "ip_city": city,
        "continent": continent,
        "latitude": lat,
        "longitude": lon,
        "event_name": "login_success",
        "is_suspicious": is_suspicious,
        "login_type": login_type,
        "login_challenge_method": challenge,
        "login_status": "success",
    }


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A temp project root with processed.py in the exact same relative
    location as real usage (<root>/data/processed.py), an empty
    data/raw/ ready for test files, and HMAC_SECRET_KEY set via
    monkeypatch (equivalent to a real .env, without touching disk)."""
    (tmp_path / "data" / "raw").mkdir(parents=True)
    (tmp_path / "data" / "processed").mkdir(parents=True)
    script_dest = tmp_path / "data" / "processed.py"
    script_dest.write_text(PROCESSED_SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setenv("HMAC_SECRET_KEY", TEST_HMAC_KEY)
    return tmp_path


def write_raw_csv(path, rows, sep=",", encoding="utf-8"):
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False, sep=sep, encoding=encoding)


def run_processed(project_root, extra_env=None):
    """Runs the script exactly as the user does, as a subprocess, from
    inside data/ (matching `py data/processed.py` / cwd expectations)."""
    env = os.environ.copy()
    env["HMAC_SECRET_KEY"] = TEST_HMAC_KEY
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, str(project_root / "data" / "processed.py")],
        cwd=str(project_root), capture_output=True, text=True, env=env,
    )
    return result


# ============================================================
# BASIC PIPELINE
# ============================================================

def test_single_well_formed_file_produces_both_outputs(project):
    rows = [make_row(i, f"10:0{i}:00.000") for i in range(1, 6)]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr

    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert len(public) == 5
    assert len(restricted) == 5


def test_no_raw_files_raises_clear_error(project):
    result = run_processed(project)
    assert result.returncode != 0
    assert "No raw files found" in result.stderr


# ============================================================
# MULTI-FILE COMBINATION (fix #8)
# ============================================================

def test_multiple_files_combine_and_get_fresh_sequential_record_id(project):
    rows0 = [make_row(i, f"09:0{i}:00.000", actor=f"user000000000000{i}") for i in range(1, 4)]
    rows1 = [make_row(i, f"11:0{i}:00.000", actor=f"user111111111111{i}") for i in range(1, 4)]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows0)
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs1.csv", rows1)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr

    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert len(restricted) == 6


def test_overlapping_rows_across_files_are_deduplicated(project):
    shared_row = make_row(1, "10:00:00.000", actor="dupdupdupdupdup1")
    rows0 = [shared_row, make_row(2, "10:05:00.000", actor="uniqueuniqueuniq")]
    rows1 = [dict(shared_row, record_id=1)]  # same content, own file's record_id=1
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows0)
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs1.csv", rows1)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    assert "Removed 1 duplicate" in result.stdout

    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert len(restricted) == 2  # not 3 -- the true duplicate was dropped


def test_schema_mismatch_across_files_raises_clear_error(project):
    rows_ok = [make_row(1, "10:00:00.000")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows_ok)

    df_bad = pd.DataFrame(rows_ok)
    df_bad = df_bad.rename(columns={"ip_country": "country_name"})  # different schema
    df_bad.to_csv(project / "data" / "raw" / "suspicious_login_logs1.csv", index=False)

    result = run_processed(project)
    assert result.returncode != 0
    assert "different column set" in result.stderr


# ============================================================
# DELIMITER / ENCODING / DECIMAL FORMAT (fix #9, #10)
# ============================================================

def test_semicolon_delimited_file_is_read_correctly(project):
    rows = [make_row(1, "10:00:00.000")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows, sep=";")

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert len(public) == 1
    assert len(public.columns) > 1  # would be 1 giant column if sep detection failed


def test_cp1252_encoded_file_with_accents_is_read_correctly(project):
    rows = [make_row(1, "10:00:00.000", city="São Paulo")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows, encoding="cp1252")

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    assert "was not valid UTF-8" in result.stdout
    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert restricted["ip_city"].iloc[0] == "São Paulo"


def test_comma_decimal_latitude_longitude_are_parsed_as_numbers(project):
    rows = [make_row(1, "10:00:00.000", lat=-8.8371, lon=13.2333)]
    df = pd.DataFrame(rows)
    # Simulate a European-format export: decimal comma, written as text
    df["latitude"] = df["latitude"].astype(str).str.replace(".", ",", regex=False)
    df["longitude"] = df["longitude"].astype(str).str.replace(".", ",", regex=False)
    df.to_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", index=False, sep=";")

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert restricted["latitude"].dtype == float
    assert abs(restricted["latitude"].iloc[0] - (-8.8371)) < 1e-6


# ============================================================
# PSEUDONYMIZATION (fix #1, #6)
# ============================================================

def test_missing_hmac_key_raises_clear_error(project, monkeypatch):
    rows = [make_row(1, "10:00:00.000")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)
    monkeypatch.delenv("HMAC_SECRET_KEY", raising=False)

    env = os.environ.copy()
    env.pop("HMAC_SECRET_KEY", None)
    result = subprocess.run(
        [sys.executable, str(project / "data" / "processed.py")],
        cwd=str(project), capture_output=True, text=True, env=env,
    )
    assert result.returncode != 0
    assert "HMAC_SECRET_KEY is not set" in result.stderr


def test_same_actor_gets_same_pseudonym_across_rows(project):
    rows = [make_row(1, "10:00:00.000", actor="sameactorsameact"),
           make_row(2, "10:05:00.000", actor="sameactorsameact")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert public["actor_pseudo_id"].nunique() == 1
    assert public["actor_pseudo_id"].iloc[0].startswith("U")


def test_raw_hash_never_appears_in_public_only_in_restricted_actor_email_hash(project):
    """actor_email_hash (the raw, unsalted SHA-256 hash) is deliberately
    kept in the RESTRICTED schema only (added 2026-08-16), specifically
    to enable correlating login events with the other extracted sources
    (drive/admin/token/gmail/meet/classroom) by the same raw hash they
    independently compute. It must never appear in the public schema,
    and in restricted it must appear ONLY as the actor_email_hash
    column's own value -- not leaked anywhere else unexpected."""
    rows = [make_row(1, "10:00:00.000", actor="secretactorhash1")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public_text = (project / "data" / "processed" / "suspicious_logins_public_v1.csv").read_text()
    assert "secretactorhash1" not in public_text

    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert "actor_email_hash" in restricted.columns
    assert restricted["actor_email_hash"].iloc[0] == "secretactorhash1"
    for col in restricted.columns:
        if col != "actor_email_hash":
            assert restricted[col].astype(str).str.contains("secretactorhash1").sum() == 0, (
                f"raw hash unexpectedly leaked into column {col}")


# ============================================================
# SCHEMA SEPARATION (fix #5)
# ============================================================

def test_public_schema_excludes_sensitive_columns(project):
    rows = [make_row(1, "10:00:00.000")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    for forbidden in ("ip_city", "latitude", "longitude", "ip_region",
                      "network_pseudo_id", "event_time", "actor_email_hash", "ip_hash"):
        assert forbidden not in public.columns, f"{forbidden} leaked into the public schema"


def test_restricted_schema_includes_the_columns_public_lacks(project):
    rows = [make_row(1, "10:00:00.000")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    for expected in ("ip_city", "latitude", "longitude", "network_pseudo_id",
                     "event_time", "actor_email_hash"):
        assert expected in restricted.columns


# ============================================================
# TEMPORAL LEAKAGE FIX (fix #2)
# ============================================================

def test_first_login_for_a_user_is_never_flagged_abnormal_hour(project):
    # Very unusual hour (03:00) as the FIRST login ever for this user --
    # must not be flagged, since there's no prior baseline to compare to.
    rows = [make_row(1, "03:00:00.000", actor="freshuserfreshus")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert public["abnormal_login_hour"].iloc[0] == 0


# ============================================================
# RISK SCORE (fix #9 in the risk-score sense -- regression guard against
# reintroducing the confirmed-worse-than-random naive formula)
# ============================================================

def test_risk_score_column_exists_and_naive_version_is_not_published(project):
    rows = [make_row(1, "10:00:00.000")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert "risk_score" in public.columns
    assert "risk_score_naive" not in public.columns


# ============================================================
# LOGIN CHALLENGE METHOD NORMALIZATION (fix #7)
# ============================================================

# ============================================================
# COUNTRY NAME NORMALIZATION (real bug found at scale: "Netherlands" vs
# "The Netherlands" treated as two different countries)
# ============================================================

# ============================================================
# MULTI-INSTITUTION SUPPORT
# ============================================================

def test_multi_institution_missing_key_for_one_subdir_raises_clear_error(project, monkeypatch):
    (project / "data" / "raw" / "institution_a").mkdir()
    (project / "data" / "raw" / "institution_b").mkdir()
    write_raw_csv(project / "data" / "raw" / "institution_a" / "suspicious_login_logs0.csv",
                  [make_row(1, "10:00:00.000")])
    write_raw_csv(project / "data" / "raw" / "institution_b" / "suspicious_login_logs0.csv",
                  [make_row(1, "10:00:00.000")])

    env = os.environ.copy()
    env["HMAC_SECRET_KEY_INSTITUTION_A"] = "key-a-only"
    env.pop("HMAC_SECRET_KEY_INSTITUTION_B", None)
    result = subprocess.run(
        [sys.executable, str(project / "data" / "processed.py")],
        cwd=str(project), capture_output=True, text=True, env=env,
    )
    assert result.returncode != 0
    assert "HMAC_SECRET_KEY_INSTITUTION_B" in result.stderr
    assert "institution_b" in result.stderr


def test_multi_institution_combines_both_with_no_id_collision(project, monkeypatch):
    (project / "data" / "raw" / "institution_a").mkdir()
    (project / "data" / "raw" / "institution_b").mkdir()
    # Same underlying actor_email_hash value in BOTH institutions, but
    # otherwise different event content (time, ip) -- realistic: the raw
    # hash coinciding across two institutions' independent SHA-256(email)
    # values is astronomically unlikely in real data, but IF it did
    # happen, different keys must still keep them as different
    # pseudonyms. Event details differ so this exercises the key
    # difference specifically, not the (unrelated, correctly-working)
    # cross-file deduplication for genuinely identical rows.
    write_raw_csv(project / "data" / "raw" / "institution_a" / "suspicious_login_logs0.csv",
                  [make_row(1, "10:00:00.000", actor="sharedvaluesharedv", ip="ipfrominstitutiona")])
    write_raw_csv(project / "data" / "raw" / "institution_b" / "suspicious_login_logs0.csv",
                  [make_row(1, "14:00:00.000", actor="sharedvaluesharedv", ip="ipfrominstitutionb")])

    env = os.environ.copy()
    env["HMAC_SECRET_KEY_INSTITUTION_A"] = "key-for-institution-a"
    env["HMAC_SECRET_KEY_INSTITUTION_B"] = "key-for-institution-b"
    result = subprocess.run(
        [sys.executable, str(project / "data" / "processed.py")],
        cwd=str(project), capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr

    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert len(public) == 2
    # Different keys -> different pseudonyms for the same underlying value.
    assert public["actor_pseudo_id"].nunique() == 2
    # Sequential numbering is GLOBAL, not restarted per institution --
    # U000001 and U000002, not two separate "U000001"s colliding.
    assert set(public["actor_pseudo_id"]) == {"U000001", "U000002"}


def test_multi_institution_pseudo_ids_do_not_reveal_institution(project):
    (project / "data" / "raw" / "institution_a").mkdir()
    (project / "data" / "raw" / "institution_b").mkdir()
    rows_a = [make_row(i, f"09:0{i}:00.000", actor=f"instaaaaaaaaaaaa{i}") for i in range(1, 4)]
    rows_b = [make_row(i, f"11:0{i}:00.000", actor=f"instbbbbbbbbbbbb{i}") for i in range(1, 4)]
    write_raw_csv(project / "data" / "raw" / "institution_a" / "suspicious_login_logs0.csv", rows_a)
    write_raw_csv(project / "data" / "raw" / "institution_b" / "suspicious_login_logs0.csv", rows_b)

    env = os.environ.copy()
    env["HMAC_SECRET_KEY_INSTITUTION_A"] = "key-for-institution-a"
    env["HMAC_SECRET_KEY_INSTITUTION_B"] = "key-for-institution-b"
    result = subprocess.run(
        [sys.executable, str(project / "data" / "processed.py")],
        cwd=str(project), capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, result.stderr

    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert len(public) == 6
    # No column anywhere should name or hint at the institution.
    for col in public.columns:
        assert "institution" not in col.lower()
    # IDs are plain sequential U000001..U000006 -- nothing in the ID
    # itself (no prefix, no pattern) distinguishes which institution a
    # given pseudonym came from.
    assert set(public["actor_pseudo_id"]) == {f"U{i:06d}" for i in range(1, 7)}


def test_country_name_variants_are_normalized(project):
    rows = [make_row(1, "10:00:00.000", country="The Netherlands", actor="nlvariantnlvaria")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    # Checked via the RESTRICTED schema, not public: with only 1 row, the
    # new rare-country generalization (below) correctly turns this into
    # "Other" in the public output -- expected interaction between the
    # two features, not a normalization failure. Restricted always keeps
    # the real, normalized country regardless of rarity.
    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")
    assert restricted["ip_country"].iloc[0] == "Netherlands"


def test_country_name_normalization_prevents_false_country_change(project):
    # Same real country, two different spellings across consecutive
    # logins -- must NOT be recorded as a country change.
    rows = [
        make_row(1, "10:00:00.000", country="Netherlands", actor="samecountrysamec"),
        make_row(2, "11:00:00.000", country="The Netherlands", actor="samecountrysamec"),
    ]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert public["country_changed"].iloc[1] == 0
    assert public["is_new_country"].iloc[1] == 0


# ============================================================
# RARE-COUNTRY GENERALIZATION (public schema only)
# ============================================================

def test_rare_country_generalized_to_other_in_public_only(project):
    # 3 events from a rare country (below the 5-event threshold), plus
    # enough common-country events to keep the file otherwise normal.
    rows = ([make_row(i, f"09:0{i}:00.000", country="RareCountryland",
                      actor=f"rareuserrareuse{i}") for i in range(1, 4)]
           + [make_row(i, f"11:0{i}:00.000", country="Angola",
                       actor=f"commonusercommon{i}") for i in range(1, 8)])
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    assert "Generalizing" in result.stdout
    assert "RareCountryland" in result.stdout

    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    restricted = pd.read_csv(project / "data" / "processed" / "suspicious_logins_restricted_v1.csv")

    assert (public["ip_country"] == "RareCountryland").sum() == 0
    assert (public["ip_country"] == "Other").sum() == 3
    # Restricted keeps the real country name regardless of rarity.
    assert (restricted["ip_country"] == "RareCountryland").sum() == 3
    assert (restricted["ip_country"] == "Other").sum() == 0


def test_common_country_not_generalized(project):
    # 7 events from the same country -- above the 5-event threshold,
    # must stay as its real name, not get swept into "Other".
    rows = [make_row(i, f"09:0{i}:00.000", country="Angola",
                     actor=f"angolauserangola{i}") for i in range(1, 8)]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert (public["ip_country"] == "Angola").sum() == 7
    assert (public["ip_country"] == "Other").sum() == 0


def test_repeated_challenge_methods_are_collapsed(project):
    rows = [make_row(1, "10:00:00.000", challenge="password|password|password")]
    write_raw_csv(project / "data" / "raw" / "suspicious_login_logs0.csv", rows)

    result = run_processed(project)
    assert result.returncode == 0, result.stderr
    public = pd.read_csv(project / "data" / "processed" / "suspicious_logins_public_v1.csv")
    assert public["login_challenge_method"].iloc[0] == "password"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
