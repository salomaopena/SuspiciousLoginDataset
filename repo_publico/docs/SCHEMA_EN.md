# Technical Schema — SuspiciousLogin Dataset v1

Compact reference of types and domains. For full descriptions, see
`docs/DATA_DICTIONARY_EN.md`.

Format: CSV, `,` separator, UTF-8 encoding, header on the first line.

## `suspicious_logins_public_v1.csv` — 44 columns

| Column | Type | Domain / range | Nullable? |
|---|---|---|---|
| `actor_pseudo_id` | string | `^U\d{6}$` | no |
| `event_hour` | int | 0–23 | no |
| `day_of_week` | int | 0–6 | no |
| `month` | int | 1–12 | no |
| `quarter` | int | 1–4 | no |
| `is_weekend` | int | {0,1} | no |
| `is_business_hours` | int | {0,1} | no |
| `is_night_login` | int | {0,1} | no |
| `ip_country` | string | country name, normalized canonical spelling | yes |
| `continent` | string | continent name | yes |
| `ip_version` | int | {4,6} | yes |
| `login_type` | string | `google_password` \| `reauth` \| `exchange` | no |
| `login_challenge_method` | string | `\|`-separated values, no consecutive repeats | yes |
| `new_ip` | int | {0,1} | no |
| `distinct_ips_7d` | int | ≥1 | no |
| `distinct_ips_30d` | int | ≥1 | no |
| `is_new_country` | int | {0,1} | no |
| `is_new_region` | int | {0,1} | no |
| `is_new_city` | int | {0,1} | no |
| `distinct_countries_cumulative` | int | ≥0 | no |
| `distinct_regions_cumulative` | int | ≥0 | no |
| `distinct_cities_cumulative` | int | ≥0 | no |
| `country_changed` | int | {0,1} | no |
| `continent_changed` | int | {0,1} | no |
| `countries_seen_30d` | int | ≥1 | no |
| `regions_seen_30d` | int | ≥1 | no |
| `cities_seen_30d` | int | ≥1 | no |
| `logins_24h` | int | ≥1 | no |
| `logins_7d` | int | ≥1 | no |
| `logins_30d` | int | ≥1 | no |
| `avg_logins_per_day` | float | ≥0, rounded to 2 decimals | no |
| `hours_since_last_login` | float | ≥0, rounded to 2 decimals | no |
| `days_since_first_login` | int | ≥0 | no |
| `abnormal_login_hour` | int | {0,1} | no |
| `abnormal_weekday` | int | {0,1} | no |
| `impossible_travel` | int | {0,1} | no |
| `travel_distance_km` | float | ≥0, rounded to 2 decimals | no |
| `travel_speed_kmh` | float | ≥0, rounded to 2 decimals | no |
| `multiple_country_logins_24h` | int | {0,1} | no |
| `distinct_users_per_network_24h` | int | ≥1 | no |
| `geo_jump` | int | {0,1,2} | no |
| `risk_score` | float | see `docs/RISK_SCORE_METHODOLOGY_EN.md` for the current version's theoretical range | no |
| `risk_level` | string | `low` \| `medium` \| `high` | no |
| `label` | int | {0,1} | no |

## `suspicious_logins_restricted_v1.csv` — the 44 columns above, plus:

| Column | Type | Domain / range | Nullable? |
|---|---|---|---|
| `event_time` | string, ISO 8601 UTC | `YYYY-MM-DDTHH:MM:SS.sssZ` | no |
| `network_pseudo_id` | string | `^N\d{6}$` | no |
| `ip_region` | string | **not reliable** — a copy of the country code, not a real region (see `DATA_DICTIONARY_EN.md`) | yes |
| `ip_city` | string | city name | yes |
| `latitude` | float | -90 to 90 | yes |
| `longitude` | float | -180 to 180 | yes |

## Expected integrity constraints (verified by `tests/test_processed.py`)

- `actor_pseudo_id` and `network_pseudo_id` are deterministically derived
  — the same source hash always produces the same pseudonym within a
  given run.
- No row in either the public or restricted file contains
  `actor_email_hash` or `ip_hash` (the source SHA-256 hashes).
- `abnormal_login_hour = 0` on the first observed event for every user
  (no exceptions — there is no historical baseline yet).
- `risk_score` never depends directly on `is_new_country`,
  `country_changed`, or `continent_changed` — it uses `geo_jump`, which
  replaces them.
