# Data Dictionary — SuspiciousLogin Dataset

This document describes every column produced by `data/processed.py`, in
the two schemas generated: **public** (`suspicious_logins_public_v1.csv`,
for publication) and **restricted** (`suspicious_logins_restricted_v1.csv`,
internal use, never published).

The **restricted** schema contains every column from the public schema,
plus six additional ones listed in their own section below.

Convention: `bool (0/1)` denotes a binary flag stored as integer 0 or 1,
not as a literal `True`/`False`.

---

## Identification

| Column | Type | Description | Privacy classification |
|---|---|---|---|
| `actor_pseudo_id` | string (`U000001`, ...) | User pseudonym, derived via HMAC-SHA256 with a secret key from the original email hash. Deterministic: the same user always gets the same pseudonym within one dataset version. | Quasi-identifier — medium risk (see `docs/PRIVACY_ANONYMIZATION_REPORT_EN.md`) |

---

## Temporal (derived from `event_time`)

| Column | Type | Description |
|---|---|---|
| `event_hour` | int (0-23) | Hour of the event, UTC |
| `day_of_week` | int (0-6) | Day of week, 0=Monday |
| `month` | int (1-12) | Month of the event |
| `quarter` | int (1-4) | Quarter of the event |
| `is_weekend` | bool (0/1) | `day_of_week` is Saturday or Sunday |
| `is_business_hours` | bool (0/1) | Event hour between 8am and 6pm |
| `is_night_login` | bool (0/1) | Event hour ≤6am or ≥10pm |

## Geographic and network

| Column | Type | Description |
|---|---|---|
| `ip_country` | text | Country of origin of the IP. Names normalized to one canonical spelling per country (see the `COUNTRY_NAME_CANONICAL` note in `processed.py`). **In the public schema**, countries with ≤5 events in the whole dataset appear as `"Other"` — the real country is available in the restricted schema. The threshold is recomputed on every processing run (`RARE_COUNTRY_MAX_EVENTS` in `processed.py`), not a fixed list. |
| `continent` | text | Continent of origin of the IP |
| `ip_version` | int (4 or 6) | IP protocol version |
| `new_ip` | bool (0/1) | First time this network pseudonym appears associated with this user |
| `distinct_ips_7d` / `distinct_ips_30d` | int | Count of distinct networks used by this user in the trailing 7/30-day window (inclusive) |
| `is_new_country` / `is_new_region` / `is_new_city` | bool (0/1) | First time this user is seen in this country/region/city, across their entire observed history |
| `distinct_countries_cumulative` / `distinct_regions_cumulative` / `distinct_cities_cumulative` | int | Cumulative count (since this user's first observed event) of distinct countries/regions/cities seen so far |
| `country_changed` / `continent_changed` | bool (0/1) | Different country/continent from this user's immediately preceding event |
| `countries_seen_30d` / `regions_seen_30d` / `cities_seen_30d` | int | Count of distinct countries/regions/cities in the trailing 30 days (inclusive) |
| `geo_jump` | ordinal (0/1/2) | 0 = no country change since the previous login; 1 = country changed; 2 = continent also changed (a larger jump). Replaces `is_new_country`+`country_changed`+`continent_changed` as a `risk_score` input, since those three were confirmed to be redundant with each other (see the code comment). |
| `multiple_country_logins_24h` | bool (0/1) | `countries_seen_30d` > 1 |
| `distinct_users_per_network_24h` | int | How many distinct pseudonymized users used the same pseudonymized network in the trailing 24 hours (inclusive). Interpretation note: high values are expected and normal on shared institutional networks (a campus NAT/gateway), not by themselves a sign of suspicion. |

## Authentication

| Column | Type | Description |
|---|---|---|
| `login_type` | text | `reauth`, `google_password`, `exchange`, `federated_login`, `session_refresh`, or `admin_login`. The last three were confirmed only at the full two-institution scale (73,528 rows) -- absent or negligible in earlier, smaller samples. `federated_login` denotes SSO via an external identity provider; `session_refresh` denotes an existing session being renewed rather than a fresh interactive login; `admin_login` denotes an administrator console login. |
| `login_challenge_method` | text, `\|`-separated values | Authentication challenge method(s) used. Consecutive repeated values are collapsed to the distinct set (e.g. `password\|password` → `password`). |

## Login history

| Column | Type | Description |
|---|---|---|
| `logins_24h` / `logins_7d` / `logins_30d` | int | Count of this user's logins in the corresponding trailing window (inclusive) |
| `avg_logins_per_day` | decimal | `logins_30d` divided by the number of days actually observed, up to 30 |
| `hours_since_last_login` | decimal | Hours since this user's previous login (0 on the first observed login) |
| `days_since_first_login` | int | Days since this user's first observed login |
| `abnormal_login_hour` | bool (0/1) | Event hour more than 2 standard deviations from this user's **prior** historical mean (never includes the event itself or future events). Always 0 on a user's first observed login, since no historical baseline exists yet. |
| `abnormal_weekday` | bool (0/1) | Identical to `is_weekend` (kept for compatibility with the original design) |

## Impossible travel

| Column | Type | Description |
|---|---|---|
| `impossible_travel` | bool (0/1) | `travel_speed_kmh` > 900 km/h (faster than a plausible commercial trip between the two points, in the elapsed time) |
| `travel_distance_km` | decimal | Straight-line distance (haversine formula) between this login and the same user's previous one. 0 if there is no previous login or coordinates are missing. |
| `travel_speed_kmh` | decimal | `travel_distance_km` divided by `hours_since_last_login`. 0 if not applicable. |

## Risk score

| Column | Type | Description |
|---|---|---|
| `risk_score` | decimal | Empirical score, derived from a logistic regression (`class_weight="balanced"`) fit on a chronological data split, converted to fixed integer/decimal points. See `docs/RISK_SCORE_METHODOLOGY_EN.md` for the full methodology and the weight version history. |
| `risk_level` | categorical (`low`/`medium`/`high`) | `risk_score` discretized by percentiles of the distribution observed at the time the weights were fit |

## Label

| Column | Type | Description |
|---|---|---|
| `label` | bool (0/1) | 1 if `is_suspicious=true` in the source (Google Workspace). **Limitation to repeat every time this field is used**: `is_suspicious` is an operational suspicion signal supplied by Google Workspace, not a forensic confirmation of phishing, credential stuffing, brute force, or actually confirmed account compromise. |

---

## Columns exclusive to the restricted schema

These six columns **never** appear in the public file. They require
controlled access, per `docs/PRIVACY_ANONYMIZATION_REPORT_EN.md`.

| Column | Type | Description | Privacy classification |
|---|---|---|---|
| `event_time` | ISO 8601 date/time, UTC | Exact moment of the event, to the millisecond | Quasi-identifier — high risk |
| `network_pseudo_id` | text (`N000001`, ...) | Pseudonym of the source network/IP, same HMAC scheme as `actor_pseudo_id` | Quasi-identifier — medium-high risk |
| `ip_region` | text | **Not reliable in this version** — confirmed to be a copy of the country code (`countryCode`), not a real region/state (see `functions.py::getGeoFromPI`). Kept in the restricted schema for audit purposes only; should not be treated as having sub-national granularity. | Low (redundant) |
| `ip_city` | text | City of origin of the IP | Quasi-identifier — high risk |
| `latitude` / `longitude` | decimal | Geographic coordinates of the IP | Quasi-identifier — high risk |

---

## Provenance notes

- Every column derives, directly or indirectly, from `event_name=login_success` extracted via the Google Workspace Admin Reports API (`extract_suspicious_logins.py`).
- Geolocation uses Google Workspace's own `geoLocation` first; when absent, it falls back to `ip-api.com` (see `functions.py`). This means **different rows in the same dataset may have their geolocation sourced from different providers** — not documented on a per-row basis in this version.
- The source `actor_email_hash` and `ip_hash` (SHA-256, unsalted, 16 characters) never appear in either final schema — they are replaced by HMAC pseudonyms before any release, even internal.
