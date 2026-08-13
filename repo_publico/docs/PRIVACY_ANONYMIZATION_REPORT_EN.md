# Privacy and Anonymization Report

**Status of this document**: figures updated on 2026-08-12, over the
dataset combining two institutions (73,528 rows, 36,691 distinct users).
If more data is added in the future (additional volume, or a third
institution), the concrete figures below should be recalculated before
any publication — the methodology itself remains valid regardless of
volume.

## 1. Identifier classification methodology

Each column is classified into one of three categories:

- **Direct identifier**: uniquely points to a person without needing any
  further information. None exist in this dataset — all original direct
  identifiers (email, IP address) are removed at the source, before this
  processing even begins.
- **Quasi-identifier**: does not identify on its own, but can, combined
  with other fields or outside knowledge, point to a specific person.
- **Sensitive attribute**: does not identify anyone on its own, but
  causes harm if associated with an identified person.

A factor that raises the risk of any quasi-identifier, common to this
entire dataset: **it comes from a small, geographically concentrated
institutional population**. Under these conditions, attribute
combinations that would be harmless in a large, diverse population can
be rare enough to point to a single person.

## 2. Classification by column

See `docs/DATA_DICTIONARY_EN.md` for the individual classification of
every column, on its own row. Summary of the highest-risk cases:

| Column | Schema | Risk | Reason |
|---|---|---|---|
| `event_time` (precise) | Restricted | High | To the millisecond, can identify a single, specific event |
| `ip_city` | Restricted | High | Cities outside the main concentration have very low counts |
| `latitude`/`longitude` | Restricted | High | Precise coordinates, near-direct identification combined with few users at that location |
| `network_pseudo_id` | Restricted | Medium-High | Allows correlating users who share a network |
| `actor_pseudo_id` | Public | Medium | Allows correlating the same person's entire behavior over time |
| `ip_country` | Public | Low (majority) / Medium (rare countries) | Discriminating for countries with few events |

No column, in either schema, contains special categories of personal
data (health, religion, sexual orientation, ethnicity, or equivalent).

## 3. Anonymization measures applied

1. **HMAC-SHA256 pseudonymization with a secret key** (`actor_pseudo_id`,
  `network_pseudo_id`), applied on top of the hash already received from
  extraction. The key is never written to the repository (environment
  variable / `.env`). Acknowledged limitation: the raw CSV already
  arrives with an unsalted SHA-256 hash (from the original extraction) —
  this processing step cannot retroactively fix that layer; the raw file
  must remain under restricted access regardless of what this script
  does afterward.
2. **Removal of fine-grained geographic detail** from the public schema
  (city, coordinates, region — the latter also redundant with country,
  see `DATA_DICTIONARY_EN.md`).
3. **Removal of the precise timestamp** from the public schema (only the
  derived fields are kept: hour, day of week, month).
4. **Split into two schemas**, public and restricted, with the
  restricted one never published, kept under access control.
5. **Normalization of network identifiers into an aggregate feature**
  (`distinct_users_per_network_24h`) instead of exposing the network
  identifier itself in the public schema.

## 4. Outlier check

Final status (73,528 rows, two institutions, 2026-08-12):

- Countries with ≤5 events: **6** (Switzerland 5, United Arab Emirates
  2, Tunisia 1, Czechia 1, Japan 1, Egypt 1)
- Most active user: **1,846 events, 2.51% of the total** — down from
  6.1% in the first sample, through institutional diversity, not
  suppression
- Known and fixed naming inconsistencies: country name variants
  (`"Netherlands"` vs `"The Netherlands"`) — see
  `COUNTRY_NAME_CANONICAL` in `processed.py`

**Resolved (2026-08-12)**: `ip_country` in the public schema
automatically generalizes any country with ≤5 events to `"Other"`
(`RARE_COUNTRY_MAX_EVENTS` in `processed.py`, recomputed on every
processing run, not a fixed list). The real country remains available
in the restricted schema, for legitimate internal analysis. No row is
removed — only the country's level of detail differs between the two
schemas.

## 5. Second institution — already implemented, not hypothetical

Confirmed and implemented (2026-08-12): the dataset now combines two
institutions. Measures adopted:

- **Separate HMAC keys per institution** (`HMAC_SECRET_KEY_<FOLDER>`,
  one per subdirectory of `data/raw/`) — implemented and tested
  (`tests/test_processed.py`, multi-institution section).
- **No institution-identifying column** in either the public or
  restricted schema — confirmed by an automated test
  (`test_multi_institution_pseudo_ids_do_not_reveal_institution`).
- **Pseudonym numbering (`U000001`, `N000001`, ...) is global**,
  assigned only after combining both institutions' data — never per
  institution, which would either collide or, with a prefix, reveal
  provenance.

**Confirmed with real data**: geographic concentration dropped from
95.68% to 63.15% (Angola), distinct users rose from 11,691 to 36,691,
the most active user's dominance dropped from 3.80% to 2.51% — the
strategy worked as anticipated.

**Process note, for future reference**: a first extraction of
institution B mistakenly used a filter that only captured events
already flagged as suspicious, producing an artificially skewed sample
(~85% suspicious). Caught before any analysis, fixed with a
re-extraction. Standing recommendation: always confirm the
`is_suspicious` proportion in the raw file of any new institution
before merging it with the rest.

If a third institution is ever added, repeat exactly the same
procedure: its own folder under `data/raw/`, its own HMAC key,
verification of the suspicious proportion in the raw file before
merging.

## 6. License and publication terms

Decided (2026-08-12):
- **Dataset** (public schema): Creative Commons Attribution-NonCommercial
  4.0 International (CC BY-NC 4.0) — allows sharing and adaptation with
  attribution, excludes commercial use. See `LICENSE-DATASET.txt`.
- **Code** (`processed.py`, `benchmark_ml.py`, tests): MIT License —
  permissive, including commercial use of the code (distinct from the
  non-commercial restriction that applies only to the data). See
  `LICENSE-CODE.txt`.

This split is deliberate: the code (methodology, processing tools)
benefits from being as reusable as possible, even in commercial
contexts — but the data itself, since it contains real behavioral
information about real people, keeps the non-commercial restriction as
an additional safeguard beyond pseudonymization.
