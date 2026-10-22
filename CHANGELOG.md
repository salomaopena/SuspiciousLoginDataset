# Changelog

## 2.0.0 — 2026-10

- Rebuilt the dataset after provenance and extraction audit.
- Replaced the v1 schema with a 23-column public schema and 39-column restricted schema.
- Replaced `label` with `provider_suspicious`.
- Removed `risk_score`, `risk_level`, and model-output fields from the dataset core.
- Corrected first-event geographic-transition handling.
- Replaced ambiguous history inference with `prior_event_count` and `history_available`.
- Separated 24-hour and 30-day country-history windows.
- Added institution-specific HMAC pseudonymization in the processing stage.
- Generalized public timestamps to hour-level UTC and rare countries to `Other`.
- Added manifest, checksums, integrity checks, and a public characterization notebook.
- Recomputed all Article 1 descriptive statistics on the frozen v2 release.

## 1.0.0

Initial research release retained for historical reference only. Results and metadata from v1 must not be mixed with v2.
