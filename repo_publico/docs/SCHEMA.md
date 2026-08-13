# Esquema técnico — SuspiciousLogin Dataset v1

Referência compacta de tipos e domínios. Para descrições completas, ver
`docs/DATA_DICTIONARY.md`.

Formato: CSV, separador `,`, codificação UTF-8, cabeçalho na primeira linha.

## `suspicious_logins_public_v1.csv` — 44 colunas

| Coluna | Tipo | Domínio / intervalo | Nulo? |
|---|---|---|---|
| `actor_pseudo_id` | string | `^U\d{6}$` | não |
| `event_hour` | int | 0–23 | não |
| `day_of_week` | int | 0–6 | não |
| `month` | int | 1–12 | não |
| `quarter` | int | 1–4 | não |
| `is_weekend` | int | {0,1} | não |
| `is_business_hours` | int | {0,1} | não |
| `is_night_login` | int | {0,1} | não |
| `ip_country` | string | nome de país, grafia canónica normalizada | sim |
| `continent` | string | nome de continente | sim |
| `ip_version` | int | {4,6} | sim |
| `login_type` | string | `google_password` \| `reauth` \| `exchange` | não |
| `login_challenge_method` | string | valores separados por `\|`, sem repetições consecutivas | sim |
| `new_ip` | int | {0,1} | não |
| `distinct_ips_7d` | int | ≥1 | não |
| `distinct_ips_30d` | int | ≥1 | não |
| `is_new_country` | int | {0,1} | não |
| `is_new_region` | int | {0,1} | não |
| `is_new_city` | int | {0,1} | não |
| `distinct_countries_cumulative` | int | ≥0 | não |
| `distinct_regions_cumulative` | int | ≥0 | não |
| `distinct_cities_cumulative` | int | ≥0 | não |
| `country_changed` | int | {0,1} | não |
| `continent_changed` | int | {0,1} | não |
| `countries_seen_30d` | int | ≥1 | não |
| `regions_seen_30d` | int | ≥1 | não |
| `cities_seen_30d` | int | ≥1 | não |
| `logins_24h` | int | ≥1 | não |
| `logins_7d` | int | ≥1 | não |
| `logins_30d` | int | ≥1 | não |
| `avg_logins_per_day` | float | ≥0, arredondado a 2 casas | não |
| `hours_since_last_login` | float | ≥0, arredondado a 2 casas | não |
| `days_since_first_login` | int | ≥0 | não |
| `abnormal_login_hour` | int | {0,1} | não |
| `abnormal_weekday` | int | {0,1} | não |
| `impossible_travel` | int | {0,1} | não |
| `travel_distance_km` | float | ≥0, arredondado a 2 casas | não |
| `travel_speed_kmh` | float | ≥0, arredondado a 2 casas | não |
| `multiple_country_logins_24h` | int | {0,1} | não |
| `distinct_users_per_network_24h` | int | ≥1 | não |
| `geo_jump` | int | {0,1,2} | não |
| `risk_score` | float | ver `docs/RISK_SCORE_METHODOLOGY.md` para o intervalo teórico da versão em vigor | não |
| `risk_level` | string | `low` \| `medium` \| `high` | não |
| `label` | int | {0,1} | não |

## `suspicious_logins_restricted_v1.csv` — as 44 colunas acima, mais:

| Coluna | Tipo | Domínio / intervalo | Nulo? |
|---|---|---|---|
| `event_time` | string, ISO 8601 UTC | `YYYY-MM-DDTHH:MM:SS.sssZ` | não |
| `network_pseudo_id` | string | `^N\d{6}$` | não |
| `ip_region` | string | **não fiável** — cópia do código de país, não região real (ver `DATA_DICTIONARY.md`) | sim |
| `ip_city` | string | nome de cidade | sim |
| `latitude` | float | -90 a 90 | sim |
| `longitude` | float | -180 a 180 | sim |

## Restrições de integridade esperadas (verificadas por `tests/test_processed.py`)

- `actor_pseudo_id` e `network_pseudo_id` deterministicamente derivados —
  o mesmo hash de origem produz sempre o mesmo pseudónimo dentro da mesma
  execução.
- Nenhuma linha do público ou do restrito contém `actor_email_hash` ou
  `ip_hash` (os hashes SHA-256 de origem).
- `abnormal_login_hour = 0` no primeiro evento observado de cada
  utilizador (sem excepção — não há referência histórica ainda).
- `risk_score` nunca depende de `is_new_country`, `country_changed`, ou
  `continent_changed` directamente — usa `geo_jump`, que os substitui.
