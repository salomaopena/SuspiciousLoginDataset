# Dicionário de Dados — SuspiciousLogin Dataset

Este documento descreve cada coluna produzida por `data/processed.py`, nos dois
esquemas gerados: **público** (`suspicious_logins_public_v1.csv`, para
publicação) e **restrito** (`suspicious_logins_restricted_v1.csv`, uso
interno, nunca publicado).

O esquema **restrito** contém todas as colunas do público, mais seis
adicionais assinaladas na secção própria mais abaixo.

Convenção: `bool (0/1)` indica uma bandeira binária guardada como inteiro
0 ou 1, não como `True`/`False` literal.

---

## Identificação

| Coluna | Tipo | Descrição | Classificação de privacidade |
|---|---|---|---|
| `actor_pseudo_id` | texto (`U000001`, ...) | Pseudónimo do utilizador, derivado por HMAC-SHA256 com chave secreta a partir do hash original do email. Determinístico: o mesmo utilizador tem sempre o mesmo pseudónimo dentro de uma versão do conjunto de dados. | Quase-identificador — risco médio (ver `docs/PRIVACY_ANONYMIZATION_REPORT.md`) |

---

## Temporais (derivadas de `event_time`)

| Coluna | Tipo | Descrição |
|---|---|---|
| `event_hour` | inteiro (0-23) | Hora do evento, UTC |
| `day_of_week` | inteiro (0-6) | Dia da semana, 0=segunda |
| `month` | inteiro (1-12) | Mês do evento |
| `quarter` | inteiro (1-4) | Trimestre do evento |
| `is_weekend` | bool (0/1) | `day_of_week` é sábado ou domingo |
| `is_business_hours` | bool (0/1) | Hora do evento entre as 08h e as 18h |
| `is_night_login` | bool (0/1) | Hora do evento ≤6h ou ≥22h |

## Geográficas e de rede

| Coluna | Tipo | Descrição |
|---|---|---|
| `ip_country` | texto | País de origem do IP. Nomes normalizados para uma grafia canónica por país (ver nota sobre `COUNTRY_NAME_CANONICAL` em `processed.py`). **No esquema público**, países com ≤5 eventos no conjunto de dados inteiro aparecem como `"Other"` — o país real fica disponível no esquema restrito. Limiar recalculado a cada processamento (`RARE_COUNTRY_MAX_EVENTS` em `processed.py`), não é uma lista fixa. |
| `continent` | texto | Continente de origem do IP |
| `ip_version` | inteiro (4 ou 6) | Versão do protocolo IP |
| `new_ip` | bool (0/1) | Primeira vez que este pseudónimo de rede aparece associado a este utilizador |
| `distinct_ips_7d` / `distinct_ips_30d` | inteiro | Contagem de redes distintas usadas por este utilizador na janela móvel de 7/30 dias anteriores (inclusive) |
| `is_new_country` / `is_new_region` / `is_new_city` | bool (0/1) | Primeira vez que este utilizador é visto neste país/região/cidade, em toda a história observada |
| `distinct_countries_cumulative` / `distinct_regions_cumulative` / `distinct_cities_cumulative` | inteiro | Contagem cumulativa (desde o primeiro evento observado deste utilizador) de países/regiões/cidades distintas já vistas |
| `country_changed` / `continent_changed` | bool (0/1) | País/continente diferente do evento imediatamente anterior deste utilizador |
| `countries_seen_30d` / `regions_seen_30d` / `cities_seen_30d` | inteiro | Contagem de países/regiões/cidades distintas nos 30 dias anteriores (inclusive) |
| `geo_jump` | ordinal (0/1/2) | 0 = sem mudança de país desde o login anterior; 1 = país mudou; 2 = continente também mudou (salto maior). Substitui `is_new_country`+`country_changed`+`continent_changed` como entrada do `risk_score`, por estas três serem confirmadamente redundantes (ver nota no código). |
| `multiple_country_logins_24h` | bool (0/1) | `countries_seen_30d` > 1 |
| `distinct_users_per_network_24h` | inteiro | Quantos utilizadores pseudonimizados distintos usaram a mesma rede pseudonimizada nas 24h anteriores (inclusive). Nota de interpretação: valores altos são esperados e normais em redes institucionais partilhadas (NAT/gateway de campus), não são por si só um sinal de suspeita. |

## Autenticação

| Coluna | Tipo | Descrição |
|---|---|---|
| `login_type` | texto | `google_password`, `reauth`, ou `exchange` |
| `login_challenge_method` | texto, valores separados por `\|` | Método(s) de desafio de autenticação usados. Valores repetidos consecutivos colapsados para o conjunto distinto (ex.: `password\|password` → `password`). |

## Histórico de login

| Coluna | Tipo | Descrição |
|---|---|---|
| `logins_24h` / `logins_7d` / `logins_30d` | inteiro | Contagem de logins deste utilizador na janela móvel correspondente (inclusive) |
| `avg_logins_per_day` | decimal | `logins_30d` dividido pelo número de dias realmente observados até 30 |
| `hours_since_last_login` | decimal | Horas desde o login anterior deste utilizador (0 no primeiro login observado) |
| `days_since_first_login` | inteiro | Dias desde o primeiro login observado deste utilizador |
| `abnormal_login_hour` | bool (0/1) | Hora do evento a mais de 2 desvios-padrão da média histórica **anterior** deste utilizador (nunca inclui o próprio evento nem eventos futuros). Sempre 0 no primeiro login observado de cada utilizador, por não existir ainda uma referência histórica. |
| `abnormal_weekday` | bool (0/1) | Idêntico a `is_weekend` (mantido por compatibilidade com o desenho original) |

## Viagem impossível

| Coluna | Tipo | Descrição |
|---|---|---|
| `impossible_travel` | bool (0/1) | `travel_speed_kmh` > 900 km/h (mais rápido do que uma viagem comercial plausível entre os dois pontos, no tempo decorrido) |
| `travel_distance_km` | decimal | Distância em linha recta (fórmula de haversine) entre este login e o anterior do mesmo utilizador. 0 se não houver login anterior ou coordenadas em falta. |
| `travel_speed_kmh` | decimal | `travel_distance_km` dividido por `hours_since_last_login`. 0 se não aplicável. |

## Pontuação de risco

| Coluna | Tipo | Descrição |
|---|---|---|
| `risk_score` | decimal | Pontuação empírica, derivada de regressão logística (`class_weight="balanced"`) ajustada sobre uma divisão temporal 75/25 dos dados, convertida em pontos inteiros/decimais fixos. Ver `docs/RISK_SCORE_METHODOLOGY.md` para a metodologia completa e o histórico de versões dos pesos. |
| `risk_level` | categórico (`low`/`medium`/`high`) | `risk_score` discretizado por percentis da distribuição observada no momento do ajuste dos pesos |

## Rótulo

| Coluna | Tipo | Descrição |
|---|---|---|
| `label` | bool (0/1) | 1 se `is_suspicious=true` na fonte (Google Workspace). **Limitação a repetir sempre que este campo for usado**: `is_suspicious` é um sinal operacional de suspeita fornecido pelo Google Workspace, não uma confirmação forense de phishing, `credential stuffing`, força bruta, ou comprometimento de conta efectivamente confirmado. |

---

## Colunas exclusivas do esquema restrito

Estas seis colunas **nunca** aparecem no ficheiro público. Requerem acesso
controlado, conforme `docs/PRIVACY_ANONYMIZATION_REPORT.md`.

| Coluna | Tipo | Descrição | Classificação de privacidade |
|---|---|---|---|
| `event_time` | data/hora ISO 8601, UTC | Momento exacto do evento, ao milissegundo | Quase-identificador — risco alto |
| `network_pseudo_id` | texto (`N000001`, ...) | Pseudónimo da rede/IP de origem, mesmo esquema HMAC do `actor_pseudo_id` | Quase-identificador — risco médio-alto |
| `ip_region` | texto | **Não fiável nesta versão** — confirmado ser uma cópia do código do país (`countryCode`), não uma região/estado real (ver `functions.py::getGeoFromPI`). Mantido no restrito só para auditoria, não deve ser usado como se tivesse granularidade sub-nacional. | Baixo (redundante) |
| `ip_city` | texto | Cidade de origem do IP | Quase-identificador — risco alto |
| `latitude` / `longitude` | decimal | Coordenadas geográficas do IP | Quase-identificador — risco alto |

---

## Notas de proveniência

- Todas as colunas derivam, directa ou indirectamente, de `event_name=login_success` extraído da API de Relatórios do Google Workspace Admin (`extract_suspicious_logins.py`).
- A geolocalização usa em primeiro lugar `geoLocation` do próprio Google Workspace; quando ausente, recorre a `ip-api.com` (ver `functions.py`). Isto significa que **linhas diferentes do mesmo conjunto de dados podem ter a sua geolocalização proveniente de fontes diferentes** — não documentado por linha nesta versão.
- `actor_email_hash` e `ip_hash` de origem (SHA-256, sem sal, 16 caracteres) nunca aparecem em nenhum dos dois esquemas finais — são substituídos pelos pseudónimos HMAC antes de qualquer publicação, mesmo interna.
