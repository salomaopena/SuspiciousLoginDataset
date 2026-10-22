# Data Dictionary Mestre — SuspiciousLogin v2.0
## Esquema Científico Consolidado (42 Públicos / 50 Restritos)

- **Esquema Público:** 42 atributos observados e derivados determinísticos.
- **Esquema Restrito:** 50 atributos (**Superconjunto**: 42 públicos + 8 de acesso controlado com alta precisão temporal e geográfica).
- **Princípio Semântico Central:** Os atributos comportamentais descrevem a sequência temporal e o histórico do ator. O atributo `provider_suspicious` é preservado de forma estritamente isolada como sinal operacional do provedor (não constitui rótulo de ataque ou comprometimento).

---

## 1. Esquema Público — 42 Atributos

### Convenções Globais de Derivação

- A ordenação canônica por ator é `actor_pseudo_id` → `event_time` exato crescente → `event_id` crescente como desempate determinístico.
- O desempate por `event_id` garante reprodutibilidade computacional, mas não prova ordem física real entre eventos simultâneos.
- Nenhum atributo comportamental utiliza eventos futuros.
- Janelas indicadas por `t_h` usam `event_time_hour_utc`, com limite inferior e evento atual incluídos.
- Valores ausentes não formam categorias artificiais em contagens de diversidade.
- `0` representa valor válido; `NA` representa ausência ou impossibilidade de cálculo quando aplicável.
- `actor_network_id` é estável somente dentro do mesmo ator e não é comparável entre atores.


### 1.1 Identificação e Bloco A — Temporal (7 Atributos)
Todos os atributos temporais são referenciados exclusivamente em **UTC**.

| # | Atributo | Tipo | Origem / Dependência | Definição Operacional | Regra de *Missing* |
|---:|---|---|---|---|---|
| 1 | `event_id` | Texto | Derivado | Identificador determinístico e único do evento (HMAC). Usado para unicidade e desempate de ordenação. | Não permitido |
| 2 | `actor_pseudo_id` | Texto | Pseudonimização | Pseudônimo estável do ator no escopo institucional. | Não permitido |
| 3 | `event_time_hour_utc` | Datetime UTC | Transformado (`event_time`) | Timestamp exato truncado para o início da hora UTC (ex.: `19:32:10` $\rightarrow$ `19:00:00`). | Não permitido |
| 4 | `event_hour` | Inteiro `0–23` | Derivado (`event_time_hour_utc`) | Hora do dia em formato UTC. | Não permitido |
| 5 | `day_of_week` | Inteiro `0–6` | Derivado (`event_time_hour_utc`) | Dia da semana UTC (0 = Segunda-feira, ..., 6 = Domingo). | Não permitido |
| 6 | `month` | Inteiro `1–12` | Derivado (`event_time_hour_utc`) | Mês do calendário em UTC. | Não permitido |
| 7 | `is_weekend` | Binário `0/1` | Derivado (`day_of_week`) | `1` se `day_of_week` $\in \{5, 6\}$; `0` caso contrário. | Não permitido |

---

### 1.2 Bloco B — Atividade e Histórico (8 Atributos)
Calculados estritamente na ordem temporal do ator.

| # | Atributo | Tipo | Base Temporal | Definição Operacional | 1º Evento do Ator |
|---:|---|---|---|---|---|
| 8 | `prior_event_count` | Inteiro $\ge 0$ | Histórico acumulado | Quantidade de eventos anteriores observados para o mesmo ator. | `0` |
| 9 | `hours_since_last_login` | Decimal $\ge 0$ | Timestamp exato | Intervalo em horas desde o acesso imediatamente anterior: $(t_i - t_{i-1}) / 3600$. | `NA` |
| 10 | `hours_since_first_observed_login` | Decimal $\ge 0$ | Timestamp exato | Tempo em horas desde o primeiro evento observado do ator na coleta: `(t_i - t_first) / 3600`. | `0.0` |
| 11 | `logins_24h` | Inteiro $\ge 1$ | Janela $[t-24h, t]$ | Total de acessos do ator nas últimas 24 horas (inclui o evento atual). | `1` |
| 12 | `logins_7d` | Inteiro $\ge 1$ | Janela $[t-7d, t]$ | Total de acessos do ator nos últimos 7 dias. | `1` |
| 13 | `logins_30d` | Inteiro $\ge 1$ | Janela $[t-30d, t]$ | Total de acessos do ator nos últimos 30 dias. | `1` |
| 14 | `login_rate_30d` | Decimal $> 0$ | Janela de exposição | Taxa média diária de acessos: `logins_30d / observed_calendar_days_30d`, onde `observed_calendar_days_30d = min(30, (data_UTC_atual - data_UTC_primeiro_evento).days + 1)`. | `1.0` |
| 15 | `active_days_30d` | Inteiro `1–30` | 30 Dias UTC | Número de datas UTC distintas com pelo menos um acesso nos últimos 30 dias. | `1` |

### Invariantes do Bloco B

- `logins_24h <= logins_7d <= logins_30d`
- `1 <= active_days_30d <= 30`
- `active_days_30d <= logins_30d`
- `hours_since_last_login = NA` no primeiro evento
- `hours_since_first_observed_login = 0.0` no primeiro evento

---

### 1.3 Bloco C — Rede / IP (8 Atributos)

| # | Atributo | Tipo | Base Temporal | Definição Operacional | *Missing* / 1º Evento |
|---:|---|---|---|---|---|
| 16 | `actor_network_id` | Texto | Evento atual | Identificador pseudonimizado da rede/IP **escopado ao ator**. Não comparável entre atores. | `NA` se IP ausente |
| 17 | `ip_version` | Inteiro `{4,6}` | Evento atual | Versão do protocolo IP observada (4 ou 6). | `NA` se indisponível |
| 18 | `is_new_ip` | Binário `0/1/NA` | Histórico anterior | `1` se a rede nunca apareceu no histórico do ator; `0` se já apareceu. | `1` (se IP válido); `NA` se IP ausente |
| 19 | `ip_changed` | Binário `0/1/NA` | Evento anterior | `1` se a rede difere da rede do evento anterior; `0` se igual ou 1º evento. | `0` (1º evento); `NA` se comparativo nulo |
| 20 | `distinct_networks_24h` | Inteiro $\ge 0$ | Janela $[t_h-24h, t_h]$ | Quantidade de redes distintas (`actor_network_id`) conhecidas na janela; valores ausentes não entram na contagem. | `0` somente se nenhuma rede conhecida existir na janela; $\ge 1$ se a rede atual for conhecida |
| 21 | `distinct_networks_7d` | Inteiro $\ge 0$ | Janela $[t_h-7d, t_h]$ | Quantidade de redes distintas conhecidas observadas nos últimos 7 dias; valores ausentes não entram na contagem. | `0` somente se nenhuma rede conhecida existir na janela |
| 22 | `distinct_networks_30d` | Inteiro $\ge 0$ | Janela $[t_h-30d, t_h]$ | Quantidade de redes distintas conhecidas observadas nos últimos 30 dias; valores ausentes não entram na contagem. | `0` somente se nenhuma rede conhecida existir na janela |
| 23 | `networks_seen_to_date` | Inteiro $\ge 0$ | Histórico acumulado | Total cumulativo de redes distintas conhecidas observadas até o evento corrente. Evento com rede ausente não incrementa nem zera o acumulado. | `0` enquanto nenhuma rede conhecida tiver sido observada; caso contrário mantém o acumulado |

### Invariantes do Bloco C

- `distinct_networks_24h <= distinct_networks_7d <= distinct_networks_30d <= networks_seen_to_date`
- Se `actor_network_id` atual for conhecido, as três contagens de janela devem ser pelo menos `1`.
- `is_new_ip = 1` implica a entrada de uma nova rede no histórico cumulativo do ator.
- As janelas de rede usam `event_time_hour_utc`, permitindo recomputação a partir do esquema público.

---

### 1.4 Bloco D — Geografia (10 Atributos)

| # | Atributo | Tipo | Base Temporal | Definição Operacional | *Missing* / 1º Evento |
|---:|---|---|---|---|---|
| 24 | `ip_country` | Texto | Evento atual | Código/Nome normalizado do país associado ao IP de origem. | `NA` se indisponível |
| 25 | `continent` | Texto | Evento atual | Continente mapeado de forma determinística a partir de `ip_country`. | `NA` se país ausente |
| 26 | `is_new_country` | Binário `0/1/NA` | Histórico anterior | `1` se o país nunca apareceu anteriormente no histórico do ator. | `1` (se país válido); `NA` se ausente |
| 27 | `country_changed` | Binário `0/1/NA` | Evento anterior | `1` se o país difere daquele associado ao evento imediatamente anterior. | `0` (1º evento); `NA` se ausente |
| 28 | `is_new_continent` | Binário `0/1/NA` | Histórico anterior | `1` se o continente nunca apareceu no histórico do ator. | `1` (se continente válido); `NA` se ausente |
| 29 | `continent_changed` | Binário `0/1/NA` | Evento anterior | `1` se o continente difere do evento imediatamente anterior. | `0` (1º evento); `NA` se ausente |
| 30 | `distinct_countries_24h` | Inteiro $\ge 0$ | Janela $[t_h-24h, t_h]$ | Países distintos conhecidos observados na janela; países ausentes não entram na contagem. | `0` somente se nenhum país conhecido existir na janela; $\ge 1$ se o país atual for conhecido |
| 31 | `distinct_countries_7d` | Inteiro $\ge 0$ | Janela $[t_h-7d, t_h]$ | Países distintos conhecidos observados nos últimos 7 dias; países ausentes não entram na contagem. | `0` somente se nenhum país conhecido existir na janela |
| 32 | `distinct_countries_30d` | Inteiro $\ge 0$ | Janela $[t_h-30d, t_h]$ | Países distintos conhecidos observados nos últimos 30 dias; países ausentes não entram na contagem. | `0` somente se nenhum país conhecido existir na janela |
| 33 | `distinct_countries_to_date` | Inteiro $\ge 0$ | Histórico acumulado | Total cumulativo de países distintos conhecidos observados até o evento corrente. Evento com país ausente não incrementa nem zera o acumulado. | `0` enquanto nenhum país conhecido tiver sido observado; caso contrário mantém o acumulado |

### Invariantes do Bloco D

- `distinct_countries_24h <= distinct_countries_7d <= distinct_countries_30d <= distinct_countries_to_date`
- Se `ip_country` for conhecido, `continent` deve ser conhecido.
- `is_new_country = 1` implica a entrada de um novo país no histórico cumulativo do ator.

---

### 1.5 Bloco E — Autenticação (8 Atributos)

| # | Atributo | Tipo | Base Temporal | Definição Operacional | *Missing* / 1º Evento |
|---:|---|---|---|---|---|
| 34 | `login_type` | Categórico | Evento atual | Tipo de login informado pelo provedor (ex.: `google_password`, `reauth`). | `NA` se indisponível |
| 35 | `login_challenge_method` | Texto | Evento atual | Método(s) ou categoria(s) de desafio de autenticação registrados pelo provedor, normalizados e separados por `\|` (ex.: `password\|security_key`). | `none` é categoria válida; `NA` se ausente |
| 36 | `is_new_login_type` | Binário `0/1/NA` | Histórico anterior | `1` se o `login_type` atual nunca apareceu no histórico do ator. | `1` (se tipo válido); `NA` se ausente |
| 37 | `login_type_changed` | Binário `0/1/NA` | Evento anterior | `1` se o `login_type` difere do evento imediatamente anterior. | `0` (1º evento); `NA` se ausente |
| 38 | `is_new_challenge` | Binário `0/1/NA` | Histórico anterior | `1` se pelo menos uma categoria do desafio atual nunca apareceu no histórico do ator. | `1` (1º conjunto válido); `NA` se ausente |
| 39 | `challenge_changed` | Binário `0/1/NA` | Evento anterior | `1` se o conjunto de desafios difere do evento anterior (independente da ordem). | `0` (1º evento); `NA` se ausente |
| 40 | `distinct_login_types_30d` | Inteiro $\ge 0$ | Janela $[t_h-30d, t_h]$ | Tipos de login distintos conhecidos observados na janela de 30 dias; valores ausentes não entram na contagem. | `0` somente se nenhum tipo conhecido existir na janela; $\ge 1$ se o tipo atual for conhecido |
| 41 | `distinct_challenges_30d` | Inteiro $\ge 0$ | Janela $[t_h-30d, t_h]$ | Categorias individuais de desafio distintas observadas na janela de 30 dias; valores ausentes não entram na contagem e `none` é categoria válida. | `0` somente se nenhuma categoria conhecida existir na janela; $\ge 1$ se o challenge atual for conhecido |

---

### 1.6 Bloco F — Sinal do Provedor (1 Atributo)

| # | Atributo | Tipo | Origem | Definição Operacional | Regra de *Missing* |
|---:|---|---|---|---|---|
| 42 | `provider_suspicious` | Binário `0/1` | Provedor de Identidade | `1` = evento de autenticação bem-sucedida sinalizado como suspeito pelo provedor; `0` = não sinalizado. `1` não representa ataque/comprometimento confirmado e `0` não representa legitimidade confirmada. | **Não permitido**. Interrompe a execução do pipeline se nulo. |

### Regra Semântica do Sinal

- `provider_suspicious = 1` significa apenas que o provedor sinalizou o evento.
- `provider_suspicious = 1` não implica ataque ou comprometimento confirmado.
- `provider_suspicious = 0` não implica legitimidade confirmada.
- O sinal não é usado como entrada para gerar atributos comportamentais do core.

---

## 2. Atributos Adicionais do Esquema Restrito (+8 Atributos)

O Esquema Restrito contém os **42 atributos públicos** e acrescenta exatamente estes **8 campos de acesso controlado**:

| # | Atributo | Tipo | Origem | Finalidade Científica e Operacional | Regra de *Missing* |
|---:|---|---|---|---|---|
| 43 | `event_time` | Datetime UTC exato | Fonte normalizada | Precisão temporal original, ordenação canônica e auditoria. | Obrigatório |
| 44 | `institution_pseudo_id` | Texto | Pseudonimização | Identificador da instituição de origem (comparação inter-institucional controlada). | Obrigatório |
| 45 | `network_pseudo_id` | Texto | Pseudonimização | Identificador de rede estável no escopo institucional (reconhece a mesma rede entre atores). | `NA` se origem IP ausente |
| 46 | `ip_city` | Texto | Geolocalização IP | Análises geográficas de granularidade fina (cidade estimada). | `NA` se indisponível |
| 47 | `latitude` | Decimal `[-90, 90]` | Geolocalização IP | Coordenada para cálculo de mobilidade geodésica. | Deve formar par com `longitude` |
| 48 | `longitude` | Decimal `[-180, 180]` | Geolocalização IP | Coordenada para cálculo de mobilidade geodésica. | Deve formar par com `latitude` |
| 49 | `travel_distance_km` | Decimal $\ge 0$ / `NA` | Derivado (`Haversine`) | Distância em km entre o evento atual e o imediatamente anterior do mesmo ator. | `NA` se 1º evento ou se coordenadas forem ausentes |
| 50 | `travel_speed_kmh` | Decimal $\ge 0$ / `NA` | Derivado | Velocidade aparente: `travel_distance_km / hours_since_last_login`. | `NA` se `travel_distance_km` estiver ausente ou se `hours_since_last_login <= 0`; distância igual a `0` com intervalo positivo produz velocidade `0` |

---

## 3. Atributos Excluídos do Core Científico

Para garantir a transparência do dataset e evitar ruído/heurísticas proprietárias, os seguintes atributos foram **explicitamente descontinuados ou excluídos do núcleo do dataset**:

1. **Artefatos Internos de Processamento (Relegados à área privada de curadoria):** `source_file_id`, `actor_email_hash`, `ip_hash`, `ip_region` legado, chaves HMAC.
2. **Atributos Redundantes:** `history_available` (100% equivalente a `prior_event_count > 0`; permanece reconstruível diretamente a partir do esquema público).
3. **Heurísticas com Limiares Decididos por Regras Fixas:** `is_impossible_travel` (ex.: limiar fixo de 900 km/h pertence à etapa de análise, não ao dataset observacional), `is_night_login`, `is_business_hours`, `geo_jump`.
4. **Variáveis Derivadas de Risco/Saídas de Modelos:** `risk_score`, `risk_level`, `label`, `is_attack`, `is_anomaly`.

---

## 4. Resumo da Disponibilidade

| Camada de Acesso | Quantidade de Atributos | Finalidade Principal |
| :--- | :---: | :--- |
| **Esquema Público** | **42 atributos** | Pesquisa aberta, reprodutibilidade analítica e benchmarks abertos. |
| **Esquema Restrito** | **50 atributos** (Superconjunto) | Pesquisa controlada, auditoria temporal exata e estudos geográficos detalhados. |
| **Artefatos Internos** | Fora do esquema | Rastreabilidade, segurança e chaves de criptografia. |