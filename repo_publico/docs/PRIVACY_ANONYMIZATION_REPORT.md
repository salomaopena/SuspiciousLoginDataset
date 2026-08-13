# Relatório de Privacidade e Anonimização

**Estado deste documento**: números actualizados em 2026-08-12, sobre o
conjunto de dados combinando duas instituições (73.528 linhas, 36.691
utilizadores distintos). Se mais dados forem adicionados no futuro
(volume adicional, ou uma terceira instituição), os números concretos
abaixo devem ser recalculados antes de qualquer publicação — a
metodologia em si mantém-se válida independentemente do volume.

## 1. Metodologia de classificação de identificadores

Cada coluna é classificada segundo três categorias:

- **Identificador directo**: aponta univocamente para uma pessoa sem
  precisar de mais informação. Nenhum existe neste conjunto de dados —
  todos os identificadores directos originais (email, endereço IP) são
  removidos na fonte, antes mesmo deste processamento.
- **Quase-identificador**: não identifica sozinho, mas pode, combinado com
  outros campos ou conhecimento externo, apontar para uma pessoa
  específica.
- **Atributo sensível**: não identifica ninguém sozinho, mas causa dano se
  associado a uma pessoa identificada.

Um factor que amplia o risco de qualquer quase-identificador, comum a todo
este conjunto de dados: **é proveniente de uma população institucional
pequena e geograficamente concentrada**. Nestas condições, combinações de
atributos que seriam inofensivas numa população grande e diversa podem ser
suficientemente raras para apontar para uma só pessoa.

## 2. Classificação por coluna

Ver `docs/DATA_DICTIONARY.md` para a classificação individual de cada
coluna, na sua própria linha. Resumo dos casos de risco mais alto:

| Coluna | Esquema | Risco | Razão |
|---|---|---|---|
| `event_time` (preciso) | Restrito | Alto | Ao milissegundo, pode identificar um evento único |
| `ip_city` | Restrito | Alto | Cidades fora da concentração principal têm contagens muito baixas |
| `latitude`/`longitude` | Restrito | Alto | Coordenadas precisas, quase identificação directa em conjunto com poucos utilizadores no local |
| `network_pseudo_id` | Restrito | Médio-Alto | Permite correlacionar utilizadores que partilham rede |
| `actor_pseudo_id` | Público | Médio | Permite correlacionar todo o comportamento da mesma pessoa ao longo do tempo |
| `ip_country` | Público | Baixo (maioria) / Médio (países raros) | Discriminante nos países com poucos eventos |

Nenhuma coluna, em nenhum dos dois esquemas, contém categorias especiais de
dados pessoais (saúde, religião, orientação sexual, etnia, ou equivalente).

## 3. Medidas de anonimização aplicadas

1. **Pseudonimização por HMAC-SHA256 com chave secreta** (`actor_pseudo_id`,
  `network_pseudo_id`), aplicada sobre o hash já recebido da extracção.
  A chave nunca é gravada no repositório (variável de ambiente / `.env`).
  Limitação reconhecida: o CSV em bruto já chega com um hash SHA-256 sem
  sal (da extracção original) — este processamento não consegue corrigir
  retroactivamente essa camada; o ficheiro em bruto tem de permanecer em
  acesso restrito independentemente do que este *script* faz depois.
2. **Remoção de granularidade geográfica fina** do esquema público
  (cidade, coordenadas, região — esta última também redundante com o
  país, ver `DATA_DICTIONARY.md`).
3. **Remoção do carimbo temporal preciso** do esquema público (mantidas
  só as derivadas: hora, dia da semana, mês).
4. **Separação em dois esquemas**, público e restrito, com o restrito
  nunca publicado, mantido sob controlo de acesso.
5. **Normalização de identificadores de rede em característica agregada**
  (`distinct_users_per_network_24h`) em vez de expor o identificador de
  rede em si no esquema público.

## 4. Verificação de casos atípicos

Estado final (73.528 linhas, duas instituições, 2026-08-12):

- Países com ≤5 eventos: **6** (Suíça 5, Emirados Árabes Unidos 2, Tunísia
  1, Chéquia 1, Japão 1, Egipto 1)
- Utilizador mais activo: **1.846 eventos, 2,51% do total** — reduzido de
  6,1% na primeira amostra, através de diversidade institucional, não de
  supressão
- Inconsistências de nomenclatura conhecidas e corrigidas: variantes de
  nome de país (`"Netherlands"` vs `"The Netherlands"`) — ver
  `COUNTRY_NAME_CANONICAL` em `processed.py`

**Resolvido (2026-08-12)**: `ip_country` no esquema público generaliza
automaticamente qualquer país com ≤5 eventos para `"Other"`
(`RARE_COUNTRY_MAX_EVENTS` em `processed.py`, recalculado a cada
processamento, não uma lista fixa). O país real permanece disponível no
esquema restrito, para análise interna legítima. Nenhuma linha é
removida — só o nível de detalhe do país muda entre os dois esquemas.

## 5. Segunda instituição — já concretizado, não hipotético

Confirmado e implementado (2026-08-12): o conjunto de dados combina agora
duas instituições. Medidas adoptadas:

- **Chaves HMAC separadas por instituição** (`HMAC_SECRET_KEY_<PASTA>`,
  uma por subpasta de `data/raw/`) — implementado e testado
  (`tests/test_processed.py`, secção multi-instituição).
- **Nenhuma coluna de identificação de instituição** no esquema público
  nem restrito — confirmado por teste automático
  (`test_multi_institution_pseudo_ids_do_not_reveal_institution`).
- **Numeração de pseudónimos (`U000001`, `N000001`, ...) é global**,
  atribuída só depois de combinar os dados das duas instituições — nunca
  por instituição, o que evitaria colisões ou, com um prefixo, revelaria
  a proveniência.

**Resultado confirmado com dados reais**: concentração geográfica caiu de
95,68% para 63,15% (Angola), utilizadores distintos subiram de 11.691
para 36.691, dominância do utilizador mais activo caiu de 3,80% para
2,51% — a estratégia funcionou como previsto.

**Nota de processo, para referência futura**: uma primeira extracção da
instituição B usou por engano um filtro que só capturava eventos já
marcados como suspeitos, produzindo uma amostra artificialmente enviesada
(~85% de suspeitos). Detectado antes de qualquer análise, corrigido com
reextracção. Recomendação permanente: confirmar sempre a proporção de
`is_suspicious` no ficheiro bruto de qualquer instituição nova antes de a
combinar com o resto.

Se uma terceira instituição vier a ser adicionada, repetir exactamente o
mesmo procedimento: pasta própria em `data/raw/`, chave HMAC própria,
verificação da proporção de suspeitos no bruto antes de combinar.

## 6. Licença e termos de publicação

Decidido (2026-08-12):
- **Conjunto de dados** (esquema público): Creative Commons
  Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) — permite
  partilha e adaptação com atribuição, exclui uso comercial. Ver
  `LICENSE-DATASET.txt`.
- **Código** (`processed.py`, `benchmark_ml.py`, testes): Licença MIT —
  permissiva, incluindo uso comercial do código (distinta da restrição
  não-comercial que se aplica só aos dados). Ver `LICENSE-CODE.txt`.

Esta separação é deliberada: o código (metodologia, ferramentas de
processamento) beneficia de ficar o mais reutilizável possível, mesmo em
contextos comerciais — mas os dados em si, por conterem informação
comportamental real de pessoas reais, mantêm a restrição não-comercial
como salvaguarda adicional para além da pseudonimização.

**Confirmação adicional (2026-08-12)**: a restrição não-comercial não é
só uma escolha nossa — o `ip-api.com`, usado como recurso de
contingência de geolocalização na extracção, exige explicitamente uso
não comercial no seu nível gratuito ("*the use of the API is strictly
limited for a non-commercial purpose*", `ip-api.com/docs/legal`). Como
parte da geolocalização deste conjunto de dados vem desse serviço, a
licença `CC BY-NC 4.0` não é só apropriada — é necessária para manter a
conformidade com essa fonte.
