# RFC-0002: MVP Deny-by-default RBAC Matrix

- 상태: **Accepted(승인됨)**
- 작성일: 2026-08-01
- 승인일: 2026-08-01
- 결정 주체: LafLabs

이 RFC는 Laf Secrets MVP의 규범적인 RBAC 계약입니다. Permission·Role·scope·
grant rule을 변경하려면 후속 Security Policy 승인과 contract regression
test가 필요합니다.

## 요약

Laf Secrets MVP는 fine-grained internal Permission 위에 다음 다섯 개의 고정
Role을 제공합니다.

- `tenant_admin`
- `project_admin`
- `secret_editor`
- `secret_accessor`
- `auditor`

`secret:read_value`는 `secret_accessor`에만 포함합니다. Tenant·Project
Administration, Secret write, Audit read는 plaintext access를 암시하지
않습니다. Custom Role, explicit deny, approval workflow, Organization 관리,
per-Secret ACL은 MVP 범위 밖입니다.

## 목표

1. 정확한 Permission vocabulary와 Role matrix를 고정합니다.
2. Tenant, Project, Environment scope의 하향 적용 규칙을 고정합니다.
3. Human·Service Principal이 받을 수 있는 Role을 제한합니다.
4. Role grant 자체를 privilege-escalation boundary로 다룹니다.
5. Transport·Database와 독립적으로 test할 수 있는 deny-by-default Policy를
   정의합니다.

## Non-goal

이 RFC는 다음 항목을 승인하지 않습니다.

- Database schema·Migration·index·transaction layout
- Public REST·OpenAPI request 또는 response schema
- Dashboard·CLI의 Role 관리 UX
- Custom Role·custom Permission·explicit deny
- Organization·Group·Team membership
- Dual approval, time-bound elevation, break-glass access
- Production Identity·storage·Audit wiring

## 설계 원칙

1. Authentication 성공은 어떤 action도 허용하지 않습니다.
2. Permission이 matrix와 유효한 Role Assignment에 명시되지 않으면
   거부합니다.
3. Administrative Role은 `secret:read_value`를 포함하지 않습니다.
4. Resource ID만으로 Tenant·parent scope를 추론하지 않습니다.
5. Scope는 아래로만 적용하며 parent·sibling으로 올라가거나 이동하지
   않습니다.
6. Domain lifecycle, Authentication state, Tenant isolation은 Role보다 먼저
   적용되며 Role로 우회할 수 없습니다.
7. Role·Permission·scope가 unknown 또는 malformed이면 fail-closed
   처리합니다.

## Permission Vocabulary

Permission은 version 없는 internal identifier입니다. 이름이나 의미가
바뀌면 이 RFC의 후속 승인과 contract regression test가 필요합니다.

<!-- markdownlint-disable MD013 -->

| Resource | Permission | 의미 |
| --- | --- | --- |
| Project | `project:create` | Tenant 안에 Project와 고정 Environment를 atomic하게 생성 |
| Project | `project:read` | 허용된 scope의 Project metadata read·list |
| Project | `project:update` | 허용된 Project metadata 변경 |
| Project | `project:archive` | Project와 하위 resource의 일반 access 차단 |
| Project | `project:restore` | Archive된 Project를 승인된 lifecycle로 복구 |
| Environment | `environment:read` | 허용된 Environment metadata read·list |
| Secret | `secret:create` | Environment에 Logical Secret과 첫 Version 생성 |
| Secret | `secret:read_metadata` | Value를 decrypt하지 않는 metadata read·list |
| Secret | `secret:write_version` | 기존 Version을 변경하지 않고 새 Version append |
| Secret | `secret:read_value` | 명시적으로 선택한 현재·과거 Version plaintext reveal |
| Secret | `secret:read_history` | Value를 decrypt하지 않는 Version history read |
| Secret | `secret:archive` | Logical Secret의 일반 read·reveal 차단 |
| Secret | `secret:restore` | Archive된 Logical Secret을 승인된 lifecycle로 복구 |
| Service Token | `service_token:create` | Tenant-scoped opaque Token 발급 |
| Service Token | `service_token:read_metadata` | Credential을 제외한 Token metadata read·list |
| Service Token | `service_token:revoke` | Token을 즉시 revoke |
| Role Assignment | `role_assignment:read` | 허용된 scope의 Assignment metadata read·list |
| Role Assignment | `role_assignment:manage` | 승인된 grant rule 안에서 Assignment 생성·revoke |
| Audit | `audit:read` | 허용된 scope의 안전한 Audit Event read·list |

<!-- markdownlint-enable MD013 -->

MVP의 Development, Staging, Production Environment는 `project:create`의
내부 결과로만 생성합니다. Custom Environment와 Environment rename·delete는
허용하지 않으므로 `environment:create`와 `environment:update`는
Principal에게 grant할 Permission에서 제거합니다.

`project:restore`와 `secret:restore`는 승인된 recoverable deletion semantics를
명시하기 위해 기존 Domain vocabulary에 추가합니다. 영구 파기는 별도의
Security Policy 승인 전까지 Permission으로 제공하지 않습니다.

## 고정 Role

<!-- markdownlint-disable MD013 -->

| Role | Principal | Assignment scope | 목적 |
| --- | --- | --- | --- |
| `tenant_admin` | Human only | Tenant only | Tenant 전체의 non-plaintext Administration과 RBAC 관리 |
| `project_admin` | Human only | Project only | 하나의 Project와 하위 resource의 non-plaintext Administration |
| `secret_editor` | Human·Service | Project·Environment | Secret metadata·Version lifecycle write |
| `secret_accessor` | Human·Service | Project·Environment | 명시적인 Secret value read-only access |
| `auditor` | Human only | Tenant·Project·Environment | Mutation·plaintext 없이 metadata·Audit 확인 |

<!-- markdownlint-enable MD013 -->

Service Principal은 `secret_editor`와 `secret_accessor`만 받을 수 있습니다.
Service Token으로 Tenant·Project Administration, RBAC 관리, Audit collection을
수행하는 기능은 실제 운영 요구와 별도 Threat Review 전까지 제공하지
않습니다.

## Role·Permission Matrix

`허용`은 Role이 Permission을 포함한다는 뜻입니다. 실제 허용에는 아래의
scope matching, Principal eligibility, lifecycle, grant rule도 모두
충족해야 합니다.

<!-- markdownlint-disable MD013 -->

| Permission | `tenant_admin` | `project_admin` | `secret_editor` | `secret_accessor` | `auditor` |
| --- | --- | --- | --- | --- | --- |
| `project:create` | 허용 | — | — | — | — |
| `project:read` | 허용 | 허용 | 허용 | 허용 | 허용 |
| `project:update` | 허용 | 허용 | — | — | — |
| `project:archive` | 허용 | 허용 | — | — | — |
| `project:restore` | 허용 | 허용 | — | — | — |
| `environment:read` | 허용 | 허용 | 허용 | 허용 | 허용 |
| `secret:create` | 허용 | 허용 | 허용 | — | — |
| `secret:read_metadata` | 허용 | 허용 | 허용 | 허용 | 허용 |
| `secret:write_version` | 허용 | 허용 | 허용 | — | — |
| `secret:read_value` | — | — | — | 허용 | — |
| `secret:read_history` | 허용 | 허용 | 허용 | 허용 | 허용 |
| `secret:archive` | 허용 | 허용 | 허용 | — | — |
| `secret:restore` | 허용 | 허용 | 허용 | — | — |
| `service_token:create` | 허용 | — | — | — | — |
| `service_token:read_metadata` | 허용 | — | — | — | 허용 |
| `service_token:revoke` | 허용 | — | — | — | — |
| `role_assignment:read` | 허용 | 허용 | — | — | 허용 |
| `role_assignment:manage` | 허용 | — | — | — | — |
| `audit:read` | 허용 | 허용 | — | — | 허용 |

<!-- markdownlint-enable MD013 -->

`tenant_admin`과 `project_admin`은 Secret을 생성·교체·archive할 수 있지만
기존 plaintext를 reveal할 수 없습니다. Value access가 필요하면 별도의
`secret_accessor` Assignment가 존재해야 합니다. 이 Assignment는 독립된
mutation·Audit Event이며 같은 reveal request 안에서 암묵적으로 만들 수
없습니다.

## Scope Model

모든 Assignment는 non-null Tenant ID와 정확히 하나의 scope를 가집니다.

- Tenant scope: 해당 Tenant와 그 아래 모든 Project·Environment·Secret
- Project scope: exact Project와 그 아래 Environment·Secret
- Environment scope: exact Environment와 그 아래 Secret

Scope는 하향으로만 적용합니다. Environment Assignment는 parent Project나
sibling Environment를 authorize하지 않습니다. Project Assignment는 Tenant
resource나 다른 Project를 authorize하지 않습니다.

Secret Version은 parent Secret의 canonical Environment scope를 사용합니다.
Audit Event는 기록된 target resource의 canonical scope를 사용합니다.
Tenant-level event는 Tenant scope Assignment로만 read할 수 있습니다.

Target의 Tenant·Project·Environment lineage는 user input을 조합해 만들지
않습니다. Application은 Tenant-scoped authoritative lookup으로 immutable
lineage를 resolve한 뒤 Policy에 전달해야 합니다. Missing·ambiguous·
cross-tenant lineage는 존재 여부를 노출하지 않는 동일한 denial로
처리합니다.

### Operation별 Target

- `project:create`의 target은 Tenant입니다.
- Project Permission의 target은 exact Project입니다.
- Environment Permission의 target은 exact Environment입니다.
- Secret·Version Permission의 target은 exact Secret의 Environment
  lineage입니다.
- Service Token Permission의 target은 Token의 immutable Tenant입니다.
- Role Assignment Permission의 target은 조회·변경할 Assignment scope입니다.
- `audit:read`의 target은 각 Audit Event의 canonical resource scope입니다.

List operation도 같은 규칙을 사용합니다. Storage query는 허용된 Tenant와
scope로 결과를 제한하고, 반환하는 각 item도 동일한 Permission을 만족해야
합니다. Filter 전 row count나 다른 scope의 존재를 노출하지 않습니다.

## Permission Evaluation

Authorization은 다음 순서로 평가합니다.

1. 유효한 Human·Service Principal인지 확인합니다.
2. Service Principal이면 immutable Token Tenant와 요청 Tenant가 정확히
   일치하는지 확인합니다.
3. Target resource를 명시적인 Tenant-scoped lookup으로 resolve합니다.
4. Principal·Tenant의 authoritative active Role Assignment를 읽습니다.
5. Role, Principal eligibility, Assignment scope가 모두 canonical한지
   검증합니다.
6. Target을 포함하는 Assignment의 Permission을 합집합으로 계산합니다.
7. exact action이 존재하고 Domain lifecycle precondition도 성공할 때만
   허용합니다.

Assignment가 없거나 하나라도 unknown·malformed·cross-tenant state이면
fail-closed 처리합니다. 여러 유효한 Assignment의 Permission은 합칠 수
있지만 Role inheritance와 explicit deny는 사용하지 않습니다.

Archived parent, expired·revoked Authentication, invalid resource relation,
required Audit persistence failure는 Permission보다 우선합니다. Role은 이
상태를 우회할 수 없습니다.

## Role Grant·Privilege Escalation Rule

1. `tenant_admin` Human만 `role_assignment:manage`를 가집니다.
2. Assignment actor와 recipient, target scope는 같은 Tenant에 속해야 합니다.
3. `tenant_admin`은 Human에게 모든 고정 Role을 grant할 수 있습니다.
4. Service Principal에는 `secret_editor`·`secret_accessor`만 grant할 수
   있습니다.
5. `tenant_admin`은 Tenant scope에만, `project_admin`은 Project scope에만
   grant할 수 있습니다.
6. `secret_editor`·`secret_accessor`는 Project·Environment scope에만 grant할
   수 있습니다.
7. `auditor`는 Tenant·Project·Environment scope에 grant할 수 있습니다.
8. Active Human `tenant_admin`이 한 명도 남지 않게 revoke할 수 없습니다.
9. Assignment는 immutable record로 생성·revoke하며 Role·Principal·scope를
   in-place update하지 않습니다.
10. 성공한 grant·revoke와 필수 Audit Event는 하나의 transaction에
    commit하며 Audit persistence가 실패하면 전체 operation을 실패시킵니다.

`project_admin`, `secret_editor`, `secret_accessor`, `auditor`, Service
Principal은 Assignment를 관리할 수 없습니다. 따라서 Project editor나
administrator가 자신에게 plaintext access를 부여하는 path는 없습니다.

`tenant_admin`은 Personal Tenant 운용을 위해 자신에게 별도의
`secret_accessor`를 grant할 수 있습니다. 그러나 이는 독립된 명시적
mutation으로 기록·audit되며 현재 진행 중인 reveal operation에는 적용되지
않습니다. Dual approval·time-bound elevation은 실제 조직 수요가 확인된 뒤
별도 Security Review로 추가합니다.

## Failure·Sensitive Data Policy

- Anonymous, unknown action, unknown Role, invalid scope, insufficient
  Permission은 하나의 sanitized Authorization denial로 반환합니다.
- Error, log, metric, trace에는 Secret value, credential, raw Authorization
  header, verifier, Role Assignment 전체 내용을 포함하지 않습니다.
- Denial reason은 Client에 세분화하지 않습니다. Internal Audit Event에는
  allowlist된 actor reference, action, target reference, Tenant, outcome,
  correlation, time만 기록할 수 있습니다.
- Policy Package는 log·persist·network·Audit write를 직접 수행하지 않습니다.
  Application Use Case가 승인된 transaction boundary를 책임집니다.
- Authorization result를 Authentication·Role revocation보다 오래 cache하지
  않습니다. MVP에서는 sensitive operation마다 authoritative state를 다시
  평가합니다.

## Contract Test 요구 사항

Slice 2.3 구현은 최소한 다음 test를 포함해야 합니다.

1. 모든 Role×Permission 조합을 matrix와 대조하는 table-driven contract test
2. Anonymous·zero value·unknown Role·unknown action·malformed scope 거부
3. Cross-tenant, parent, sibling, unrelated resource 거부
4. Tenant→Project→Environment 하향 scope와 no-upward inheritance 검증
5. Admin·Editor·Auditor의 `secret:read_value` 거부
6. `secret_accessor`의 모든 mutation 거부
7. Service Principal Role·scope eligibility와 Tenant mismatch 거부
8. Assignment union이 명시된 Permission만 추가함을 검증
9. Last Human `tenant_admin` revoke와 invalid grant 거부
10. Role change가 in-flight decision에 소급 적용되지 않음을 검증
11. Archived parent와 invalid resource lineage가 Role보다 우선함을 검증
12. Error·formatting·decision metadata의 sensitive field redaction 검증

Database Adapter가 추가되면 Tenant-scoped query, concurrent revoke, atomic
Audit write에 대한 negative integration test를 별도로 추가해야 합니다.

## Security Impact·Trade-off

### 장점

- Plaintext access가 Administration·write·Audit 권한과 구조적으로 분리됩니다.
- Service Token이 Control Plane Administration으로 승격되지 않습니다.
- 다섯 개 고정 Role로 Review·문서·지원 surface를 제한합니다.
- Explicit deny나 Role inheritance의 충돌 없이 deterministic하게 평가합니다.
- Project administrator의 self-escalation path를 제거합니다.

### 비용과 잔여 위험

- `tenant_admin`에게 Role 관리가 집중되어 큰 Team에서는 병목이 될 수
  있습니다.
- `tenant_admin`은 별도 Assignment를 통해 자신에게 value access를 부여할 수
  있습니다. MVP는 이를 명시적이고 audit 가능한 operation으로 만들지만
  dual control을 제공하지 않습니다.
- `project_admin`이 Service Token을 직접 발급하거나 Role을 위임할 수 없어
  Tenant Administrator의 작업량이 늘어납니다.
- 고정 Role만으로 일부 Team의 세밀한 직무 분리를 표현할 수 없습니다.

이 제약은 MVP의 단순성·검증 가능성·least privilege를 위해 수용합니다.
실제 운영 evidence 없이 Custom Role이나 예외 Permission을 추가하지
않습니다.

## 검토한 대안

### `owner`·`admin`·`viewer`의 세 가지 broad Role

간단하지만 Secret plaintext, metadata, write, RBAC 권한이 broad Role에
섞여 Security Invariant를 약화하므로 채택하지 않습니다.

### MVP부터 Custom Role 제공

권한 조합, escalation, migration, UI, support surface가 급격히 커지고 현재
수요가 증명되지 않아 채택하지 않습니다.

### Per-Secret ACL

세밀하지만 Assignment 수, query complexity, Audit surface가 증가합니다.
MVP는 Environment를 가장 작은 Assignment scope로 사용합니다.

### Explicit deny·Role inheritance

정책 충돌 순서와 effective Permission 설명을 복잡하게 만듭니다. MVP는
고정 Role Permission의 합집합과 fail-closed Domain constraint만 사용합니다.

## 승인 범위

LafLabs는 다음 범위를 명시적으로 승인했습니다.

1. 상태를 `Accepted`로 변경하고 승인일을 기록합니다.
2. `docs/decisions-required.md`의 D7 gate를 해결합니다.
3. Roadmap Slice 2.3에서 transport·Database와 독립적인 Authorization Policy와
   contract test를 구현합니다.

승인은 Database Migration, Public API, Production wiring, Audit storage를
승인하지 않습니다.
