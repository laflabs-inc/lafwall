# Domain Contract

상태: **Accepted Baseline(승인된 기준선)**

승인일: 2026-07-30

이 문서는 stable HTTP·Database schema가 아닌 Domain의 의미를 정의합니다.
Public API와 Migration은 별도의 approval gate입니다.

## Security Boundary

Persist되는 모든 Domain resource는 정확히 하나의 `Tenant`에 속합니다. 초기
Product experience가 Personal Tenant를 자동으로 생성하고 Organization
관리를 노출하지 않더라도 Tenant는 internal isolation boundary입니다.

어떤 query나 Authorization decision도 user-controlled resource identifier만으로
Tenant를 추론해서는 안 됩니다.

## Core Entity

### Tenant

Resource, Principal, Role Assignment, Audit Record의 최상위 isolation
boundary입니다.

### Principal

인증된 Actor입니다.

- Immutable OIDC issuer·subject로 식별하는 `HumanPrincipal`
- Opaque Service Token으로 인증하는 `ServicePrincipal`

Email, display name, token prefix는 metadata이며 identity proof가 아닙니다.

### Project

연관된 Environment·Secret의 namespace이자 Policy Boundary입니다.

- Immutable ID와 Tenant ID를 가집니다.
- Tenant 안에서 unique한 human-readable slug를 가집니다.
- Archive·restore할 수 있습니다.
- Archive하면 history를 제거하지 않고 하위 resource의 일반 access를
  거부합니다.

### Environment

Project 안에서 분리된 deployment context입니다.

- Immutable ID와 Project ID를 가집니다.
- Development, Staging, Production을 초기 기본값으로 생성합니다.
- MVP 동안 Development, Staging, Production의 이름을 변경하거나 제거할 수
  없습니다.
- Custom Environment는 MVP 범위 밖입니다.

### Secret

하나의 Environment에 속한 logical Secret key입니다.

- Immutable ID를 가집니다.
- Environment 안에서 unique한 canonical key를 가집니다.
- Metadata·lifecycle state만 저장하며 plaintext value는 저장하지 않습니다.
- 현재 immutable Version을 참조합니다.

### SecretVersion

하나의 logical Secret에 속한 immutable encrypted value입니다.

- Immutable ID와 단조롭게 할당되는 sequence를 가집니다.
- Encryption Envelope과 안전한 creation metadata를 포함합니다.
- 생성 후 수정할 수 없습니다.
- Historical access는 별도로 authorize·audit합니다.

### RoleAssignment

정의된 Tenant, Project, Environment scope에서 Principal에게 승인된 role을
부여합니다. [RFC-0002](../rfc/0002-mvp-rbac-matrix.md)의 하향 scope와
Principal eligibility를 따르며 Grant가 없으면 거부합니다.

### ServiceToken

`ServicePrincipal`의 Authentication credential입니다.

- Plaintext는 한 번만 표시합니다.
- Persistent state에는 public identifier, non-reversible verifier, scope,
  expiry, status, 안전한 operational metadata만 저장합니다.
- Authoritative verification boundary에서 revocation을 즉시 적용합니다.

### AuditEvent

Security-relevant attempt나 완료된 action의 append-only record입니다.

- Stable identifier, outcome, time, correlation, 안전한 context를 포함합니다.
- Secret plaintext, credential, raw Authorization data, Wrapped Key material을
  포함하지 않습니다.

## Lifecycle Rule

1. Secret 생성은 Version `1`을 atomic하게 생성합니다.
2. Value 변경은 새 Version을 append하며 과거 Version을 수정하지 않습니다.
3. Metadata read는 Secret value를 decrypt하지 않습니다.
4. Plaintext access는 별도로 authorize·audit하는 명시적인 Use Case입니다.
5. Archive·soft deletion은 recovery·Audit history를 보존하면서 일반 access를
   제거합니다.
6. State-changing transaction과 필수 success Audit Event는 함께 commit합니다.
7. 개별 ID가 존재하더라도 cross-tenant relationship은 유효하지 않습니다.
8. Parent archive·deletion은 승인된 lifecycle policy에 따라 하위 resource의
   access를 제한합니다.

## Permission Vocabulary Boundary

MVP는 fine-grained Permission 위에 RFC-0002의 다섯 고정 Role을 사용합니다.
정확한 Role matrix, scope, Principal eligibility, grant·revoke rule은 승인된
[RFC-0002](../rfc/0002-mvp-rbac-matrix.md)가 규범적인 계약입니다. Policy는
다음 action만 사용합니다.

- `project:create`, `project:read`, `project:update`, `project:archive`,
  `project:restore`
- `environment:read`
- `secret:create`, `secret:read_metadata`, `secret:write_version`
- `secret:read_value`, `secret:read_history`, `secret:archive`, `secret:restore`
- `service_token:create`, `service_token:read_metadata`,
  `service_token:revoke`
- `role_assignment:read`, `role_assignment:manage`
- `audit:read`

`secret:read_value`는 의도적으로 Project administration·metadata access와
분리합니다.

## Storage에서 강제할 Invariant

- Tenant ownership은 non-null·immutable입니다.
- Project slug는 Tenant 안에서 unique합니다.
- Environment identifier는 Project 안에서 unique합니다.
- Secret canonical key는 Environment의 active Secret 사이에서 unique합니다.
- Version sequence는 Secret 안에서 unique하며 단조롭게 증가합니다.
- Historical Version·Audit Event는 runtime role로 수정할 수 없습니다.
- Current Version reference는 다른 Secret을 가리킬 수 없습니다.
- Role Assignment scope는 Principal의 Tenant boundary를 넘을 수 없습니다.
