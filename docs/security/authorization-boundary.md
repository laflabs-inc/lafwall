# Authorization Boundary

상태: **Accepted Implementation Boundary(승인된 구현 경계)**

정책 기준: [RFC-0002](../rfc/0002-mvp-rbac-matrix.md)

구현 위치: `internal/authorization`

## 목적과 범위

Authorization Boundary는 인증된 Principal, exact Permission, canonical target,
authoritative Role Assignment snapshot을 입력받아 하나의 operation을
deny-by-default로 평가합니다.

Policy package는 transport, Database, OIDC, Service Token verification, log,
network, cache, persistence, Audit write에 의존하지 않습니다. Authentication
성공이나 resource identifier 자체는 Permission을 부여하지 않습니다.

Database Migration, Public API, Production wiring, Audit storage는 이 Slice에
포함하지 않습니다.

## Closed Vocabulary

Policy는 RFC-0002에서 승인한 19개 Permission과 다음 다섯 Role만 인식합니다.

- `tenant_admin`
- `project_admin`
- `secret_editor`
- `secret_accessor`
- `auditor`

Unknown Role·Permission은 확장 지점이 아니라 invalid state이며 fail-closed
처리합니다. `secret:read_value`는 `secret_accessor`만 포함하고 Admin·Editor·
Auditor에는 포함하지 않습니다.

## 입력 계약

### Principal

Application은 Authentication 성공 후 authoritative mapping으로 stable internal
Principal ID와 exact Tenant ID를 resolve해야 합니다. Email, display name,
token prefix, raw credential은 Principal ID가 아닙니다.

Service Principal의 Tenant는 검증된 Service Token의 immutable Tenant와 정확히
일치해야 합니다. Service Principal은 `secret_editor`와 `secret_accessor`만
받을 수 있습니다.

### Scope·Target

Scope는 다음 hierarchy만 사용합니다.

1. Tenant
2. Project
3. Environment

Application은 user input을 이어 붙이지 않고 Tenant-scoped authoritative lookup으로
resource lineage를 resolve한 뒤 `Target`을 생성합니다. Zero·unresolved Target,
malformed lineage, cross-tenant relation은 거부합니다.

Target은 semantic resource kind와 lifecycle snapshot을 함께 포함합니다.
Permission과 resource kind가 다르거나 parent가 archived 상태이면 Role이 있어도
거부합니다. `project:restore`와 `secret:restore`만 exact archived target을
허용합니다.

### Assignment Snapshot

`Policy.Authorize`에는 해당 Principal의 authoritative Assignment value snapshot만
전달합니다. Assignment가 없거나 snapshot에 unknown·malformed·다른 Principal
state가 하나라도 있으면 전체 decision을 거부합니다. Revoked Assignment는
Permission을 추가하지 않습니다.

Sensitive operation마다 최신 Authentication·Assignment·lifecycle state를
다시 평가합니다. MVP Policy는 Authorization result를 cache하지 않습니다.

## Evaluation

Policy는 다음 조건을 모두 만족할 때만 허용합니다.

1. Principal, Permission, Target이 canonical합니다.
2. Principal과 Target Tenant가 exact match입니다.
3. Permission이 Target resource kind와 lifecycle에 유효합니다.
4. 모든 Assignment가 canonical하고 동일한 Principal·Tenant에 속합니다.
5. Assignment Role이 Principal kind와 scope에 허용됩니다.
6. Assignment scope가 Target을 아래 방향으로 포함합니다.
7. 유효한 Role Permission의 합집합에 exact Permission이 존재합니다.

Tenant Assignment는 하위 Project·Environment에 적용됩니다. Project Assignment는
exact Project와 하위 Environment에만 적용되고 Tenant나 sibling Project에는
적용되지 않습니다. Environment Assignment는 exact Environment에만 적용되고
parent Project나 sibling Environment에는 적용되지 않습니다.

## Grant·Revoke Boundary

`Policy.Grant`와 `Policy.Revoke`는 complete authoritative Tenant Assignment
snapshot을 검증하고 proposed immutable value만 반환합니다.

- Active Human `tenant_admin`만 Assignment를 관리할 수 있습니다.
- Actor, recipient, Assignment scope는 같은 Tenant여야 합니다.
- Human·Service Principal eligibility와 Role별 scope를 exact match합니다.
- 마지막 distinct active Human `tenant_admin`은 revoke할 수 없습니다.
- Revoke는 기존 Assignment를 변경하지 않고 revoked copy를 반환합니다.

Policy는 Assignment나 Audit Event를 저장하지 않습니다. 이후 Application·
storage Slice는 성공한 grant·revoke와 필수 Audit Event를 하나의 transaction에
commit하고 Audit persistence 실패 시 전체 operation을 실패시켜야 합니다.

초기 `tenant_admin` bootstrap은 이 Policy의 일반 grant path가 아닙니다. 초기
Tenant·storage baseline을 승인할 때 별도의 제한된 bootstrap contract와
negative integration test를 정의해야 합니다.

## Failure·Sensitive Data

Malformed, unknown, cross-tenant, inactive, insufficient Permission은 모두
`authorization denied`로 반환합니다. Client-facing error는 denial reason이나
resource 존재 여부를 구분하지 않습니다.

Principal, Scope, Assignment, Target, Decision의 routine formatting은 internal
identifier와 Assignment metadata를 redact합니다. Policy는 Secret value,
credential, raw Authorization header, verifier를 입력받지 않습니다.

## 검증 증거

Race-enabled contract test는 다음 경계를 검증합니다.

- 다섯 Role×19 Permission 전체 matrix
- zero value, unknown Role·Permission, malformed scope·lineage
- cross-tenant, parent, sibling, unrelated resource
- Tenant→Project→Environment 하향 scope와 no-upward inheritance
- Admin·Editor·Auditor plaintext access 거부
- `secret_accessor` mutation 거부
- Service Principal Role·scope·Tenant 제한
- Assignment union, immutable revoke, in-flight Decision snapshot
- invalid grant와 마지막 Human `tenant_admin` revoke 거부
- archived parent와 lifecycle precondition
- error·formatting metadata redaction

Database Adapter가 승인된 뒤에는 Tenant-scoped query, concurrent revoke,
transactional Audit failure에 대한 negative integration test를 추가해야 합니다.

## Security Impact Review

- 승인된 Security Invariant를 완화하지 않습니다.
- Administration과 plaintext access를 구조적으로 분리합니다.
- Unknown state와 dependency 미구현 상태는 fail-closed 처리합니다.
- Cryptography, plaintext handling, token verifier를 변경하지 않습니다.
- Database schema·Migration, public contract, Architecture를 변경하지 않습니다.

잔여 위험은 authoritative storage query, concurrent role revocation, atomic Audit
write, initial administrator bootstrap, Production identity mapping이 아직
구현되지 않았다는 점입니다. 이 dependency가 승인·검증되기 전까지 Production
startup은 계속 차단됩니다.
