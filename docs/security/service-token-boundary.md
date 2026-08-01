# Service Token Boundary

상태: **Implemented — Slice 2.2(구현됨)**

이 Boundary는 Workload용 opaque Service Token을 발급하고, immutable Tenant
scope·authoritative lifecycle state에 대해 인증합니다. Database, HTTP,
Public API, 최종 RBAC Permission Matrix를 만들지 않고 승인된
Authentication·Token Invariant를 구현합니다.

Service Token 인증은 어떤 resource action도 허용하지 않습니다. 인증에
성공해도 Slice 2.3의 deny-by-default Authorization Policy가 명시적으로
Permission을 부여하기 전에는 모든 operation을 거부해야 합니다.

## Credential Format·Entropy

Credential은 version marker, public Token ID, secret component로 구성된
opaque value입니다.

- Token ID: CSPRNG가 생성한 128 bit
- Secret component: CSPRNG가 생성한 256 bit
- Encoding: padding 없는 Base64URL
- Version marker: `lafst_v1`

Format은 credential lookup과 안전한 migration을 위한 내부 versioning입니다.
Client가 Token 구조를 해석하거나 identifier만으로 권한을 추론해서는 안
됩니다. `SafePrefix`는 version marker와 public ID 앞 8자만 포함하는 표시용
metadata이며 Authentication이나 Authorization에 사용할 수 없습니다.

`Issuer`는 Go standard library의 `crypto/rand.Reader`만 사용합니다. 매
발급마다 새로운 ID와 secret을 생성하며 zero entropy, short read, dependency
failure, cancellation은 fail-closed 처리합니다. Random dependency detail은
error에 포함하지 않습니다.

## Non-reversible Verifier

Persistent `Record`에는 plaintext credential이나 secret component를 넣지
않습니다. Verifier는 다음 입력을 Go standard library SHA-256으로 digest한
32-byte value입니다.

1. versioned domain separator
2. public Token ID
3. 256-bit random secret component

이 credential은 password가 아니라 256-bit CSPRNG secret이므로 offline
guessing을 방어하기 위한 entropy를 자체적으로 가집니다. Password KDF나
직접 구현한 cryptographic primitive를 추가하지 않습니다. Authentication
Boundary는 candidate verifier와 stored verifier를 constant-time으로
비교합니다.

Verifier, Token ID, lifecycle metadata도 민감한 persistent state로
취급합니다. `Record`와 `ServicePrincipal`의 일반 formatting은 내용을
redact하며, log·telemetry는 별도의 allowlist field만 사용해야 합니다.

## Persistent Record Contract

향후 Storage Adapter는 다음 state만 persist할 수 있습니다.

- public Token ID와 display-only `SafePrefix`
- non-reversible verifier
- immutable Tenant scope
- `active`·`revoked` status
- creation·expiry·revocation·last-used time
- 별도로 승인된 안전한 operational metadata

Plaintext credential, secret component, raw Authorization header, reversible
derivative는 Database, backup, Audit Event, log, error, metric, trace에 저장할
수 없습니다.

현재 Slice는 초기 Database schema나 Migration을 만들지 않습니다. Storage
representation과 index, transaction, retention policy는 Database baseline
approval 뒤에 정합니다.

## Issuance·One-time Reveal

`Issuer.Issue`는 persistent `Record`와 plaintext credential을 한 번의 return
boundary에서 분리합니다. Caller는 다음 조건을 지켜야 합니다.

1. Credential을 생성 response에서 한 번만 전달합니다.
2. Delivery가 실패해도 동일 credential을 다시 조회하지 않습니다. 새 Token을
   발급해야 합니다.
3. Credential을 log, Audit, telemetry, retry payload, background job에
   전달하지 않습니다.
4. Persistent write와 필수 success Audit Event를 atomic하게 commit하기 전에는
   issuance를 성공으로 표시하지 않습니다.

HTTP response schema와 retry semantics는 초기 Public API approval 전까지
보류합니다.

## Authentication·Tenant Scope

`Authenticator.AuthenticateForTenant`는 caller가 authoritative storage에서
방금 읽은 `Record`를 받아 다음 조건을 모두 검사합니다.

1. Credential format·encoding·length가 canonical합니다.
2. Public Token ID와 verifier가 정확히 일치합니다.
3. Record가 `active`이며 revoked state가 없습니다.
4. 현재 시각이 creation 이상, expiry 미만입니다.
5. Clock이 이전 `last-used`보다 뒤로 이동하지 않았습니다.
6. 요청의 Tenant ID가 immutable Token scope와 정확히 일치합니다.

성공하면 immutable `ServicePrincipal`과 갱신된 last-used metadata를
반환합니다. Principal은 Token ID·Tenant ID만 포함하며 Permission을 포함하지
않습니다. Resource ID만으로 Tenant를 추론하거나 다른 Tenant로 scope를
넓힐 수 없습니다.

Malformed, unknown, wrong-secret, wrong-tenant, expired, revoked credential은
모두 동일한 `ErrUnauthenticated`를 반환합니다. Raw credential, Token ID,
Tenant ID, verifier, lifecycle failure reason은 error에 포함하지 않습니다.
Caller cancellation만 별도로 유지합니다.

## Revocation·Concurrency Contract

`Record.Revoke`는 input을 변경하지 않고 immutable revoked state를 반환합니다.
Revocation time은 creation·last-used보다 빠를 수 없으며 이미 revoked된
Record의 처리는 idempotent합니다.

Storage Adapter가 추가되면 Authentication은 active state를 cache하지 않고
authoritative Record를 매번 확인해야 합니다. 성공한 last-used update는 읽은
active Record의 동일 revision에 조건부로 commit해야 합니다. 그 사이
revocation이 commit되면 update와 Authentication 전체가 실패해야 하므로
revocation이 항상 우선합니다.

Issuance, successful use, denied use, revocation은 승인된 Audit Policy에 따라
안전한 identifier·outcome만 기록해야 합니다. Token lifecycle state와 필수
Audit Event의 transaction wiring은 Storage·Audit Slice 전까지 보류합니다.

## 검증 증거

Race detector가 활성화된 Unit Test는 다음 항목을 검증합니다.

- 발급마다 새로운 Token ID·secret·verifier 생성
- canonical Base64URL format과 display-only prefix
- exact credential·Tenant scope Authentication
- plaintext credential과 secret component가 `Record`에 남지 않음
- `Record`·`ServicePrincipal` formatting redaction
- malformed, padding, invalid encoding, wrong ID·secret, unknown Record 거부
- expiry, revocation, wrong Tenant, clock rollback 거부
- constant-time verifier comparison을 사용하는 exact-secret boundary
- immutable last-used update·revocation과 idempotency
- sanitized entropy failure·Authentication error와 Context cancellation

Test entropy는 `_test.go`에서만 주입되며 runtime build에서 deterministic
generator를 선택할 수 없습니다. Source, fixture, snapshot에는 실제 Token이나
고정된 plaintext credential을 포함하지 않습니다.

## 잔여 위험·보류 작업

- Go `string`으로 반환한 credential memory를 안정적으로 zeroize할 수
  없습니다. Caller는 수명과 copy를 최소화해야 합니다.
- Database Adapter가 없으므로 authoritative lookup, conditional last-used
  update, atomic Audit write는 아직 runtime에 연결되지 않았습니다.
- Token TTL 상한·발급 quota·rate limit은 Public API·운영 Policy 전에 별도로
  확정해야 합니다. Expiry 자체는 모든 발급에 필수입니다.
- 정확한 Permission, role, Project·Environment scope inheritance는 Slice
  2.3의 승인된 RBAC RFC 전까지 구현하지 않습니다.
- Production endpoint는 아직 Service Token을 받지 않으며 Production startup은
  계속 fail-closed 상태입니다.

이 제약 때문에 현재 구현을 Production-ready credential service로 간주할 수
없습니다.
