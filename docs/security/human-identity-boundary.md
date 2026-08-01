# Human Identity Boundary

상태: **Implemented — Slice 2.1(구현됨)**

이 Boundary는 명시적으로 승인된 하나의 issuer가 발급한 OIDC ID Token을
검증하고 immutable issuer·subject claim을 내부 Human Principal로 mapping합니다.
HTTP, session, Database, Public API contract를 만들지 않고 승인된 Identity
Policy를 구현합니다.

## Trust Configuration

`HumanVerifierConfig`는 Token을 처리하기 전에 다음 trust input을 모두
요구합니다.

- user information, query, fragment가 없는 정확한 HTTPS issuer URL
- 정확히 하나의 audience identifier
- 비어 있지 않은 asymmetric signing algorithm allowlist

Configuration은 symmetric MAC algorithm과 `none`을 거부합니다. Verifier를
생성할 때 allowlist를 copy하므로 이후 caller가 값을 변경해 trust 범위를
넓힐 수 없습니다.

Caller는 설정된 issuer가 소유한 public key로 signature를 검증하는 `KeySet`도
제공합니다. `KeySet`은 검증하지 않은 Token claim으로 issuer, discovery URL,
JWKS URL을 선택해서는 안 됩니다. Remote discovery·JWKS retrieval은 이
Slice에서 의도적으로 구현하지 않았습니다.

## Token Validation

Boundary는 JWT·signature primitive를 직접 구현하지 않고 `go-oidc`와
`go-jose`를 사용합니다. 다음 조건을 모두 충족하지 않으면 검증은
fail-closed 처리됩니다.

1. Compact ID Token이 존재하며 16 KiB 이하입니다.
2. Caller가 허용한 asymmetric algorithm으로 signature가 검증됩니다.
3. `iss`가 설정된 issuer와 정확히 일치합니다.
4. `aud`가 정확히 하나의 value만 포함하고 설정된 audience와 정확히
   일치합니다.
5. Optional `azp` claim이 있으면 동일한 audience와 정확히 일치합니다.
6. Duplicate top-level claim이 없습니다.
7. `exp`가 존재하며 현재 시각보다 엄격하게 이후입니다.
8. `iat`가 존재하고 미래가 아니며 `exp`보다 엄격하게 이전입니다.
9. Optional `nbf`가 미래가 아니며 `exp`보다 엄격하게 이전입니다.
10. `sub`가 1~255자의 visible ASCII로 구성됩니다.
11. Flow nonce가 양쪽 모두 없거나 caller가 제공한 expected nonce와 정확히
    일치합니다.

Application Boundary는 clock-skew grace를 추가하지 않습니다. Operator는
Application과 issuer clock을 동기화해야 하며 승인된 provider adapter도 이
time check를 암묵적으로 약화할 수 없습니다.

Expected nonce가 있으면 constant-time으로 비교합니다. Caller가 expected
value를 제공하지 않았는데 Token이 nonce를 포함하면 거부하여 Transport
Adapter가 flow state를 실수로 무시하지 못하게 합니다.

## Principal Mapping

검증에 성공하면 정확한 `(issuer, subject)` pair만으로 식별하는
`HumanPrincipal`을 반환합니다. Email, name, 기타 profile claim은 identity에서
무시합니다. Principal field는 Identity Package 외부에서 construct·modify할 수
없으며 zero value는 유효하지 않습니다.

서로 다른 issuer의 동일한 subject는 서로 다른 Principal로 mapping됩니다.
동일한 issuer·subject의 profile이 바뀌어도 Principal identity는 바뀌지
않습니다.

## Failure·Data Handling Policy

- Raw ID Token은 method input으로만 받고 retain하지 않습니다.
- Authentication, parsing, claim, signature, key, nonce failure는 모두 동일한
  `ErrUnauthenticated` value를 반환합니다.
- Dependency error, claim value, raw Token을 반환하는 error에 wrap하지
  않습니다.
- Caller Context cancellation은 구분할 수 있게 유지하여 Authentication
  failure reason을 노출하지 않으면서 작업을 즉시 중단할 수 있게 합니다.
- 이 Package는 log, persist, telemetry emit, Audit Event 생성을 하지
  않습니다.

Transport Adapter도 Authorization header·Token을 log하지 않아야 합니다.
향후 Audit Event에는 안전한 Principal identifier·outcome만 기록할 수 있으며
raw Authentication material은 기록할 수 없습니다.

## `KeySet` Contract

향후 Remote `KeySet` Adapter는 다음 조건을 충족해야 합니다.

- 승인된 configuration만으로 discovery·JWKS endpoint를 결정합니다.
- Authenticated HTTPS를 요구하고 승인된 Trust Boundary 밖으로 향하는
  redirect를 거부합니다.
- Request deadline, response size limit, bounded refresh behavior, 안전한 key
  caching을 적용합니다.
- Unknown issuer·algorithm을 수락하지 않고 rotation을 처리하며 unknown·
  ambiguous key selection을 거부합니다.
- Concurrent use에 안전하고 caller cancellation을 준수합니다.
- Raw Token을 retain·log하지 않고 Token, key material, response body, 민감한
  provider detail이 없는 error를 반환합니다.

Provider discovery, Production Laf ID value, HTTP Authentication wiring,
readiness integration은 별도 작업입니다. Production startup은 여전히 사용할
수 없습니다.

## 검증 증거

Unit test는 test-only ephemeral RSA key와 synthetic signed Token을 runtime에
생성하여 다음 항목을 검증합니다.

- 성공적인 signature 검증·immutable Principal mapping
- Issuer, audience, `azp`, algorithm, signature, nonce 거부
- Expiry, issued-at, not-before 거부
- Duplicate Security claim·malformed claim type
- Subject boundary·cross-issuer Identity 분리
- Signature 작업 전 input size 제한
- Configuration immutability·fail-closed typed-nil handling
- Sanitized dependency failure·Context cancellation

Token literal·private key는 source, fixture, snapshot, log에 저장하지 않습니다.
이 Slice에는 Database Migration·Public API Change가 없습니다.

## 잔여 위험·보류 작업

- 승인된 Laf ID issuer URL, audience, signing profile, JWKS endpoint를 아직
  설정하지 않았습니다.
- OAuth Authorization redirect, state, PKCE, code exchange, session behavior,
  companion access-token hash validation은 이 internal Token Boundary의 범위
  밖입니다.
- HTTP endpoint는 아직 Human credential을 받지 않습니다.
- Remote provider adapter가 생기기 전까지 key retrieval outage behavior를
  readiness에 반영할 수 없습니다.
- Service Token·deny-by-default Authorization은 각각 Slice 2.2·2.3
  작업입니다.

이 제약 때문에 현재 구현을 Production Identity readiness로 간주할 수
없습니다.
