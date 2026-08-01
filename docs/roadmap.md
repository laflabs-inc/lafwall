# Laf Secrets Roadmap

## Roadmap 원칙

- 한 번에 하나의 Slice만 진행합니다.
- 다음 Slice로 이동하기 전에 Review, test, 문서, Security evidence를
  완료합니다.
- 필수 Architecture, storage, public API, Security decision이 승인되지 않은
  상태에서는 구현을 시작하지 않습니다.
- 구현이 간단해 보여도 Roadmap에서 제외한 기능은 정해진 단계 전까지 범위에
  포함하지 않습니다.

## Phase 0 — Security·Architecture Baseline

상태: **완료**

### Slice 0.1 — Product·Security Boundary

- [x] MVP와 non-MVP 범위를 기록합니다.
- [x] 초기 Threat Model을 작성합니다.
- [x] 변경할 수 없는 Security Invariant를 작성합니다.
- [x] 초기 Domain Contract를 작성합니다.
- [x] API-first Modular Monolith ADR을 작성합니다.
- [x] `docs/decisions-required.md`의 결정을 해결하고 승인합니다.
- [x] 승인된 ADR, RFC, Security 문서, Domain Contract를 baseline으로
  확정합니다.

완료 증거:

- Trust boundary, 보호 자산, 주요 위협이 명시되어 있습니다.
- 사용자 승인이 필요한 Architecture·public contract 결정을 암묵적으로
  가정하지 않고 기록했습니다.
- Production code는 Proposed decision에 의존하지 않습니다.

## Phase 1 — 실행 가능한 Security Foundation

상태: **완료**

### Slice 1.1 — Repository·품질 기반

상태: **완료**

- [x] 승인된 Backend workspace를 구성합니다.
- [x] Format, lint, unit test, integration test, dependency audit, Secret scan
  명령을 추가합니다.
- [x] Remote repository 연결 후 CI를 추가합니다.
- [x] Production-safe validation이 적용된 configuration parsing을 추가합니다.
- [x] 민감한 상태를 노출하지 않는 health·readiness 동작을 추가합니다.

완료 증거:

- Standard library 중심의 Go service가 승인된 module workspace에서
  build됩니다.
- Unit·integration test가 configuration 거부, readiness fail-closed,
  probe response 최소화, readiness lifecycle을 검증합니다.
- CI가 read-only permission으로 format, vet, race test, dependency audit,
  Gitleaks worktree·history scan을 실행합니다.
- 필수 Security dependency와 approval gate가 완료되기 전까지 Production
  startup은 차단됩니다.
- Operational probe는 version이 없고 cache할 수 없으며 body가 없고 public
  REST contract에 포함되지 않습니다.

### Slice 1.2 — Encryption Boundary

상태: **완료**

- [x] `KekProvider` port와 Production provider 계약을 정의합니다.
- [x] Test-only deterministic fake를 구현합니다.
- [x] Versioned canonical AAD를 사용하는 AES-256-GCM Envelope Encryption을
  구현합니다.
- [x] Secret Version마다 하나의 DEK를 강제합니다.
- [x] Known-answer, tamper, wrong-context, provider-failure test를 추가합니다.
- [x] Plaintext와 unwrapped DEK가 persist·log되지 않음을 증명합니다.

완료 증거:

- Encryption과 decryption은 fail-closed 처리됩니다.
- Ciphertext를 다른 Tenant, Project, Environment, Secret, Version context로
  이동할 수 없습니다.
- Production startup은 test·local-only key provider를 거부합니다.
- [Encryption Boundary](security/encryption-boundary.md)에 format, provider
  contract, 검증 증거, 잔여 위험을 기록했습니다.

## Phase 2 — Identity·Authorization Foundation

상태: **완료**

### Slice 2.1 — Human Identity Boundary

상태: **완료**

- [x] 승인된 issuer의 OIDC Token을 검증합니다.
- [x] Immutable issuer·subject identifier를 내부 Principal로 mapping합니다.
- [x] 모호한 issuer, audience, time, signature 상태를 거부합니다.

완료 증거:

- 고정된 검토 대상 library가 명시적인 asymmetric algorithm allowlist 아래서
  서명된 ID Token을 검증합니다.
- Exact issuer, single audience, authorized party, time, subject, nonce, token
  size, duplicate claim 검사가 하나의 sanitized error 뒤에서 fail-closed
  처리됩니다.
- Human Principal은 immutable `(issuer, subject)` identity만 포함하며 profile
  claim은 identity를 변경할 수 없습니다.
- Race detector가 활성화된 test가 유효한 signature와 claim, algorithm,
  signature, nonce, dependency, cross-issuer 거부를 검증합니다.
- [Human Identity Boundary](security/human-identity-boundary.md)에 trust
  configuration, `KeySet` contract, 검증 증거, 보류된 Production wiring을
  기록했습니다.

### Slice 2.2 — Service Token

상태: **완료**

- [x] Entropy가 높은 opaque Token을 발급하고 plaintext는 한 번만
  표시합니다.
- [x] Non-reversible verifier와 Token metadata만 persistent state로
  분리합니다.
- [x] Expiry, revocation, last-used metadata, exact Tenant scope를
  지원합니다.
- [x] 권한을 부여하지 않는 안전한 Token prefix로 credential을 식별합니다.

완료 증거:

- 매 발급마다 CSPRNG 기반 128-bit public ID와 256-bit secret을 새로
  생성합니다.
- Persistent `Record`는 domain-separated SHA-256 verifier만 보유하고 plaintext
  credential·secret component를 보유하지 않습니다.
- Candidate verifier를 constant-time으로 비교하고 malformed, unknown,
  wrong-secret, wrong-tenant, expired, revoked 상태를 하나의 sanitized error로
  거부합니다.
- Authentication은 immutable Tenant scope를 강제하지만 Permission을 부여하지
  않습니다. 모든 resource action은 별도의 deny-by-default Authorization
  decision을 요구합니다.
- Last-used·revocation lifecycle은 immutable value transition이며 concurrent
  revocation이 우선해야 하는 future storage contract를 명시합니다.
- Race-enabled Unit Test가 fresh entropy, format, exact match, scope, expiry,
  revocation, clock rollback, redaction, failure sanitization을 검증합니다.
- [Service Token Boundary](security/service-token-boundary.md)에 format,
  verifier, one-time reveal, storage·concurrency contract, 보류된 Production
  wiring을 기록했습니다.
- Database Migration, Public API, RBAC matrix, Production runtime wiring은
  추가하지 않았습니다.

### Slice 2.3 — Deny-by-default RBAC

상태: **완료**

- [x] [RFC-0002](rfc/0002-mvp-rbac-matrix.md)의 정확한 Role·Permission·scope·
  grant rule을 Review하고 승인합니다.
- [x] 승인된 최소 Role·Permission을 closed vocabulary로 정의합니다.
- [x] Principal·Tenant·canonical resource scope를 평가하는 독립 Policy를
  구현합니다.
- [x] Permission matrix와 negative contract test를 추가합니다.

완료 증거:

- 다섯 Role×19 Permission 전체 matrix를 table-driven contract test로
  검증합니다.
- Anonymous, zero value, unknown Role·action, cross-tenant, parent, sibling,
  revoked Assignment, archived parent, insufficient scope는 하나의 sanitized
  denial로 거부됩니다.
- Tenant→Project→Environment 하향 scope만 적용하며 no-upward inheritance를
  검증합니다.
- Admin·Editor·Auditor는 `secret:read_value`를 받지 않고 Service Principal은
  `secret_editor`·`secret_accessor`만 받을 수 있습니다.
- Grant·revoke는 immutable value transition이며 마지막 distinct Human
  `tenant_admin` revoke를 거부합니다.
- [Authorization Boundary](security/authorization-boundary.md)에 Policy 입력,
  evaluation, redaction, 보류된 storage·Audit contract를 기록했습니다.
- Database Migration, Public API, Production wiring, Audit persistence는
  추가하지 않았습니다.

## Phase 3 — Audit 가능한 Project·Environment 관리

상태: **초기 Database Migration·storage baseline 승인 대기**

### Slice 3.1 — Project Lifecycle

- Project create, read, list, update, archive, restore를 구현합니다.
- Stable identifier와 Tenant isolation을 강제합니다.
- State change와 동일한 transaction에 Audit Event를 기록합니다.

### Slice 3.2 — Environment Lifecycle

- Development, Staging, Production 기본 Environment를 생성합니다.
- 승인된 Environment naming·lifecycle policy를 구현합니다.
- 모호하거나 cross-project인 reference를 차단합니다.

완료 증거:

- 성공한 모든 mutation이 Audit Record를 생성합니다.
- 실패하거나 거부된 시도는 민감한 input을 유출하지 않으면서 승인된 Security
  Audit signal을 생성합니다.

## Phase 4 — Secret Lifecycle

상태: **Phase 3에 의해 차단됨**

### Slice 4.1 — Write·Metadata Operation

- Logical Secret과 첫 번째 immutable encrypted version을 생성합니다.
- 과거 Ciphertext를 변경하지 않고 새로운 Version을 추가합니다.
- Value를 decrypt하지 않고 metadata를 list·read합니다.
- Archive와 복구 가능한 deletion semantics를 구현합니다.

### Slice 4.2 — Secret Access

- 명시적으로 선택되고 authorize된 Version만 reveal합니다.
- Plaintext나 reversible derivative를 기록하지 않고 access를 audit합니다.
- 우발적 persistence를 막는 response·cache control을 강제합니다.
- Concurrency, tamper, rollback, cross-scope regression test를 추가합니다.

완료 증거:

- Plaintext는 명시적인 access operation에서만 반환됩니다.
- Listing, history, audit, error에는 Secret value가 포함되지 않습니다.
- Concurrent write는 deterministic한 Version 순서를 생성합니다.

## Phase 5 — Stable REST API·OpenAPI

상태: **Phase 4에 의해 차단됨**

- Versioned REST resource model과 error format을 승인합니다.
- OpenAPI를 공개하고 검증합니다.
- Request limit, 필요한 idempotency, pagination, 안전한 concurrency control을
  추가합니다.
- Generated client·backward compatibility contract test를 실행합니다.

완료 증거:

- Public contract를 구현과 독립적으로 Review할 수 있습니다.
- CI가 의도하지 않은 Breaking Change를 감지합니다.

## Phase 6 — CLI

상태: **Phase 5에 의해 차단됨**

- 안전한 Authentication·local configuration을 구현합니다.
- Project, Environment, Secret, Version, Audit workflow를 추가합니다.
- Plaintext가 command history, process argument, debug output, shell
  completion에 남지 않게 합니다.
- Machine-readable output과 non-interactive CI 동작을 추가합니다.

## Phase 7 — Web Dashboard

상태: **Phase 5에 의해 차단됨**

- Project, Environment, Secret metadata, access, token, RBAC, Audit workflow를
  구현합니다.
- Secret reveal을 명시적이고 짧게 유지하며 우발적인 copy·cache에 저항하도록
  만듭니다.
- Accessibility, Security header, session, browser regression test를
  완료합니다.

## MVP Release Gate

- 위의 모든 Phase가 완료되었습니다.
- 독립적인 Threat Model·Authorization Review가 완료되었습니다.
- Backup restore, key-provider outage, migration recovery, incident runbook을
  실제로 검증했습니다.
- Public API, CLI behavior, operator documentation이 versioning되었습니다.
- MVP를 안전하게 운영하는 데 Roadmap 제외 기능이 필요하지 않습니다.
