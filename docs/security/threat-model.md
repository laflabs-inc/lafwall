# Threat Model

상태: **Accepted Baseline(승인된 기준선)**

승인일: 2026-07-30

이 문서는 지속적으로 갱신하는 Security Baseline입니다. Trust boundary,
보호 자산, Production provider, Public API, deployment model이 변경되면 반드시
Review해야 합니다.

## 범위

이 Model은 Laf Secrets MVP의 Control Plane, REST API, persistent storage,
Key Encryption Provider Boundary, CLI, Dashboard, Human OIDC Authentication,
Service Token, RBAC, Audit Event를 다룹니다.

Dynamic Credential, Credential Rotation, PKI, SSH Certificate, Kubernetes
Operator 동작, Multi-region Replication, HSM Integration은 MVP Model 범위
밖입니다.

## 보호 자산

- Secret plaintext·historical value
- Data Encryption Key·Production Key Encryption authority
- Human session, OIDC Token, Service Token
- Tenant, Project, Environment, membership, RBAC state
- Audit Record·Security-relevant metadata
- Ciphertext, Wrapped DEK, backup, configuration
- Secret access path의 availability·integrity

Ciphertext·Wrapped Key도 plaintext가 아니더라도 민감정보로 취급합니다.

## Actor

- 승인된 Human User
- Service Token을 사용하는 승인된 Workload
- Tenant Administrator
- Laf Secrets Operator
- 침해되었거나 악의적인 Tenant Member
- 외부 unauthenticated attacker
- Application Database·backup에 read access를 얻은 attacker
- Network, proxy, log sink, observability system을 제어하는 attacker
- 침해된 Application Process
- 침해되었거나 사용할 수 없는 Key Provider

## Trust Boundary

1. User·Workload와 Laf Secrets API 사이
2. Dashboard·CLI와 Public REST Contract 사이
3. Transport Adapter와 Application Use Case 사이
4. Application Use Case와 Authorization Policy 사이
5. Application과 PostgreSQL 사이
6. Encryption Service와 외부 `KekProvider` 사이
7. Application과 OIDC issuer·JWK retrieval 사이
8. Application과 Audit·observability destination 사이
9. Backup·restore path

Boundary를 넘을 때마다 명시적인 Authentication, validation, failure policy가
필요합니다. Internal network에 있다는 사실은 trust의 증거가 아닙니다.

## 주요 위협과 필수 통제

<!-- markdownlint-disable MD013 -->

| 위협 | 예시 | 필수 통제 |
| --- | --- | --- |
| Credential theft | Service Token이 source·log에 노출됨 | One-time display, non-reversible verifier, safe prefix, allowlisted logging, expiry·revocation |
| Broken object authorization | 유효한 User가 Project ID를 바꿔 다른 Tenant에 접근함 | Deny-by-default Use Case Authorization, Tenant-scoped query, negative integration test |
| Ciphertext substitution | Database attacker가 Ciphertext를 다른 Secret·Version으로 옮김 | Stable resource·Version ID에 묶인 canonical AAD |
| Nonce·key reuse | Encryption이 GCM key/nonce pair를 재사용함 | Version별 fresh DEK와 CSPRNG nonce generation |
| Database disclosure | Attacker가 primary Database·backup을 읽음 | Envelope Encryption, Database 외부 KEK, encrypted backup, plaintext persistence 금지 |
| Log·telemetry disclosure | Request body·header·error가 Secret을 capture함 | Allowlisted field, body capture 비활성화, Secret-safe error, regression test |
| Privilege escalation | Project editor가 자신에게 Secret access를 부여함 | Membership, Policy, metadata, plaintext access Permission 분리와 검증된 matrix |
| Audit tampering | Operator가 access 증거를 제거함 | Append-only runtime role, atomic event write, 제한된 retention path, 향후 external export boundary |
| Replay·stale authorization | Revoked Token이 계속 동작함 | 사용 시 opaque token lookup, revocation state, expiry, cache limit |
| OIDC confusion | 다른 issuer·audience의 Token을 수락함 | Exact issuer·audience 검사, algorithm allowlist, immutable issuer/subject mapping |
| Resource exhaustion | 지나치게 큰 Secret value·무제한 list request | 명시적인 size, rate, pagination, concurrency limit |
| Key-provider outage | Write·reveal 중 KMS를 사용할 수 없음 | Bounded retry, readiness degradation, fail-closed, plaintext fallback 금지 |
| Rollback attack | 과거 Database state가 현재 상태로 바뀜 | Immutable Version, monotonic sequencing, Audit correlation, restore procedure |
| Supply-chain compromise | Dependency·build pipeline이 악성 코드를 주입함 | Locked dependency, Review, provenance, dependency audit, 최소 build permission |
| Browser persistence | Dashboard·proxy가 reveal된 plaintext를 cache함 | 명시적 reveal flow, no-store header, persistent client state 금지, telemetry capture 비활성화 |
| CLI leakage | Secret이 shell history·process list에 노출됨 | stdin·file descriptor input, masked prompt, argv에 value 금지, 안전한 debug mode |

<!-- markdownlint-enable MD013 -->

## 반드시 검증할 Abuse Case

1. Tenant A의 Principal이 Tenant B ID에 모든 operation을 시도합니다.
2. 한 Version의 Ciphertext, Wrapped DEK, nonce, AAD를 다른 Version으로
   대체합니다.
3. Revoked·expired Service Token을 replay합니다.
4. 인증된 Project Administrator에게 plaintext access Permission이 없습니다.
5. Mutation 중 Database와 Key Provider operation이 각각 실패합니다.
6. Secret access·Policy 수정 중 Audit persistence가 실패합니다.
7. 여러 Writer가 동일한 다음 Secret Version을 동시에 생성합니다.
8. Log, trace, error, fixture, snapshot, Audit export에서 알려진 canary Secret
   value를 검사합니다.
9. KEK reference가 없거나 잘못되었거나 rotate된 상태로 backup을 restore합니다.
10. Dashboard·CLI가 plaintext를 받은 뒤 error를 발생시킵니다.

## 가정

- TLS는 승인된 Infrastructure에서만 terminate하며 edge에서 plaintext를
  capture하지 않습니다.
- Production Key Provider Identity·Permission은 Application Database 외부에서
  설정합니다.
- Host, container, deployment hardening은 Production release 전에 문서화할
  별도의 Operator 책임입니다.
- Application Process 전체가 침해되면 처리 중인 plaintext가 노출될 수
  있습니다. MVP는 노출을 줄이지만 Confidential Computing을 제공한다고
  주장하지 않습니다.

## 잔여 위험

- 유효한 Key Provider authority를 가진 실행 중 Application이 침해되면 해당
  runtime identity가 access할 수 있는 data를 decrypt할 수 있습니다.
- Application-level append-only Audit control만으로 모든 privileged
  Database·Infrastructure Administrator를 방어할 수 없습니다. External
  immutable export는 향후 hardening boundary입니다.
- Soft deletion은 recovery를 제공하지만 즉각적인 cryptographic erasure는
  제공하지 않습니다.
- Project name, Secret name, access timing, Ciphertext size 같은 metadata가
  운영 정보를 노출할 수 있으므로 access control이 필요합니다.

이 위험을 Operator documentation에 반영해야 하며 더 강한 Product claim으로
숨겨서는 안 됩니다.
