# ADR-0001: API-first 중앙집중형 Modular Monolith

- 상태: **Accepted(승인됨)**
- 작성일: 2026-07-29
- 승인일: 2026-07-30
- 결정 주체: LafLabs

## 배경

Laf Secrets는 LafLabs와 외부 개발자에게 신뢰할 수 있는 Secret state를
제공해야 합니다. Local SDK에만 의존하는 설계로는 Encryption custody,
revocation, RBAC, Auditability, 여러 Client 간 coordination을 일관되게
강제할 수 없습니다.

MVP에는 REST API, CLI, Dashboard가 필요하지만 Microservice의 운영 비용과
분산 failure mode는 필요하지 않습니다.

## 결정

API-first 중앙집중형 Backend를 Modular Monolith로 구축합니다.

- REST API를 stable external product contract로 사용합니다.
- CLI와 Dashboard는 독립적인 Secret policy를 구현하지 않고 동일한 public
  Application behavior를 사용합니다.
- Domain·Application policy를 HTTP, Database, OIDC, cloud KMS adapter와
  분리합니다.
- PostgreSQL에 Tenant metadata, Authorization state, Ciphertext, Encryption
  Envelope, Audit Event를 저장합니다.
- `KekProvider` port로 Envelope Encryption과 Production cloud key provider를
  분리합니다.
- Human user는 승인된 OIDC issuer로 인증하고 Workload는 revocable opaque
  Service Token을 사용합니다.
- 필수 Audit write는 성공한 state change와 동일한 transaction에 참여합니다.
- 하나의 Backend unit으로 배포를 시작합니다. 측정된 scale, isolation,
  reliability 요구가 있을 때만 Module boundary를 분리할 수 있습니다.

## 논리 Module

- Identity
- Authorization
- Projects
- Environments
- Secrets·Versions
- Encryption
- Service Tokens
- Audit
- Public API

Module은 deployment와 Database를 공유할 수 있지만 서로의 Application
Contract를 우회하거나 다른 Module의 table에 직접 write하지 않습니다.

## 결과

### 장점

- 하나의 authoritative Security·Authorization path
- Atomic Domain·Audit transaction
- MVP의 낮은 운영 복잡도
- CLI, Dashboard, 향후 SDK가 공유하는 단일 contract
- 성급한 Service 분리 없이 OIDC, PostgreSQL, KMS를 교체할 수 있는 명확한
  adapter

### 비용과 제약

- Backend process가 침해되면 Security 영향 범위가 넓으므로 강한 runtime
  isolation과 least-privilege KMS policy가 필요합니다.
- 초기에는 Module별 독립 scaling을 지원하지 않습니다.
- PostgreSQL과 Backend availability가 전체 Control Plane에 영향을 줍니다.
- Modular Monolith가 강하게 결합되는 것을 막으려면 규율과 Architecture
  test가 필요합니다.

## 검토한 대안

### SDK-only encrypted storage

Client가 key custody를 가져야 하고 Authorization, revocation, Versioning,
Audit을 서로 다르게 구현하게 되므로 채택하지 않았습니다.

### 첫 Release부터 Microservice 사용

Scale이 필요하기 전에 distributed transaction, Audit consistency,
deployment, incident response 위험을 추가하므로 MVP에서는 채택하지
않았습니다.

### Master Encryption Key를 Database와 함께 저장

Database나 backup이 침해되면 Ciphertext와 key authority가 함께 노출될 수
있으므로 Production에서는 채택하지 않았습니다.

## 결정 범위

이 ADR은 Product shape와 deployment boundary를 승인합니다. Backend stack은
[`ADR-0002`](0002-go-postgresql-backend.md)에서 별도로 승인합니다.

초기 Production KMS provider, 최종 REST resource model, 정확한 RBAC matrix,
Database Migration은 별도의 approval gate로 유지합니다.
