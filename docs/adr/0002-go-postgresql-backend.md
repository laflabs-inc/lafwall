# ADR-0002: Go·PostgreSQL Backend

- 상태: **Accepted(승인됨)**
- 작성일: 2026-07-30
- 결정 주체: LafLabs

## 배경

Laf Secrets에는 예측 가능한 resource 사용량, 명확한 운영 model, 성숙한
standard library, transaction persistence 지원을 갖춘 Security-sensitive
Backend가 필요합니다. MVP는 하나의 Backend runtime을 사용하고 Domain에
필요하지 않은 framework·Service boundary를 피해야 합니다.

이 결정은 [`ADR-0001`](0001-api-first-modular-monolith.md)의 Architecture를
유지해야 합니다. Domain·Application policy는 HTTP, Database, OIDC, KMS
adapter와 독립적입니다.

## 결정

Laf Secrets Backend를 Go Modular Monolith로 구현합니다. PostgreSQL을 Tenant
metadata, Authorization state, Ciphertext, Encryption Envelope, Version state,
Audit Event의 authoritative system of record로 사용합니다.

- Package boundary는 transport나 table layout이 아닌 Domain·Application
  책임을 따릅니다.
- PostgreSQL 전용 코드는 Repository·Transaction port 뒤에 둡니다.
- Domain policy는 실행 중인 HTTP server, PostgreSQL, OIDC issuer, Production
  KMS 없이 test할 수 있어야 합니다.
- 하나의 state-changing transaction에 필수 success Audit Event를
  포함합니다.
- Database access는 explicit query와 좁은 interface를 사용합니다. Query
  generator, router, Migration tool, dependency injection 방식은 Repository
  skeleton에서 필요성이 증명될 때까지 선택하지 않습니다.
- CLI는 Backend language를 공유할 필요가 없으며 Public API contract가
  안정된 뒤 선택합니다.

## 결과

### 장점

- 예측 가능한 runtime과 단순한 static deployment
- 성숙한 HTTP, cryptography, Database, test, observability ecosystem
- Security-sensitive path에서 명시적인 error handling
- Domain invariant를 보강하는 PostgreSQL transaction·constraint
- 하나의 Backend runtime으로 유지되는 단순한 MVP 운영

### 비용과 제약

- Go는 Rust보다 type-level Domain constraint가 적으므로 constructor,
  Package boundary, test, storage constraint가 더 큰 역할을 해야 합니다.
- PostgreSQL availability가 전체 Control Plane에 영향을 줍니다.
- Unit test 외에도 Database 전용 adapter·integration test가 필요합니다.
- Modular Monolith도 coupling을 방지하는 dependency rule이 필요합니다.

## 검토한 대안

### Rust Backend

Rust는 더 강한 memory safety와 type-level guarantee를 제공하지만 현 단계의
LafLabs에는 MVP 구현, Review, 채용 비용이 더 높습니다.

### TypeScript Backend

TypeScript는 기존 LafLabs ecosystem과 더 잘 맞지만 Security-critical
Backend의 runtime·dependency surface가 커집니다.

### 여러 Persistence Technology 사용

분리된 state가 MVP 요구 없이 transaction, Audit consistency, backup,
restore, incident response를 복잡하게 만들기 때문에 채택하지 않았습니다.

## 결정 범위

이 ADR은 Backend language와 Database technology를 선택합니다. 다음 항목은
승인하지 않습니다.

- 초기 Database schema·Migration
- Go module layout·third-party framework
- Production deployment topology
- Production KMS provider
- Stable public API contract

각 항목은 Roadmap의 증거와 approval gate를 별도로 충족해야 합니다.
