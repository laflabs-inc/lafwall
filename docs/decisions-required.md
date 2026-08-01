# 구현 전 필수 결정

상태: **Phase 0에서 해결됨**

결정일: 2026-07-30

이 문서는 LafLabs가 승인한 Phase 0 결정의 index입니다. Accepted ADR·RFC가
규범적인 기록입니다. 이 문서에서 명시적으로 보류한 결정은 관련 작업을
시작하기 전에 해결해야 하는 approval gate로 유지합니다.

## D1 — Platform Architecture

결정: `docs/adr/0001-api-first-modular-monolith.md`에서 **승인됨**.

운영 근거가 정당화하기 전에 Microservice failure mode를 도입하지 않고,
하나의 authoritative API-first Security Boundary를 사용합니다.

## D2 — Backend 구현 Stack

결정: `docs/adr/0002-go-postgresql-backend.md`에서 **승인됨**.

Backend는 Go Modular Monolith이며 PostgreSQL을 system of record로 사용합니다.
이 결정은 초기 Migration이나 CLI language를 승인하지 않습니다.

## D3 — 초기 Production KEK Provider

결정: **일부 승인·명시적 보류**.

- Vendor-neutral `KekProvider` boundary를 승인합니다.
- 첫 Release에는 실제 deployment Environment에 맞춰 선택한 하나의
  Production provider만 구현합니다.
- Deterministic fake provider는 test-only입니다. Local provider가 있다면
  development-only여야 하며 Production startup은 이를 거부해야 합니다.

첫 deployment Environment와 managed KMS provider는 아직 선택하지
않았습니다. 선택이 명시적으로 승인되기 전까지 Production Encryption
Provider 구현과 Production deployment를 차단합니다. 실제 deployment 요구가
증명되지 않으면 여러 cloud adapter는 범위 밖입니다.

## D4 — Human Identity

결정: `docs/rfc/0001-mvp-policy-boundaries.md`에서 **승인됨**.

OIDC만 Human Authentication Boundary로 사용하고 Laf ID를 Production
issuer로 사용할 예정입니다. Laf ID가 준비될 때까지 local·staging에서만
임시 standards-compliant issuer를 명시적으로 설정할 수 있으며 Production에서
실수로 활성화할 수 없어야 합니다. User는 email이 아닌 immutable
`(issuer, subject)`로 식별합니다.

## D5 — Tenant·Organization Model

결정: `docs/rfc/0001-mvp-policy-boundaries.md`에서 **승인됨**.

첫 storage baseline부터 `Tenant`를 필수 internal isolation boundary로
사용합니다. Human에게 초기 Personal Tenant를 부여할 수 있습니다.
Collaborative Organization 관리·UI는 MVP 범위 밖이며 Project-scoped
membership은 승인된 RBAC contract 안에서만 도입할 수 있습니다.

## D6 — Environment Policy

결정: `docs/rfc/0001-mvp-policy-boundaries.md`에서 **승인됨**.

Development, Staging, Production을 고정 MVP Environment로 사용합니다. 일반
Domain Entity이지만 MVP 동안 이름을 변경·제거하거나 Custom Environment를
추가할 수 없습니다.

## D7 — RBAC Role Matrix

결정: **Product boundary 승인·정확한 matrix 보류**.

MVP는 fine-grained internal permission 위에 소수의 고정 role을 사용하고
custom role을 지원하지 않습니다. `secret:read_value`는 administration·
metadata access와 분리합니다.

정확한 role 이름, Permission, scope, grant rule을
[`RFC-0002`](rfc/0002-mvp-rbac-matrix.md)에서 **Proposed** 상태로
제안했습니다. 이 문서는 아직 승인된 결정이 아니며 Slice 2.3 구현 전에
LafLabs의 명시적인 승인을 받아야 합니다.

## D8 — Secret Access API

결정: **Semantic boundary 승인·public contract 보류**.

Metadata read와 명시적인 plaintext reveal은 서로 다른 operation입니다.
List·metadata operation은 value를 decrypt하지 않습니다. 최종 versioned
resource path, request body, concurrency·idempotency behavior, error format은
공개 전에 Proposed OpenAPI contract와 명시적인 승인을 받아야 합니다.

## 남은 Approval Gate

- 초기 Database Migration·storage baseline
- 초기 Production deployment Environment·KMS provider
- 정확한 RBAC matrix — [`RFC-0002`](rfc/0002-mvp-rbac-matrix.md) 승인 대기
- 초기 versioned OpenAPI contract
- CLI 작업 시작 시 구현 언어
