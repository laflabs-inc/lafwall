# RFC-0001: MVP Policy Boundary

- 상태: **Accepted(승인됨)**
- 작성일: 2026-07-30
- 결정 주체: LafLabs

## 요약

이 RFC는 Human Identity, Tenant isolation, Environment, RBAC shape,
plaintext Secret access의 MVP boundary를 확정합니다. HTTP schema, Database
schema, 정확한 Permission matrix는 의도적으로 공개하지 않습니다.

## Human Identity

- OIDC만 Human Authentication Boundary로 사용합니다.
- Laf ID를 Production issuer로 사용할 예정입니다.
- Human Principal은 immutable `(issuer, subject)`로 식별합니다. Email과
  profile field는 identity proof가 아닙니다.
- Laf ID가 준비될 때까지 local·staging Environment에서만 별도의
  standards-compliant issuer를 사용할 수 있습니다.
- 임시 issuer는 명시적으로 설정해야 합니다. Production startup은 임시 또는
  development-only identity configuration을 거부해야 합니다.

이 결정은 Laf Secrets에 password, session, account recovery behavior를
추가하지 않습니다. 해당 기능은 승인된 issuer의 책임입니다.

## Tenant·Organization Boundary

- Persist되는 모든 Domain resource는 정확히 하나의 non-null `Tenant`에
  속합니다.
- Tenant identity는 immutable이며 Authorization·storage access에 항상
  포함합니다.
- 초기에는 Human에게 Personal Tenant를 부여할 수 있습니다.
- Collaborative Organization 관리와 Organization UI는 MVP 범위 밖입니다.
- Project-scoped collaboration은 승인된 RBAC contract를 통해서만 도입할 수
  있으며 Tenant boundary를 약화할 수 없습니다.

## Environment Policy

- 모든 Project는 Development, Staging, Production으로 시작합니다.
- 각 Environment는 immutable identifier를 가진 일반 Entity입니다.
- MVP 동안 이름을 변경하거나 제거할 수 없습니다.
- Custom Environment는 MVP 범위 밖입니다.

실제 수요가 확장을 정당화할 때까지 이 고정 Policy로 Authorization, CLI
behavior, API contract, support expectation을 deterministic하게 유지합니다.

## Authorization 구조

- Authorization은 deny-by-default입니다.
- MVP는 fine-grained internal permission 위에 소수의 고정 role을 제공합니다.
- Custom role은 MVP 범위 밖입니다.
- `secret:read_value`는 Project administration, Secret metadata access,
  Version write, role management와 분리합니다.
- 모든 Authorization decision에 Principal, Tenant, action, target scope를
  포함합니다.

정확한 role 이름, Permission matrix, scope inheritance, escalation rule은
RBAC 구현 전에 별도의 Proposed RFC와 명시적인 승인을 받아야 합니다.

## Secret Access Semantics

- Metadata와 plaintext reveal은 서로 다른 Application operation입니다.
- List, search, history, metadata read는 Secret value를 decrypt하지 않습니다.
- Plaintext reveal은 명시적이고 별도로 authorize·audit하며 cache할 수
  없습니다.
- Administrative authority는 plaintext access를 암시하지 않습니다.

최종 resource path, request·response schema, concurrency behavior,
idempotency rule, error model은 공개 전에 Proposed OpenAPI contract와
명시적인 승인을 받아야 합니다.

## 보류된 결정

다음 항목은 별도의 approval gate로 계속 차단됩니다.

- 초기 PostgreSQL Migration·storage baseline
- 정확한 고정 RBAC matrix
- 초기 versioned OpenAPI contract
- Production deployment Environment·KMS provider
- CLI 구현 언어

## 결과

### 장점

- Persist되는 Product state보다 먼저 Tenant isolation이 존재합니다.
- Authentication을 standards-based Identity Provider에 위임합니다.
- 고정 Environment·role로 MVP contract를 작고 test하기 쉽게 유지합니다.
- Plaintext access가 안전한 metadata operation과 명확히 구분됩니다.

### 비용과 제약

- MVP에서는 custom deployment stage·custom role을 표현할 수 없습니다.
- 내부 Tenant boundary가 이미 존재하더라도 Organization workflow는
  연기됩니다.
- Local·staging Identity configuration에 Production safety test가 필요합니다.
- 이후 확장에는 기존 semantics를 암묵적으로 넓히는 대신 additive
  contract와 Migration 계획이 필요합니다.
