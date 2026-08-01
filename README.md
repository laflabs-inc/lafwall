# Laf Secrets

**한국어** | [English](README.en.md)

Laf Secrets는 민감한 애플리케이션 설정을 안전하게 저장·조회·버전
관리하고 접근 정책을 집행하는 LafLabs의 API-first Secret Management
Platform입니다.

LafLabs의 서비스와 외부 개발자가 모두 사용할 수 있도록 설계합니다.
단순한 Key-Value Store가 아니며, Access Control·Encryption
Boundary·Version History·감사 가능한 접근을 제품의 핵심 동작으로
다룹니다.

## 현재 상태

초기 Security·Domain·Architecture baseline, Phase 1의 실행 가능한
Security Foundation, Phase 2의 Human Identity Boundary가 구현되었습니다.
Service Token과 RBAC는 아직 구현되지 않았습니다. Database baseline,
Production deployment, stable public API도 아직 존재하지 않습니다.

각 Decision 문서는 문서에 명시된 범위에서만 Source of Truth입니다. 보류된
결정은 해당 결정에 의존하는 작업을 시작하기 전에 승인을 받아야 합니다.

## 핵심 가치

- Security First
- Secure by Default
- Reliability
- Simplicity
- Developer Experience
- Auditability

## MVP 범위

- Project 관리
- Development·Staging·Production을 중심으로 한 Environment 관리
- Secret CRUD
- 변경 불가능한 Secret Versioning
- Envelope Encryption
- Service Token
- RBAC
- Audit Log
- OpenAPI를 포함한 REST API
- CLI
- Web Dashboard

## MVP에서 명시적으로 제외하는 범위

- Dynamic Secrets
- Database Credential Rotation
- PKI
- SSH Certificate
- Kubernetes Operator
- Multi-region Replication
- HSM Integration

Architecture는 제외된 기능을 위한 명확한 확장 경계를 유지해야 합니다. 다만
해당 기능은 Roadmap에 정의된 단계보다 먼저 구현하지 않습니다.

## 제품 구조

Secret state의 신뢰 원천은 encrypted storage와 외부 Key Encryption
Boundary를 사용하는 중앙 Backend입니다. REST API가 제품 계약이며, CLI와
Dashboard는 동일한 계약을 사용하는 Client입니다.

공식 SDK는 이후 검토할 수 있지만, 승인된 MVP 범위에는 포함되지 않습니다.

## Repository 안내

- [개발 가이드](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [Security Invariants](docs/security/security-invariants.md)
- [Threat Model](docs/security/threat-model.md)
- [Encryption Boundary](docs/security/encryption-boundary.md)
- [Human Identity Boundary](docs/security/human-identity-boundary.md)
- [Domain Contract](docs/domain/domain-contract.md)
- [Platform Architecture](docs/adr/0001-api-first-modular-monolith.md)
- [Backend Stack](docs/adr/0002-go-postgresql-backend.md)
- [MVP Policy Boundaries](docs/rfc/0001-mvp-policy-boundaries.md)
- [Phase 0 Decision Record](docs/decisions-required.md)

## 로컬 검증

지원하는 Go toolchain을 설치한 뒤 다음 명령을 실행합니다.

```sh
make check
```

Configuration, 개별 품질 검사 명령, CI 동작, Operational Probe 계약은
[개발 가이드](docs/development.md)를 참고하세요.
