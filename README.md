# Laf Secrets

Laf Secrets is LafLabs' API-first secret-management platform for safely
storing, retrieving, versioning, and governing sensitive application
configuration.

The platform is intended for both LafLabs services and external developers.
It is not a plain key-value store: access control, encryption boundaries,
version history, and auditable access are core product behavior.

## Status

The project is in its security and architecture baseline phase. No production
implementation or stable public API exists yet.

The current documents are proposals until their approval status says
otherwise.

## Product values

- Security First
- Secure by Default
- Reliability
- Simplicity
- Developer Experience
- Auditability

## MVP scope

- Project management
- Environment management, initially centered on Development, Staging, and
  Production
- Secret CRUD
- Immutable secret versioning
- Envelope encryption
- Service tokens
- RBAC
- Audit log
- REST API with OpenAPI
- CLI
- Web dashboard

## Explicitly excluded from the MVP

- Dynamic secrets
- Database credential rotation
- PKI
- SSH certificates
- Kubernetes Operator
- Multi-region replication
- HSM integration

These exclusions do not prevent the architecture from preserving clean
extension boundaries. They must not be implemented before their roadmap
stage.

## Product shape

The trusted source of secret state is a central backend with encrypted
storage and an external key-encryption boundary. The REST API is the product
contract. The CLI and dashboard are clients of that same contract.

An official SDK may be considered later, but is not part of the approved MVP
scope.

## Repository guide

- [Roadmap](docs/roadmap.md)
- [Security invariants](docs/security/security-invariants.md)
- [Threat model](docs/security/threat-model.md)
- [Domain contract](docs/domain/domain-contract.md)
- [Proposed platform architecture](docs/adr/0001-api-first-modular-monolith.md)
- [Decisions required before implementation](docs/decisions-required.md)

