# Laf Secrets

[한국어](README.md) | **English**

Laf Secrets is LafLabs' API-first secret-management platform for safely
storing, retrieving, versioning, and governing sensitive application
configuration.

The platform is intended for both LafLabs services and external developers.
It is not a plain key-value store: access control, encryption boundaries,
version history, and auditable access are core product behavior.

## Status

The initial security, domain, and architecture baseline is accepted. Phase 1
is establishing the executable security foundation. No database baseline,
production deployment, or stable public API exists yet.

Each decision document remains authoritative only for the scope stated in
that document. Deferred decisions must be approved before dependent work
begins.

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

- [Development](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [Security invariants](docs/security/security-invariants.md)
- [Threat model](docs/security/threat-model.md)
- [Domain contract](docs/domain/domain-contract.md)
- [Platform architecture](docs/adr/0001-api-first-modular-monolith.md)
- [Backend stack](docs/adr/0002-go-postgresql-backend.md)
- [MVP policy boundaries](docs/rfc/0001-mvp-policy-boundaries.md)
- [Phase 0 decision record](docs/decisions-required.md)

## Local verification

With the supported Go toolchain installed:

```sh
make check
```

See the [development guide](docs/development.md) for configuration, individual
quality commands, CI behavior, and the operational probe contract.
