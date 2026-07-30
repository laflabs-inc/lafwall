# ADR-0001: API-first centralized modular monolith

- Status: **Accepted**
- Date: 2026-07-29
- Accepted: 2026-07-30
- Decision owners: LafLabs

## Context

Laf Secrets must provide a trusted source of secret state for LafLabs and
external developers. A local SDK-only design cannot consistently enforce
encryption custody, revocation, RBAC, auditability, or multi-client
coordination.

The MVP needs a REST API, CLI, and dashboard but does not need the operational
cost or distributed failure modes of microservices.

## Decision

Build an API-first centralized backend as a modular monolith.

- The REST API is the stable external product contract.
- CLI and dashboard use the same public application behavior rather than
  implementing independent secret policy.
- Domain and application policy are independent of HTTP, database, OIDC, and
  cloud KMS adapters.
- PostgreSQL stores tenant metadata, authorization state, ciphertext,
  encryption envelopes, and audit events.
- A `KekProvider` port separates envelope encryption from a production cloud
  key provider.
- Human users authenticate through an approved OIDC issuer. Workloads use
  revocable opaque service tokens.
- Required audit writes participate in the same transaction as successful
  state changes.
- Deployment begins as one backend unit. Module boundaries may be extracted
  only when measured scale, isolation, or reliability needs justify it.

## Logical modules

- Identity
- Authorization
- Projects
- Environments
- Secrets and versions
- Encryption
- Service tokens
- Audit
- Public API

Modules may share a deployment and database, but they do not bypass each
other's application contracts or write another module's tables directly.

## Consequences

### Benefits

- One authoritative security and authorization path
- Atomic domain and audit transactions
- Lower operational complexity for the MVP
- A single contract for CLI, dashboard, and future SDKs
- Clear adapters for OIDC, PostgreSQL, and KMS without premature service
  boundaries

### Costs and limitations

- A compromised backend process has a broad security impact and requires
  strong runtime isolation and least-privilege KMS policy.
- Independent module scaling is not initially available.
- PostgreSQL and backend availability affect the entire control plane.
- Discipline and architectural tests are required to prevent a modular
  monolith from becoming tightly coupled.

## Alternatives considered

### SDK-only encrypted storage

Rejected because clients would need key custody and would implement
authorization, revocation, versioning, and audit inconsistently.

### Microservices from the first release

Rejected for the MVP because distributed transactions, audit consistency,
deployment, and incident response would add risk before scale requires them.

### Store a master encryption key beside the database

Rejected for production because database or backup compromise could expose
both ciphertext and its key authority.

## Decision scope

This ADR approves the product shape and deployment boundary. The backend stack
is accepted separately in
[`ADR-0002`](0002-go-postgresql-backend.md). The initial production KMS
provider, final REST resource model, exact RBAC matrix, and database migration
remain separate approval gates.
