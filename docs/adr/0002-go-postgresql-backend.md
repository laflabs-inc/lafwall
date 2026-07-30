# ADR-0002: Go backend with PostgreSQL

- Status: **Accepted**
- Date: 2026-07-30
- Decision owners: LafLabs

## Context

Laf Secrets needs a security-sensitive backend with predictable resource use,
an explicit operational model, mature standard libraries, and strong support
for transactional persistence. The MVP should use one backend runtime and
avoid framework or service boundaries that are not required by the domain.

This decision must preserve the architecture in
[`ADR-0001`](0001-api-first-modular-monolith.md): domain and application
policy remain independent of HTTP, database, OIDC, and KMS adapters.

## Decision

Implement the Laf Secrets backend as a Go modular monolith. Use PostgreSQL as
the authoritative system of record for tenant metadata, authorization state,
ciphertext, encryption envelopes, version state, and audit events.

- Package boundaries follow domain and application responsibilities, not
  transport or table layout.
- PostgreSQL-specific code remains behind repository and transaction ports.
- Domain policy is testable without a running HTTP server, PostgreSQL, OIDC
  issuer, or production KMS.
- One state-changing transaction includes its required success audit event.
- Database access uses explicit queries and narrow interfaces. Selecting a
  query generator, router, migration tool, or dependency-injection approach
  is deferred until the repository skeleton proves it is needed.
- The CLI does not need to share the backend language and will be selected
  after the public API contract is stable.

## Consequences

### Benefits

- Predictable runtime and straightforward static deployment
- Mature HTTP, cryptography, database, testing, and observability ecosystem
- Explicit error handling on security-sensitive paths
- PostgreSQL transactions and constraints can reinforce domain invariants
- A single backend runtime keeps the MVP operationally simple

### Costs and limitations

- Go provides fewer type-level domain constraints than Rust, so constructors,
  package boundaries, tests, and storage constraints must carry more weight.
- PostgreSQL availability affects the whole control plane.
- Database-specific adapters and integration tests are required in addition
  to unit tests.
- A modular monolith still requires dependency rules to prevent coupling.

## Alternatives considered

### Rust backend

Rust offers stronger memory-safety and type-level guarantees, but its MVP
implementation, review, and hiring costs are higher for LafLabs at this stage.

### TypeScript backend

TypeScript aligns with more of the existing LafLabs ecosystem, but adds a
larger runtime and dependency surface to the security-critical backend.

### Multiple persistence technologies

Rejected because split state would complicate transactions, audit
consistency, backup, restore, and incident response without an MVP
requirement.

## Decision scope

This ADR selects the backend language and database technology. It does not
approve:

- an initial database schema or migration;
- a Go module layout or third-party framework;
- a production deployment topology;
- a production KMS provider; or
- a stable public API contract.

Each remains subject to its roadmap evidence and approval gate.
