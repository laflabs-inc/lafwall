# Decisions Required Before Implementation

Status: **Resolved for Phase 0**

Decision date: 2026-07-30

This is the index of the Phase 0 decisions approved by LafLabs. Accepted ADRs
and RFCs are the normative records. A decision explicitly deferred here
remains an approval gate before dependent work begins.

## D1 — Platform architecture

Decision: **Accepted** in
`docs/adr/0001-api-first-modular-monolith.md`.

The platform uses one authoritative API-first security boundary without
adopting microservice failure modes before operational evidence justifies
them.

## D2 — Backend implementation stack

Decision: **Accepted** in `docs/adr/0002-go-postgresql-backend.md`.

The backend is a Go modular monolith and PostgreSQL is its system of record.
This does not approve an initial migration or select the CLI language.

## D3 — Initial production KEK provider

Decision: **Partially accepted and explicitly deferred**.

- A vendor-neutral `KekProvider` boundary is approved.
- The first release will implement exactly one production provider selected
  for its actual deployment environment.
- Deterministic fake providers are test-only. Any local provider is
  development-only and production startup must reject it.

The first deployment environment and managed KMS provider remain unselected.
Production encryption-provider implementation and production deployment are
blocked until that selection receives explicit approval. Multiple cloud
adapters remain out of scope without a demonstrated deployment requirement.

## D4 — Human identity

Decision: **Accepted** as part of
`docs/rfc/0001-mvp-policy-boundaries.md`.

OIDC is the only human authentication boundary. Laf ID is the intended
production issuer. A temporary standards-compliant issuer may be configured
only for local or staging use until Laf ID is ready; it must be explicit and
impossible to enable in production accidentally. Users are keyed by immutable
`(issuer, subject)`, never email.

## D5 — Tenant and organization model

Decision: **Accepted** as part of
`docs/rfc/0001-mvp-policy-boundaries.md`.

`Tenant` is a mandatory internal isolation boundary from the first storage
baseline. A human may initially receive a personal tenant. Collaborative
organization management and its UI are outside the MVP; project-scoped
membership may be introduced only within the approved RBAC contract.

## D6 — Environment policy

Decision: **Accepted** as part of
`docs/rfc/0001-mvp-policy-boundaries.md`.

Development, Staging, and Production are fixed MVP environments. They are
normal domain entities but cannot be renamed, removed, or supplemented with
custom environments during the MVP.

## D7 — RBAC role matrix

Decision: **Product boundary accepted; exact matrix deferred**.

The MVP uses a small fixed role set over fine-grained internal permissions and
does not support custom roles. `secret:read_value` is separate from
administration and metadata access. The exact role names, permissions, scope,
and inheritance rules require a dedicated proposed RFC and explicit approval
before Slice 2.3 begins.

## D8 — Secret access API

Decision: **Semantic boundary accepted; public contract deferred**.

Metadata retrieval and explicit plaintext reveal are separate operations.
List and metadata operations never decrypt values. Final versioned resource
paths, request bodies, concurrency and idempotency behavior, and error format
require a proposed OpenAPI contract and explicit approval before publication.

## Remaining approval gates

- Initial database migration and storage baseline
- Initial production deployment environment and KMS provider
- Exact RBAC matrix
- Initial versioned OpenAPI contract
- CLI implementation language, when CLI work begins
