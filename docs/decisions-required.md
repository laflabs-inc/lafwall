# Decisions Required Before Implementation

Status: **Open**

The following choices affect architecture, storage, public API, or security
policy. They must be explicitly approved before dependent production code is
written.

## D1 — Platform architecture

Recommendation: accept
`docs/adr/0001-api-first-modular-monolith.md`.

Why: it provides one authoritative security boundary without adopting
microservice failure modes before they are justified.

## D2 — Backend implementation stack

Recommendation: **Go modular monolith** with PostgreSQL.

Reasons:

- predictable resource use and straightforward static deployment;
- mature standard HTTP, cryptography, database, and observability ecosystem;
- explicit error handling is valuable on security-sensitive paths;
- easier operational profile than a multi-runtime backend.

Alternatives:

- Rust provides stronger memory-safety and type-level guarantees but increases
  implementation and hiring complexity for the MVP.
- TypeScript maximizes LafLabs ecosystem familiarity but has a larger runtime
  and dependency surface for this security-critical backend.

The CLI language should be chosen after the public API contract is stable. It
does not need to share the backend runtime.

## D3 — Initial production KEK provider

Recommendation: define a vendor-neutral `KekProvider` contract and implement
exactly one production provider for the first deployment. A local provider is
development-only and production startup must reject it.

Approval needed:

- the first deployment environment; and
- its managed KMS provider.

Do not build multiple cloud adapters during the MVP without an actual
deployment requirement.

## D4 — Human identity

Recommendation: accept OIDC as the only human authentication boundary, with
Laf ID as the intended issuer when it satisfies the required contracts.

The backend must key users by immutable `(issuer, subject)`. Email is mutable
profile data.

Approval needed: whether early local and staging deployments may use a
separate standards-compliant OIDC issuer until Laf ID is production-ready.

## D5 — Tenant and organization model

Recommendation: make `Tenant` an internal mandatory isolation boundary from
the first migration. Initially, each human can receive a personal tenant.
Organization management can remain outside the MVP UI.

Why: adding tenant ownership later would require a high-risk migration across
every secret, role, token, and audit record.

Approval needed: whether the MVP must expose collaborative organization
management or only the internal boundary and project-scoped membership.

## D6 — Environment policy

Recommendation: create Development, Staging, and Production by default, model
Environment as a normal entity, and defer arbitrary additional environments
until product demand is demonstrated.

Approval needed:

- whether default environments may be renamed; and
- whether users may add custom environments in the MVP.

## D7 — RBAC role matrix

Recommendation: define a small fixed role set over fine-grained internal
permissions. Keep `secret:read_value` separate from administration and
metadata access.

The exact roles and inheritance rules require a dedicated proposed RFC before
implementation.

## D8 — Secret access API

Recommendation: separate metadata retrieval from explicit plaintext access.
List and metadata endpoints must never decrypt values.

The final versioned resource paths, request bodies, concurrency mechanism,
idempotency behavior, and error format require a proposed OpenAPI contract and
explicit approval before publication.

