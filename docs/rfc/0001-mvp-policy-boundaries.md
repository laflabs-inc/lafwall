# RFC-0001: MVP policy boundaries

- Status: **Accepted**
- Date: 2026-07-30
- Decision owners: LafLabs

## Summary

This RFC fixes the MVP boundaries for human identity, tenant isolation,
environments, RBAC shape, and plaintext secret access. It deliberately does
not publish an HTTP schema, database schema, or exact permission matrix.

## Human identity

- OIDC is the only human authentication boundary.
- Laf ID is the intended production issuer.
- Human principals are keyed by immutable `(issuer, subject)`. Email and
  profile fields are not identity proof.
- A separate standards-compliant issuer may be used only in local or staging
  environments until Laf ID is ready.
- Any temporary issuer must be explicitly configured. Production startup must
  reject temporary or development-only identity configuration.

This decision does not add password, session, or account-recovery behavior to
Laf Secrets. Those remain responsibilities of the approved issuer.

## Tenant and organization boundary

- Every persisted domain resource belongs to exactly one non-null `Tenant`.
- Tenant identity is immutable and is included in authorization and storage
  access.
- A human may initially receive a personal tenant.
- Collaborative organization management and organization UI are outside the
  MVP.
- Project-scoped collaboration may be introduced only through the approved
  RBAC contract; it cannot weaken the tenant boundary.

## Environment policy

- Every project begins with Development, Staging, and Production.
- These environments are normal entities with immutable identifiers.
- Their names cannot be changed and they cannot be removed during the MVP.
- Additional custom environments are outside the MVP.

This fixed policy keeps authorization, CLI behavior, API contracts, and
support expectations deterministic until actual demand justifies expansion.

## Authorization shape

- Authorization is deny-by-default.
- The MVP exposes a small fixed set of roles over fine-grained internal
  permissions.
- Custom roles are outside the MVP.
- `secret:read_value` remains distinct from project administration, secret
  metadata access, version writes, and role management.
- Every authorization decision includes principal, tenant, action, and target
  scope.

The exact role names, permission matrix, scope inheritance, and escalation
rules require a dedicated proposed RFC and explicit approval before RBAC
implementation begins.

## Secret access semantics

- Metadata and plaintext reveal are separate application operations.
- Listing, searching, history, and metadata reads never decrypt secret values.
- Plaintext reveal is explicit, separately authorized, audited, and
  non-cacheable.
- Administrative authority does not imply plaintext access.

The final resource paths, request and response schemas, concurrency behavior,
idempotency rules, and error model require a proposed OpenAPI contract and
explicit approval before publication.

## Deferred decisions

The following remain blocked by separate approval gates:

- initial PostgreSQL migration and storage baseline;
- exact fixed RBAC matrix;
- initial versioned OpenAPI contract;
- production deployment environment and KMS provider; and
- CLI implementation language.

## Consequences

### Benefits

- Tenant isolation exists before any persisted product state.
- Authentication stays delegated to a standards-based identity provider.
- Fixed environments and roles keep the MVP contract small and testable.
- Plaintext access is visibly distinct from safe metadata operations.

### Costs and limitations

- The MVP cannot model custom deployment stages or custom roles.
- Organization workflows are delayed even though the internal tenant boundary
  already exists.
- Local and staging identity configuration needs production-safety tests.
- Later expansion requires additive contracts and migration planning rather
  than silently broadening existing semantics.
