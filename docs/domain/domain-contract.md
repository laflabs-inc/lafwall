# Domain Contract

Status: **Draft**

This document defines domain meaning, not a stable HTTP or database schema.
Public API and migration approval are separate gates.

## Security boundary

Every persisted domain resource belongs to exactly one `Tenant`. A tenant is
an internal isolation boundary even if the first product experience creates a
personal tenant automatically and does not yet expose organization
management.

No query or authorization decision may infer tenancy from a user-controlled
resource identifier alone.

## Core entities

### Tenant

The root isolation boundary for resources, principals, role assignments, and
audit records.

### Principal

An authenticated actor:

- `HumanPrincipal`, keyed by immutable OIDC issuer and subject; or
- `ServicePrincipal`, authenticated by an opaque service token.

Email, display name, and token prefix are metadata, not identity proof.

### Project

A namespace and policy boundary for related environments and secrets.

- Has an immutable ID and tenant ID.
- Has a tenant-unique, human-readable slug.
- Can be archived and restored.
- Archival denies normal descendant access without destroying history.

### Environment

An isolated deployment context within a project.

- Has an immutable ID and project ID.
- Development, Staging, and Production are created as initial defaults.
- The policy for additional environments and renaming remains an approval
  decision.

### Secret

A logical secret key within one environment.

- Has an immutable ID.
- Has an environment-unique canonical key.
- Stores metadata and lifecycle state, never a plaintext value.
- Points to a current immutable version.

### SecretVersion

An immutable encrypted value belonging to one logical secret.

- Has an immutable ID and monotonically allocated sequence.
- Contains an encryption envelope and safe creation metadata.
- Cannot be edited after creation.
- Historical access is separately authorized and audited.

### RoleAssignment

Grants an approved role to a principal at a defined tenant, project, or
environment scope. Inheritance, if approved, is explicit and tested. Absence
of a grant means denial.

### ServiceToken

An authentication credential for a `ServicePrincipal`.

- Plaintext is shown once.
- Persistent state contains only a public identifier, non-reversible verifier,
  scope, expiry, status, and safe operational metadata.
- Revocation is immediate at the authoritative verification boundary.

### AuditEvent

An append-only record of a security-relevant attempt or completed action.

- Contains stable identifiers, outcome, time, correlation, and safe context.
- Never contains secret plaintext, credentials, raw authorization data, or
  wrapped key material.

## Lifecycle rules

1. Creating a secret creates version `1` atomically.
2. Changing a value appends a new version; it never updates an old version.
3. Metadata reads do not decrypt secret values.
4. Plaintext access is an explicit use case, separately authorized and
   audited.
5. Archive and soft deletion remove normal accessibility while preserving
   recovery and audit history.
6. A state-changing transaction and its required success audit event commit
   together.
7. Cross-tenant relationships are invalid even if individual IDs exist.
8. Parent archival or deletion restricts descendant access according to an
   approved lifecycle policy.

## Preliminary permission vocabulary

The exact roles remain an approval decision. Policy should be expressed using
fine-grained actions such as:

- `project:create`, `project:read`, `project:update`, `project:archive`
- `environment:create`, `environment:read`, `environment:update`
- `secret:create`, `secret:read_metadata`, `secret:write_version`
- `secret:read_value`, `secret:read_history`, `secret:archive`
- `service_token:create`, `service_token:read_metadata`,
  `service_token:revoke`
- `role_assignment:read`, `role_assignment:manage`
- `audit:read`

`secret:read_value` is deliberately distinct from project administration and
metadata access.

## Invariants requiring storage enforcement

- Tenant ownership is non-null and immutable.
- Project slugs are unique within a tenant.
- Environment identifiers are unique within a project.
- Secret canonical keys are unique among active secrets in an environment.
- Version sequence is unique and monotonic within a secret.
- Historical versions and audit events are immutable to the runtime role.
- Current-version references cannot point across secrets.
- Role-assignment scope cannot cross the principal's tenant boundary.

