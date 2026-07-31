# Laf Secrets Roadmap

## Roadmap rules

- Work on only one slice at a time.
- Complete review, tests, documentation, and security evidence before moving
  to the next slice.
- Do not begin implementation while a required architecture, storage, public
  API, or security decision is still unapproved.
- Roadmap-excluded features remain out of scope even when an implementation
  shortcut appears to make them inexpensive.

## Phase 0 — Security and architecture baseline

Status: **Complete**

### Slice 0.1 — Product and security boundary

- [x] Record MVP and non-MVP scope.
- [x] Draft the initial threat model.
- [x] Draft non-negotiable security invariants.
- [x] Draft the initial domain contract.
- [x] Draft the API-first modular-monolith ADR.
- [x] Resolve and approve the decisions in `docs/decisions-required.md`.
- [x] Mark the accepted ADR, RFC, security documents, and domain contract as
  approved baselines.

Exit evidence:

- The trust boundaries, protected assets, and principal threats are explicit.
- Architecture and public-contract choices that need user approval are
  recorded rather than silently assumed.
- No production code depends on a proposed decision.

## Phase 1 — Executable security foundation

Status: **Complete**

### Slice 1.1 — Repository and quality skeleton

Status: **Complete**

- [x] Establish the approved backend workspace.
- [x] Add format, lint, unit-test, integration-test, dependency-audit, and secret
  scanning commands.
- [x] Add CI after the remote repository is attached.
- [x] Add configuration parsing with production-safe validation.
- [x] Add health and readiness behavior without exposing sensitive state.

Exit evidence:

- The standard-library Go service builds from the approved module workspace.
- Unit and integration tests cover configuration rejection, readiness
  fail-closed behavior, probe response minimization, and readiness lifecycle.
- CI runs formatting, vet, race-enabled tests, dependency audit, and Gitleaks
  worktree and history scans with read-only permissions.
- Production startup remains blocked until its required security dependencies
  and approval gates are complete.
- Operational probes are unversioned, non-cacheable, bodyless, and outside the
  public REST contract.

### Slice 1.2 — Encryption boundary

Status: **Complete**

- [x] Define the `KekProvider` port and production-provider contract.
- [x] Implement a test-only deterministic fake.
- [x] Implement AES-256-GCM envelope encryption with versioned canonical AAD.
- [x] Enforce one DEK per secret version.
- [x] Add known-answer, tamper, wrong-context, and provider-failure tests.
- [x] Prove that plaintext and unwrapped DEKs are never persisted or logged.

Exit evidence:

- Encryption and decryption fail closed.
- Ciphertext cannot be moved across tenant, project, environment, secret, or
  version context.
- Production startup rejects test and local-only key providers.
- The [Encryption Boundary](security/encryption-boundary.md) records the
  format, provider contract, verification evidence, and residual risks.

## Phase 2 — Identity and authorization foundation

Status: **Not started**

### Slice 2.1 — Human identity boundary

- Verify OIDC tokens from an approved issuer.
- Map immutable issuer and subject identifiers to an internal principal.
- Reject ambiguous issuer, audience, time, or signature state.

### Slice 2.2 — Service tokens

- Issue high-entropy opaque tokens and display the plaintext once.
- Persist only a non-reversible verifier and token metadata.
- Support expiry, revocation, last-used metadata, and scoped authorization.
- Add safe token prefixes for identification without granting authority.

### Slice 2.3 — Deny-by-default RBAC

- Define the minimal approved roles and permissions.
- Authorize every use case against tenant and resource scope.
- Add a permission matrix and negative contract tests.

Exit evidence:

- Anonymous, cross-tenant, expired, revoked, and insufficiently scoped access
  is denied.
- Authorization policy is tested independently of transport code.

## Phase 3 — Audited project and environment management

Status: **Blocked by Phase 2**

### Slice 3.1 — Project lifecycle

- Create, read, list, update, archive, and restore projects.
- Enforce stable identifiers and tenant isolation.
- Record audit events in the same transaction as state changes.

### Slice 3.2 — Environment lifecycle

- Create the Development, Staging, and Production defaults.
- Implement the approved environment naming and lifecycle policy.
- Prevent ambiguous or cross-project references.

Exit evidence:

- Every successful mutation produces an audit record.
- Failed and denied attempts produce the approved security audit signal
  without leaking sensitive input.

## Phase 4 — Secret lifecycle

Status: **Blocked by Phase 3**

### Slice 4.1 — Write and metadata operations

- Create a logical secret and its first immutable encrypted version.
- Add new versions without modifying historical ciphertext.
- List and read metadata without decrypting values.
- Implement archive and recoverable deletion semantics.

### Slice 4.2 — Secret access

- Reveal only an explicitly selected authorized version.
- Audit access without recording plaintext or a reversible derivative.
- Enforce response and cache controls that prevent accidental persistence.
- Add concurrency, tamper, rollback, and cross-scope regression tests.

Exit evidence:

- Plaintext is returned only by the explicit access operation.
- Listing, history, audit, and errors never contain secret values.
- Concurrent writes produce a deterministic version order.

## Phase 5 — Stable REST API and OpenAPI

Status: **Blocked by Phase 4**

- Approve the versioned REST resource model and error format.
- Publish and validate OpenAPI.
- Add request limits, idempotency where required, pagination, and safe
  concurrency controls.
- Run generated-client and backward-compatibility contract tests.

Exit evidence:

- The public contract is reviewable independently of implementation.
- CI detects unintended breaking changes.

## Phase 6 — CLI

Status: **Blocked by Phase 5**

- Implement secure authentication and local configuration.
- Add project, environment, secret, version, and audit workflows.
- Avoid plaintext in command history, process arguments, debug output, and
  shell completion.
- Add machine-readable output and non-interactive CI behavior.

## Phase 7 — Web dashboard

Status: **Blocked by Phase 5**

- Implement project, environment, secret metadata, access, token, RBAC, and
  audit workflows.
- Make secret reveal explicit, short-lived, and resistant to accidental
  copying or caching.
- Complete accessibility, security-header, session, and browser regression
  tests.

## MVP release gate

- All phases above are complete.
- Independent threat-model and authorization review is complete.
- Backup restore, key-provider outage, migration recovery, and incident
  runbooks have been exercised.
- The public API, CLI behavior, and operator documentation are versioned.
- No excluded roadmap feature is required for safe operation of the MVP.
