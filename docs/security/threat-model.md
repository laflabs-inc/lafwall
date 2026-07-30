# Threat Model

Status: **Accepted baseline**

Accepted: 2026-07-30

This is a living security baseline. It must be reviewed when a trust boundary,
protected asset, production provider, public API, or deployment model changes.

## Scope

This model covers the Laf Secrets MVP control plane, REST API, persistent
storage, key-encryption provider boundary, CLI, dashboard, human OIDC
authentication, service tokens, RBAC, and audit events.

Dynamic credentials, credential rotation, PKI, SSH certificates, Kubernetes
Operator behavior, multi-region replication, and HSM integration are outside
the MVP model.

## Protected assets

- Secret plaintext and historical values
- Data-encryption keys and production key-encryption authority
- Human sessions, OIDC tokens, and service tokens
- Tenant, project, environment, membership, and RBAC state
- Audit records and security-relevant metadata
- Ciphertext, wrapped DEKs, backups, and configuration
- Availability and integrity of the secret access path

Ciphertext and wrapped keys remain sensitive even though they are not
plaintext.

## Actors

- Authorized human user
- Authorized workload using a service token
- Tenant administrator
- Laf Secrets operator
- Compromised or malicious tenant member
- External unauthenticated attacker
- Attacker with read access to the application database or backups
- Attacker controlling a network, proxy, log sink, or observability system
- Compromised application process
- Compromised or unavailable key provider

## Trust boundaries

1. User or workload to the Laf Secrets API
2. Dashboard or CLI to the public REST contract
3. Transport adapters to application use cases
4. Application use cases to authorization policy
5. Application to PostgreSQL
6. Encryption service to the external `KekProvider`
7. Application to OIDC issuer and JWK retrieval
8. Application to audit and observability destinations
9. Backup and restore path

Crossing a boundary requires explicit authentication, validation, and a
failure policy. Internal network location is not proof of trust.

## Primary threats and required controls

<!-- markdownlint-disable MD013 -->

| Threat | Example | Required control |
| --- | --- | --- |
| Credential theft | Service token appears in source or logs | One-time display, non-reversible verifier, safe prefix, allowlisted logging, expiry and revocation |
| Broken object authorization | A valid user changes a project ID to access another tenant | Deny-by-default use-case authorization, tenant-scoped queries, negative integration tests |
| Ciphertext substitution | A database attacker moves ciphertext to a different secret or version | Canonical AAD bound to stable resource and version IDs |
| Nonce or key reuse | Encryption repeats a GCM key/nonce pair | Fresh DEK per version and CSPRNG nonce generation |
| Database disclosure | Attacker reads the primary database or backup | Envelope encryption, KEK outside database, encrypted backups, no plaintext persistence |
| Log or telemetry disclosure | Request body, header, or error captures a secret | Allowlisted fields, body capture disabled, secret-safe errors, regression tests |
| Privilege escalation | A project editor grants themselves secret access | Separate permissions for membership, policy, metadata, and plaintext access; tested permission matrix |
| Audit tampering | An operator removes evidence of access | Append-only runtime role, atomic event writes, restricted retention path, later external export boundary |
| Replay or stale authorization | A revoked token continues to work | Opaque token lookup on use, revocation state, expiry, cache limits |
| OIDC confusion | Token from another issuer or audience is accepted | Exact issuer and audience checks, algorithm allowlist, immutable issuer/subject mapping |
| Resource exhaustion | Oversized secret values or unbounded list requests | Explicit size, rate, pagination, and concurrency limits |
| Key-provider outage | KMS becomes unavailable during a write or reveal | Bounded retries, readiness degradation, fail closed, no plaintext fallback |
| Rollback attack | Older database state silently becomes current | Immutable versions, monotonic sequencing, audit correlation, restore procedures |
| Supply-chain compromise | Dependency or build pipeline injects malicious code | Locked dependencies, review, provenance, dependency audit, minimal build permissions |
| Browser persistence | Dashboard or proxy caches revealed plaintext | Explicit reveal flow, no-store headers, no persistent client state, capture-disabled telemetry |
| CLI leakage | Secret appears in shell history or process list | stdin/file-descriptor input, masked prompt, no value in argv, safe debug mode |

<!-- markdownlint-enable MD013 -->

## Critical abuse cases to test

1. A principal from tenant A attempts every operation against tenant B IDs.
2. Ciphertext, wrapped DEK, nonce, or AAD from one version is substituted into
   another.
3. A revoked or expired service token is replayed.
4. An authenticated project administrator lacks plaintext-access permission.
5. Database and key-provider operations fail independently during a mutation.
6. Audit persistence fails during secret access or policy modification.
7. Concurrent writers attempt to create the same next secret version.
8. Logs, traces, errors, fixtures, snapshots, and audit exports are scanned for
   known canary secret values.
9. Backup restore occurs with missing, wrong, and rotated KEK references.
10. A dashboard or CLI error occurs after plaintext has been received.

## Assumptions

- TLS is terminated only by approved infrastructure and plaintext is not
  captured at the edge.
- Production key-provider identity and permissions are configured outside the
  application database.
- Host, container, and deployment hardening are separate operator
  responsibilities documented before production release.
- Full application-process compromise may expose plaintext being actively
  processed. The MVP reduces exposure but does not claim confidential
  computing.

## Residual risks

- A compromised running application with valid key-provider authority can
  decrypt data that its runtime identity is allowed to access.
- Application-level append-only audit controls do not protect against every
  privileged database or infrastructure administrator. External immutable
  export is a future hardening boundary.
- Soft deletion preserves recoverability but does not provide immediate
  cryptographic erasure.
- Metadata such as project names, secret names, access timing, and ciphertext
  sizes may reveal operational information and must be access-controlled.

These risks must be reflected in operator documentation and must not be hidden
by stronger product claims.
