# Human Identity Boundary

Status: **Implemented — Slice 2.1**

This boundary verifies OIDC ID tokens from one explicitly approved issuer and
maps the immutable issuer and subject claims to an internal human principal.
It implements the accepted identity policy without creating an HTTP, session,
database, or public API contract.

## Trust configuration

`HumanVerifierConfig` requires all trust inputs before a token is processed:

- an exact HTTPS issuer URL without user information, query, or fragment;
- one exact audience identifier; and
- a non-empty allowlist of asymmetric signing algorithms.

Symmetric MAC algorithms and `none` are rejected by configuration. The
allowlist is copied when the verifier is constructed, so later caller mutation
cannot broaden trust.

The caller also supplies a `KeySet` that verifies signatures with public keys
belonging to the configured issuer. A `KeySet` must never choose an issuer,
discovery URL, or JWKS URL from an unverified token claim. Remote discovery and
JWKS retrieval are deliberately not implemented in this Slice.

## Token validation

The boundary uses `go-oidc` and `go-jose` rather than implementing JWT or
signature primitives. Verification fails closed unless all of the following
are true:

1. The compact ID token is present and no larger than 16 KiB.
2. Its signature verifies under a caller-allowed asymmetric algorithm.
3. `iss` exactly matches the configured issuer.
4. `aud` contains exactly one value and it exactly matches the configured
   audience.
5. An optional `azp` claim, when present, exactly matches that same audience.
6. Duplicate top-level claims are absent.
7. `exp` is present and strictly later than the current time.
8. `iat` is present, is not in the future, and is strictly earlier than
   `exp`.
9. An optional `nbf` is not in the future and is strictly earlier than `exp`.
10. `sub` is between 1 and 255 visible ASCII characters.
11. A flow nonce is either absent on both sides or exactly matches the
    caller-provided expected nonce.

The application boundary does not add clock-skew grace. Operators must keep
application and issuer clocks synchronized; an approved provider adapter may
not silently weaken these time checks.

Nonce comparison is constant-time when a nonce is expected. Tokens carrying a
nonce are rejected if the caller does not supply the corresponding expected
value, preventing a transport adapter from accidentally ignoring flow state.

## Principal mapping

A successful verification returns `HumanPrincipal`, keyed only by the exact
`(issuer, subject)` pair. Email, name, and other profile claims are ignored for
identity. The principal fields cannot be constructed or modified outside the
identity package, and its zero value is invalid.

The same subject from two issuers maps to two different principals. Profile
changes from the same issuer and subject do not change principal identity.

## Failure and data-handling policy

- Raw ID tokens are accepted as method input and are not retained.
- Authentication, parsing, claim, signature, key, and nonce failures return
  the same `ErrUnauthenticated` value.
- Dependency errors, claim values, and raw tokens are not wrapped into returned
  errors.
- Caller context cancellation remains distinguishable so work can stop
  promptly without exposing an authentication failure reason.
- This package does not log, persist, emit telemetry, or produce audit events.

Transport adapters must also avoid logging authorization headers or tokens.
Future audit events may record only safe principal identifiers and outcomes,
never raw authentication material.

## KeySet contract

A future remote `KeySet` adapter must:

- derive discovery and JWKS endpoints only from approved configuration;
- require authenticated HTTPS and reject redirects outside the approved trust
  boundary;
- apply request deadlines, response-size limits, bounded refresh behavior, and
  safe key caching;
- handle rotation without accepting an unknown issuer or algorithm, and reject
  unknown or ambiguous key selection;
- be safe for concurrent use and respect caller cancellation; and
- never retain or log raw tokens, and return errors without tokens, key
  material, response bodies, or sensitive provider details.

Provider discovery, Production Laf ID values, HTTP authentication wiring, and
readiness integration remain separate work. Production startup is still
unavailable.

## Verification evidence

Unit tests generate ephemeral test-only RSA keys and synthetic signed tokens at
runtime. They cover:

- successful signature verification and immutable principal mapping;
- issuer, audience, `azp`, algorithm, signature, and nonce rejection;
- expiry, issued-at, and not-before rejection;
- duplicate security claims and malformed claim types;
- subject bounds and cross-issuer identity separation;
- input-size enforcement before signature work;
- configuration immutability and fail-closed typed-nil handling; and
- sanitized dependency failures and context cancellation.

No token literal or private key is stored in source, fixtures, snapshots, or
logs. There is no database migration or public API change in this Slice.

## Residual risks and deferred work

- The approved Laf ID issuer URL, audience, signing profile, and JWKS endpoint
  are not yet configured.
- OAuth authorization redirects, state, PKCE, code exchange, session behavior,
  and companion access-token hash validation are outside this internal token
  boundary.
- HTTP endpoints do not accept human credentials yet.
- Key retrieval outage behavior cannot participate in readiness until a remote
  provider adapter exists.
- Service tokens and deny-by-default authorization remain Slice 2.2 and Slice
  2.3 work.

These limits prevent this implementation from being treated as Production
identity readiness.
