# Encryption Boundary

Status: **Implemented baseline**

Implemented: 2026-07-31

This document records the implementation contract for Roadmap Slice 1.2. It
applies the accepted [Security Invariants](security-invariants.md) without
selecting a Production KMS, defining a Database schema, or publishing an API
contract.

## Responsibilities

The `internal/encryption` package:

- generates a fresh 256-bit DEK for every encryption operation with
  `crypto/rand`;
- encrypts plaintext with the Go standard library's AES-256-GCM
  implementation;
- generates a fresh 96-bit GCM nonce for every envelope;
- authenticates the immutable Secret Version context as canonical AAD;
- delegates DEK wrapping and unwrapping to a `KekProvider`;
- returns a versioned Envelope containing only Ciphertext and key metadata;
- clears the directly managed plaintext DEK buffers after use; and
- returns sanitized errors without provider details or sensitive values.

The package has no storage, logging, telemetry, HTTP, or Production provider
dependency. It does not decide whether a Principal may encrypt or reveal a
value; authorization remains an Application Use Case responsibility.

## Canonical AAD version 1

AAD version 1 is a byte sequence in this exact order:

1. the fixed bytes `LAFSECRETS`, a zero byte, `SECRET-VERSION`, and a zero byte;
2. an unsigned 16-bit big-endian AAD format version;
3. an unsigned 16-bit big-endian Envelope format version;
4. each of Tenant ID, Project ID, Environment ID, Secret ID, and Secret Version
   ID as an unsigned 32-bit big-endian UTF-8 byte length followed by those
   bytes; and
5. the unsigned 64-bit big-endian Secret Version sequence.

Every identifier must be non-empty valid UTF-8 and the sequence begins at one.
Length prefixes prevent ambiguous concatenation. The fixed domain separates
this AAD from other current or future cryptographic uses.

Changing the order, encoding, domain, or meaning requires a new AAD format
version, compatibility tests, and an approved migration or forward-recovery
plan. Existing Ciphertext must never be silently reinterpreted.

## Envelope format version 1

An Envelope persists these fields together:

- Envelope format version;
- AAD format version;
- Data Encryption algorithm identifier (`AES-256-GCM`);
- Key Wrapping algorithm identifier;
- external KEK reference;
- 96-bit Nonce;
- Ciphertext including the GCM Authentication Tag; and
- opaque Wrapped DEK.

Decryption rejects unknown versions or algorithms, incomplete metadata,
malformed Nonces, and Ciphertext shorter than a GCM tag before asking the
provider to unwrap a key. Authentication failure and wrong resource context
return no plaintext.

Envelope fields, including Ciphertext and Wrapped DEKs, remain sensitive and
must not be logged or exposed through Metadata operations.

## `KekProvider` contract

A Production provider must:

- hold KEK authority outside the Laf Secrets Database;
- use a reviewed provider SDK or established library;
- never export, persist, retain, or log a plaintext DEK;
- return opaque Wrapped Key bytes, a stable KEK reference, and an algorithm
  identifier;
- reject unknown or mismatched KEK references and wrapping algorithms;
- return a caller-owned 32-byte DEK buffer from unwrap;
- be safe for concurrent use and respect Context cancellation;
- avoid sensitive values in errors; and
- fail closed without a plaintext or local-key fallback.

The Encryption Service copies provider output before constructing an Envelope,
clears unwrapped key buffers, sanitizes provider failures, and rejects a
provider that returns the plaintext DEK verbatim as its Wrapped Key.

The deterministic provider used by tests exists only in a `_test.go` file. It
is stateful, memory-only, and is not available to an Application build.
Production startup remains unavailable, so no test or local provider can be
selected accidentally.

## Verification evidence

Unit tests cover:

- a fixed AES-256-GCM and canonical-AAD known-answer vector;
- successful round trips;
- distinct DEKs and Nonces for repeated operations;
- tampered Ciphertext, Nonce, and Wrapped DEK;
- wrong Tenant, Project, Environment, Secret, Version ID, and sequence;
- unknown Envelope versions and algorithms;
- invalid Bindings and provider output;
- provider, random-source, and cancellation failures;
- sanitized errors;
- absence of plaintext and unwrapped DEKs from Envelope fields; and
- clearing the DEK buffers directly managed by the service.

CI runs these tests with the race detector, `go vet`, `govulncheck`, and
worktree and full-history Gitleaks scans.

## Security impact and residual risk

This boundary mitigates Database disclosure and Ciphertext substitution by
separating KEK custody and binding Ciphertext to its immutable domain context.
It does not claim to protect plaintext from a fully compromised Application
process while that plaintext is actively being handled.

Go and the standard library may make internal key-schedule or plaintext
copies that Application code cannot reliably erase. The implementation
minimizes explicit copies and clears buffers it owns, but it does not claim
guaranteed memory erasure. Confidential computing and HSM Integration remain
outside the MVP.

A Production provider selection, provider-specific outage policy, Database
Envelope schema, backup behavior, and key rotation procedure remain approval
gates before Production can start.
