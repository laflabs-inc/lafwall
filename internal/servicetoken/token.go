package servicetoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	credentialVersion = "lafst_v1"
	credentialDomain  = "lafsecrets.service-token.verifier.v1"

	tokenIDBytes         = 16
	tokenSecretBytes     = 32
	encodedTokenIDBytes  = 22
	encodedSecretBytes   = 43
	safeIdentifierBytes  = 8
	maximumTenantIDBytes = 255
)

var (
	ErrInvalidScope     = errors.New("invalid service token scope")
	ErrInvalidLifecycle = errors.New("invalid service token lifecycle")
	ErrIssuance         = errors.New("service token issuance failed")
	ErrUnauthenticated  = errors.New("service token authentication failed")
)

// Status is the authoritative lifecycle state of a service token.
type Status uint8

const (
	StatusActive Status = iota + 1
	StatusRevoked
)

func (s Status) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusRevoked:
		return "revoked"
	default:
		return "invalid"
	}
}

// Scope binds a service token to exactly one tenant. It is an authentication
// boundary, not an authorization grant. A caller must still apply the
// deny-by-default permission policy before every resource operation.
type Scope struct {
	tenantID string
}

func NewTenantScope(tenantID string) (Scope, error) {
	if !validOpaqueIdentifier(tenantID, maximumTenantIDBytes) {
		return Scope{}, ErrInvalidScope
	}
	return Scope{tenantID: tenantID}, nil
}

func (s Scope) TenantID() string {
	return s.tenantID
}

func (s Scope) Valid() bool {
	return validOpaqueIdentifier(s.tenantID, maximumTenantIDBytes)
}

func (s Scope) MatchesTenant(tenantID string) bool {
	return s.Valid() && s.tenantID == tenantID
}

// Record is the persistent representation of a service token. It deliberately
// contains neither the plaintext credential nor the random secret from which
// the verifier was derived.
//
// Database adapters added in a later storage slice must persist this state as
// sensitive metadata and must not expose it through general-purpose logging.
type Record struct {
	tokenID    [tokenIDBytes]byte
	verifier   [sha256.Size]byte
	scope      Scope
	status     Status
	createdAt  time.Time
	expiresAt  time.Time
	revokedAt  time.Time
	lastUsedAt time.Time
}

func (r Record) ID() string {
	if allZero(r.tokenID[:]) {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(r.tokenID[:])
}

// SafePrefix is display-only metadata and never grants access.
func (r Record) SafePrefix() string {
	id := r.ID()
	if len(id) < safeIdentifierBytes {
		return ""
	}
	return credentialVersion + "." + id[:safeIdentifierBytes]
}

func (r Record) Scope() Scope {
	return r.scope
}

func (r Record) Status() Status {
	return r.status
}

func (r Record) CreatedAt() time.Time {
	return r.createdAt
}

func (r Record) ExpiresAt() time.Time {
	return r.expiresAt
}

func (r Record) RevokedAt() time.Time {
	return r.revokedAt
}

func (r Record) LastUsedAt() time.Time {
	return r.lastUsedAt
}

func (r Record) Valid() bool {
	if allZero(r.tokenID[:]) ||
		allZero(r.verifier[:]) ||
		!r.scope.Valid() ||
		r.createdAt.IsZero() ||
		r.expiresAt.IsZero() ||
		!r.createdAt.Before(r.expiresAt) ||
		(!r.lastUsedAt.IsZero() &&
			(r.lastUsedAt.Before(r.createdAt) ||
				!r.lastUsedAt.Before(r.expiresAt))) {
		return false
	}

	switch r.status {
	case StatusActive:
		return r.revokedAt.IsZero()
	case StatusRevoked:
		return !r.revokedAt.IsZero() &&
			!r.revokedAt.Before(r.createdAt) &&
			(r.lastUsedAt.IsZero() || !r.revokedAt.Before(r.lastUsedAt))
	default:
		return false
	}
}

// Revoke returns a new immutable record. Persistence and its mandatory audit
// event must be committed atomically by a later application/storage boundary.
func (r Record) Revoke(at time.Time) (Record, error) {
	if !r.Valid() {
		return Record{}, ErrInvalidLifecycle
	}
	if r.status == StatusRevoked {
		return r, nil
	}

	at = normalizeTime(at)
	if at.IsZero() ||
		at.Before(r.createdAt) ||
		(!r.lastUsedAt.IsZero() && at.Before(r.lastUsedAt)) {
		return Record{}, ErrInvalidLifecycle
	}

	r.status = StatusRevoked
	r.revokedAt = at
	return r, nil
}

// String and GoString prevent routine formatting from disclosing the verifier
// or lifecycle metadata. Structured logging must still allowlist fields.
func (Record) String() string {
	return "service token record [redacted]"
}

func (Record) GoString() string {
	return "servicetoken.Record{redacted}"
}

// ServicePrincipal is the immutable identity produced by a successfully
// authenticated service token. Its tenant scope is not a permission grant.
type ServicePrincipal struct {
	tokenID  [tokenIDBytes]byte
	tenantID string
}

func (p ServicePrincipal) TokenID() string {
	if allZero(p.tokenID[:]) {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(p.tokenID[:])
}

func (p ServicePrincipal) TenantID() string {
	return p.tenantID
}

func (p ServicePrincipal) Valid() bool {
	return !allZero(p.tokenID[:]) &&
		validOpaqueIdentifier(p.tenantID, maximumTenantIDBytes)
}

func (p ServicePrincipal) MatchesTenant(tenantID string) bool {
	return p.Valid() && p.tenantID == tenantID
}

func (ServicePrincipal) String() string {
	return "service principal [redacted]"
}

func (ServicePrincipal) GoString() string {
	return "servicetoken.ServicePrincipal{redacted}"
}

// Issuer creates high-entropy opaque service-token credentials. The returned
// plaintext string is the sole reveal boundary: callers must deliver it once
// and must never persist, log, audit, or emit it as telemetry.
type Issuer struct {
	random io.Reader
	now    func() time.Time
}

func NewIssuer() *Issuer {
	return &Issuer{random: rand.Reader, now: time.Now}
}

func newIssuer(random io.Reader, now func() time.Time) (*Issuer, error) {
	if random == nil || now == nil {
		return nil, ErrIssuance
	}
	return &Issuer{random: random, now: now}, nil
}

func (i *Issuer) Issue(
	ctx context.Context,
	scope Scope,
	expiresAt time.Time,
) (Record, string, error) {
	if i == nil || i.random == nil || i.now == nil || ctx == nil || !scope.Valid() {
		return Record{}, "", ErrIssuance
	}
	if err := ctx.Err(); err != nil {
		return Record{}, "", err
	}

	createdAt := normalizeTime(i.now())
	expiresAt = normalizeTime(expiresAt)
	if createdAt.IsZero() || expiresAt.IsZero() || !createdAt.Before(expiresAt) {
		return Record{}, "", ErrInvalidLifecycle
	}

	var tokenID [tokenIDBytes]byte
	var secret [tokenSecretBytes]byte
	defer clear(secret[:])

	if _, err := io.ReadFull(i.random, tokenID[:]); err != nil {
		return Record{}, "", issuanceError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return Record{}, "", err
	}
	if _, err := io.ReadFull(i.random, secret[:]); err != nil {
		return Record{}, "", issuanceError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return Record{}, "", err
	}
	if allZero(tokenID[:]) || allZero(secret[:]) {
		return Record{}, "", ErrIssuance
	}

	credential := credentialVersion + "." +
		base64.RawURLEncoding.EncodeToString(tokenID[:]) + "." +
		base64.RawURLEncoding.EncodeToString(secret[:])
	record := Record{
		tokenID:   tokenID,
		verifier:  deriveVerifier(tokenID[:], secret[:]),
		scope:     scope,
		status:    StatusActive,
		createdAt: createdAt,
		expiresAt: expiresAt,
	}
	if !record.Valid() {
		return Record{}, "", ErrIssuance
	}

	return record, credential, nil
}

// Authenticator verifies a credential against a freshly loaded authoritative
// Record. Callers must not cache active state. A future storage adapter must
// make the successful last-used update conditional on the same active record
// revision so that concurrent revocation wins and authentication fails closed.
type Authenticator struct {
	now func() time.Time
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{now: time.Now}
}

func newAuthenticator(now func() time.Time) (*Authenticator, error) {
	if now == nil {
		return nil, ErrUnauthenticated
	}
	return &Authenticator{now: now}, nil
}

func (a *Authenticator) AuthenticateForTenant(
	ctx context.Context,
	credential string,
	record Record,
	tenantID string,
) (ServicePrincipal, Record, error) {
	if a == nil || a.now == nil || ctx == nil {
		return ServicePrincipal{}, Record{}, ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return ServicePrincipal{}, Record{}, err
	}

	tokenID, secret, ok := decodeCredential(credential)
	if !ok {
		return ServicePrincipal{}, Record{}, ErrUnauthenticated
	}
	defer clear(secret[:])

	candidateVerifier := deriveVerifier(tokenID[:], secret[:])
	defer clear(candidateVerifier[:])
	now := normalizeTime(a.now())
	idMatches := subtle.ConstantTimeCompare(tokenID[:], record.tokenID[:])
	verifierMatches := subtle.ConstantTimeCompare(
		candidateVerifier[:],
		record.verifier[:],
	)

	valid := record.Valid() &&
		record.status == StatusActive &&
		!now.IsZero() &&
		!now.Before(record.createdAt) &&
		now.Before(record.expiresAt) &&
		(record.lastUsedAt.IsZero() || !now.Before(record.lastUsedAt)) &&
		record.scope.MatchesTenant(tenantID)
	if !valid || idMatches != 1 || verifierMatches != 1 {
		return ServicePrincipal{}, Record{}, ErrUnauthenticated
	}

	updated := record
	if updated.lastUsedAt.IsZero() || now.After(updated.lastUsedAt) {
		updated.lastUsedAt = now
	}
	principal := ServicePrincipal{
		tokenID:  record.tokenID,
		tenantID: record.scope.tenantID,
	}
	if !updated.Valid() || !principal.Valid() {
		return ServicePrincipal{}, Record{}, ErrUnauthenticated
	}

	return principal, updated, nil
}

func decodeCredential(
	credential string,
) ([tokenIDBytes]byte, [tokenSecretBytes]byte, bool) {
	var tokenID [tokenIDBytes]byte
	var secret [tokenSecretBytes]byte

	parts := strings.Split(credential, ".")
	if len(parts) != 3 ||
		parts[0] != credentialVersion ||
		len(parts[1]) != encodedTokenIDBytes ||
		len(parts[2]) != encodedSecretBytes {
		return tokenID, secret, false
	}

	encoding := base64.RawURLEncoding.Strict()
	decodedID, err := encoding.Decode(tokenID[:], []byte(parts[1]))
	if err != nil || decodedID != tokenIDBytes {
		return [tokenIDBytes]byte{}, [tokenSecretBytes]byte{}, false
	}
	decodedSecret, err := encoding.Decode(secret[:], []byte(parts[2]))
	if err != nil || decodedSecret != tokenSecretBytes {
		clear(secret[:])
		return [tokenIDBytes]byte{}, [tokenSecretBytes]byte{}, false
	}
	if allZero(tokenID[:]) || allZero(secret[:]) {
		clear(secret[:])
		return [tokenIDBytes]byte{}, [tokenSecretBytes]byte{}, false
	}

	return tokenID, secret, true
}

func deriveVerifier(
	tokenID []byte,
	secret []byte,
) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = io.WriteString(hash, credentialDomain)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(tokenID)
	_, _ = hash.Write(secret)

	var verifier [sha256.Size]byte
	copy(verifier[:], hash.Sum(nil))
	return verifier
}

func validOpaqueIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func normalizeTime(value time.Time) time.Time {
	return value.Round(0).UTC()
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func issuanceError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrIssuance
}

func (r Record) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, r.String())
}

func (p ServicePrincipal) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, p.String())
}
