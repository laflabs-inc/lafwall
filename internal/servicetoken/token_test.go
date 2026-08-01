package servicetoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

const testTenantID = "tenant-test-01"

func TestIssueAndAuthenticateForExactTenant(t *testing.T) {
	t.Parallel()

	createdAt := testNow()
	scope := testScope(t, testTenantID)
	issuer := testIssuer(t, createdAt, entropyBytes(1, 48))
	record, credential, err := issuer.Issue(
		context.Background(),
		scope,
		createdAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !record.Valid() {
		t.Fatal("Issue() returned an invalid record")
	}
	if record.Status() != StatusActive {
		t.Fatalf("Status() = %v, want active", record.Status())
	}
	if record.Scope() != scope {
		t.Fatal("Scope() did not preserve the exact tenant scope")
	}
	if record.CreatedAt() != createdAt ||
		record.ExpiresAt() != createdAt.Add(time.Hour) {
		t.Fatal("Issue() did not preserve normalized lifecycle times")
	}
	if !record.LastUsedAt().IsZero() || !record.RevokedAt().IsZero() {
		t.Fatal("a newly issued record contains use or revocation metadata")
	}

	parts := strings.Split(credential, ".")
	if len(parts) != 3 || parts[0] != credentialVersion {
		t.Fatal("Issue() returned a non-canonical credential")
	}
	if record.ID() != parts[1] {
		t.Fatal("Record ID does not match the public credential identifier")
	}
	wantSafePrefix := credentialVersion + "." + parts[1][:safeIdentifierBytes]
	if record.SafePrefix() != wantSafePrefix {
		t.Fatalf("SafePrefix() = %q, want %q", record.SafePrefix(), wantSafePrefix)
	}

	usedAt := createdAt.Add(5 * time.Minute)
	authenticator := testAuthenticator(t, usedAt)
	principal, updated, err := authenticator.AuthenticateForTenant(
		context.Background(),
		credential,
		record,
		testTenantID,
	)
	if err != nil {
		t.Fatalf("AuthenticateForTenant() error = %v", err)
	}
	if !principal.Valid() ||
		principal.TokenID() != record.ID() ||
		principal.TenantID() != testTenantID ||
		!principal.MatchesTenant(testTenantID) ||
		principal.MatchesTenant("tenant-test-other") {
		t.Fatal("AuthenticateForTenant() returned an invalid scoped principal")
	}
	if updated.LastUsedAt() != usedAt {
		t.Fatalf("LastUsedAt() = %v, want %v", updated.LastUsedAt(), usedAt)
	}
	if !record.LastUsedAt().IsZero() {
		t.Fatal("AuthenticateForTenant() mutated the input record")
	}
}

func TestIssueUsesFreshIdentifierAndSecret(t *testing.T) {
	t.Parallel()

	now := testNow()
	issuer := testIssuer(t, now, entropyBytes(1, 96))
	scope := testScope(t, testTenantID)

	firstRecord, firstCredential, err := issuer.Issue(
		context.Background(),
		scope,
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("first Issue() error = %v", err)
	}
	secondRecord, secondCredential, err := issuer.Issue(
		context.Background(),
		scope,
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("second Issue() error = %v", err)
	}

	if firstCredential == secondCredential ||
		firstRecord.tokenID == secondRecord.tokenID ||
		firstRecord.verifier == secondRecord.verifier {
		t.Fatal("Issue() reused credential entropy")
	}
}

func TestRecordDoesNotRetainOrFormatPlaintextCredential(t *testing.T) {
	t.Parallel()

	now := testNow()
	record, credential, err := testIssuer(
		t,
		now,
		entropyBytes(33, 48),
	).Issue(
		context.Background(),
		testScope(t, testTenantID),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	parts := strings.Split(credential, ".")
	formatted := fmt.Sprintf("%+v %#v", record, record)
	if strings.Contains(formatted, credential) ||
		strings.Contains(formatted, parts[2]) ||
		strings.Contains(formatted, record.ID()) ||
		strings.Contains(formatted, testTenantID) {
		t.Fatal("Record formatting disclosed credential or sensitive metadata")
	}
	if !strings.Contains(formatted, "redacted") {
		t.Fatal("Record formatting does not identify redacted output")
	}

	secret := decodeTestPart(t, parts[2], tokenSecretBytes)
	if bytes.Equal(record.verifier[:], secret) {
		t.Fatal("Record retained the plaintext credential secret as its verifier")
	}
}

func TestIssueRejectsInvalidLifecycleAndDependencies(t *testing.T) {
	t.Parallel()

	now := testNow()
	validScope := testScope(t, testTenantID)
	validIssuer := testIssuer(t, now, entropyBytes(1, 96))

	tests := map[string]struct {
		issuer    *Issuer
		ctx       context.Context
		scope     Scope
		expiresAt time.Time
		want      error
	}{
		"nil issuer": {
			issuer:    nil,
			ctx:       context.Background(),
			scope:     validScope,
			expiresAt: now.Add(time.Hour),
			want:      ErrIssuance,
		},
		"nil context": {
			issuer:    validIssuer,
			ctx:       nil,
			scope:     validScope,
			expiresAt: now.Add(time.Hour),
			want:      ErrIssuance,
		},
		"invalid scope": {
			issuer:    validIssuer,
			ctx:       context.Background(),
			scope:     Scope{},
			expiresAt: now.Add(time.Hour),
			want:      ErrIssuance,
		},
		"zero expiry": {
			issuer:    validIssuer,
			ctx:       context.Background(),
			scope:     validScope,
			expiresAt: time.Time{},
			want:      ErrInvalidLifecycle,
		},
		"expiry at issuance": {
			issuer:    validIssuer,
			ctx:       context.Background(),
			scope:     validScope,
			expiresAt: now,
			want:      ErrInvalidLifecycle,
		},
		"expiry before issuance": {
			issuer:    validIssuer,
			ctx:       context.Background(),
			scope:     validScope,
			expiresAt: now.Add(-time.Second),
			want:      ErrInvalidLifecycle,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			record, credential, err := test.issuer.Issue(
				test.ctx,
				test.scope,
				test.expiresAt,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Issue() error = %v, want %v", err, test.want)
			}
			if record.Valid() || credential != "" {
				t.Fatal("failed Issue() returned credential state")
			}
		})
	}
}

func TestIssueSanitizesEntropyFailure(t *testing.T) {
	t.Parallel()

	const marker = "entropy dependency detail"
	issuer, err := newIssuer(
		failingReader{err: errors.New(marker)},
		testClock(testNow()),
	)
	if err != nil {
		t.Fatalf("newIssuer() error = %v", err)
	}

	record, credential, err := issuer.Issue(
		context.Background(),
		testScope(t, testTenantID),
		testNow().Add(time.Hour),
	)
	if !errors.Is(err, ErrIssuance) {
		t.Fatalf("Issue() error = %v, want ErrIssuance", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("Issue() disclosed entropy dependency details")
	}
	if record.Valid() || credential != "" {
		t.Fatal("failed Issue() returned credential state")
	}
}

func TestIssueRejectsPartialAndZeroEntropy(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"short identifier": entropyBytes(1, tokenIDBytes-1),
		"short secret": entropyBytes(
			1,
			tokenIDBytes+tokenSecretBytes-1,
		),
		"zero identifier and secret": make(
			[]byte,
			tokenIDBytes+tokenSecretBytes,
		),
	}

	for name, entropy := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := testIssuer(t, testNow(), entropy)
			record, credential, err := issuer.Issue(
				context.Background(),
				testScope(t, testTenantID),
				testNow().Add(time.Hour),
			)
			if err != ErrIssuance {
				t.Fatalf("Issue() error = %v, want ErrIssuance", err)
			}
			if record.Valid() || credential != "" {
				t.Fatal("failed Issue() returned credential state")
			}
		})
	}
}

func TestIssuePreservesContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &countingReader{reader: bytes.NewReader(entropyBytes(1, 48))}
	issuer, err := newIssuer(reader, testClock(testNow()))
	if err != nil {
		t.Fatalf("newIssuer() error = %v", err)
	}

	record, credential, err := issuer.Issue(
		ctx,
		testScope(t, testTenantID),
		testNow().Add(time.Hour),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Issue() error = %v, want context.Canceled", err)
	}
	if reader.calls != 0 || record.Valid() || credential != "" {
		t.Fatal("canceled Issue() accessed entropy or returned credential state")
	}
}

func TestAuthenticateRejectsInvalidCredentialAndStateUniformly(t *testing.T) {
	t.Parallel()

	createdAt := testNow()
	scope := testScope(t, testTenantID)
	issuer := testIssuer(t, createdAt, entropyBytes(1, 96))
	record, credential, err := issuer.Issue(
		context.Background(),
		scope,
		createdAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	_, otherCredential, err := issuer.Issue(
		context.Background(),
		scope,
		createdAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("second Issue() error = %v", err)
	}
	revoked, err := record.Revoke(createdAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	parts := strings.Split(credential, ".")
	wrongSecret := mutateCredentialPart(t, credential, 2)
	wrongIdentifier := mutateCredentialPart(t, credential, 1)
	invalidEncoding := parts[0] + "." + parts[1] + "." +
		"*" + parts[2][1:]

	tests := map[string]struct {
		credential string
		record     Record
		tenantID   string
		now        time.Time
	}{
		"safe prefix only": {
			credential: record.SafePrefix(),
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"wrong secret": {
			credential: wrongSecret,
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"wrong identifier": {
			credential: wrongIdentifier,
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"other credential": {
			credential: otherCredential,
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"invalid encoding": {
			credential: invalidEncoding,
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"padded encoding": {
			credential: credential + "=",
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"extra segment": {
			credential: credential + ".extra",
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"unknown record": {
			credential: credential,
			record:     Record{},
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
		"wrong tenant": {
			credential: credential,
			record:     record,
			tenantID:   "tenant-test-other",
			now:        createdAt.Add(2 * time.Minute),
		},
		"expired": {
			credential: credential,
			record:     record,
			tenantID:   testTenantID,
			now:        record.ExpiresAt(),
		},
		"before creation": {
			credential: credential,
			record:     record,
			tenantID:   testTenantID,
			now:        createdAt.Add(-time.Second),
		},
		"revoked": {
			credential: credential,
			record:     revoked,
			tenantID:   testTenantID,
			now:        createdAt.Add(2 * time.Minute),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			authenticator := testAuthenticator(t, test.now)
			principal, updated, err := authenticator.AuthenticateForTenant(
				context.Background(),
				test.credential,
				test.record,
				test.tenantID,
			)
			assertUnauthenticated(t, principal, updated, err, test.credential)
		})
	}
}

func TestAuthenticateRejectsClockRollback(t *testing.T) {
	t.Parallel()

	createdAt := testNow()
	record, credential, err := testIssuer(
		t,
		createdAt,
		entropyBytes(1, 48),
	).Issue(
		context.Background(),
		testScope(t, testTenantID),
		createdAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	firstUse := createdAt.Add(10 * time.Minute)
	_, usedRecord, err := testAuthenticator(t, firstUse).AuthenticateForTenant(
		context.Background(),
		credential,
		record,
		testTenantID,
	)
	if err != nil {
		t.Fatalf("first AuthenticateForTenant() error = %v", err)
	}

	principal, updated, err := testAuthenticator(
		t,
		firstUse.Add(-time.Second),
	).AuthenticateForTenant(
		context.Background(),
		credential,
		usedRecord,
		testTenantID,
	)
	assertUnauthenticated(t, principal, updated, err, credential)
}

func TestAuthenticatePreservesContextCancellation(t *testing.T) {
	t.Parallel()

	now := testNow()
	record, credential, err := testIssuer(
		t,
		now,
		entropyBytes(1, 48),
	).Issue(
		context.Background(),
		testScope(t, testTenantID),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	principal, updated, err := testAuthenticator(
		t,
		now.Add(time.Minute),
	).AuthenticateForTenant(ctx, credential, record, testTenantID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("AuthenticateForTenant() error = %v, want context.Canceled", err)
	}
	if principal.Valid() || updated.Valid() {
		t.Fatal("canceled authentication returned state")
	}
}

func TestAuthenticateRejectsNilBoundaryAndZeroCredentialParts(t *testing.T) {
	t.Parallel()

	now := testNow()
	record, credential, err := testIssuer(
		t,
		now,
		entropyBytes(1, 48),
	).Issue(
		context.Background(),
		testScope(t, testTenantID),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	var nilAuthenticator *Authenticator
	principal, updated, err := nilAuthenticator.AuthenticateForTenant(
		context.Background(),
		credential,
		record,
		testTenantID,
	)
	assertUnauthenticated(t, principal, updated, err, credential)

	principal, updated, err = testAuthenticator(
		t,
		now.Add(time.Minute),
	).AuthenticateForTenant(nil, credential, record, testTenantID)
	assertUnauthenticated(t, principal, updated, err, credential)

	parts := strings.Split(credential, ".")
	zeroID := credentialVersion + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, tokenIDBytes)) +
		"." + parts[2]
	zeroSecret := credentialVersion + "." + parts[1] + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, tokenSecretBytes))
	invalidIDEncoding := credentialVersion + "." +
		"*" + parts[1][1:] + "." + parts[2]

	for _, candidate := range []string{zeroID, zeroSecret, invalidIDEncoding} {
		principal, updated, err = testAuthenticator(
			t,
			now.Add(time.Minute),
		).AuthenticateForTenant(
			context.Background(),
			candidate,
			record,
			testTenantID,
		)
		assertUnauthenticated(t, principal, updated, err, candidate)
	}
}

func TestRevocationIsImmutableAndImmediate(t *testing.T) {
	t.Parallel()

	createdAt := testNow()
	record, credential, err := testIssuer(
		t,
		createdAt,
		entropyBytes(1, 48),
	).Issue(
		context.Background(),
		testScope(t, testTenantID),
		createdAt.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	usedAt := createdAt.Add(5 * time.Minute)
	_, usedRecord, err := testAuthenticator(t, usedAt).AuthenticateForTenant(
		context.Background(),
		credential,
		record,
		testTenantID,
	)
	if err != nil {
		t.Fatalf("AuthenticateForTenant() error = %v", err)
	}

	if invalid, err := usedRecord.Revoke(usedAt.Add(-time.Second)); !errors.Is(err, ErrInvalidLifecycle) || invalid.Valid() {
		t.Fatalf("Revoke() before last use = (%v, %v)", invalid, err)
	}

	revokedAt := usedAt.Add(time.Minute)
	revoked, err := usedRecord.Revoke(revokedAt)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revoked.Status() != StatusRevoked || revoked.RevokedAt() != revokedAt {
		t.Fatal("Revoke() did not preserve authoritative revocation metadata")
	}
	if usedRecord.Status() != StatusActive || !usedRecord.RevokedAt().IsZero() {
		t.Fatal("Revoke() mutated the input record")
	}

	again, err := revoked.Revoke(revokedAt.Add(time.Hour))
	if err != nil || again != revoked {
		t.Fatal("Revoke() is not idempotent")
	}

	principal, updated, err := testAuthenticator(
		t,
		revokedAt.Add(time.Second),
	).AuthenticateForTenant(
		context.Background(),
		credential,
		revoked,
		testTenantID,
	)
	assertUnauthenticated(t, principal, updated, err, credential)
}

func TestRecordRejectsCorruptedPersistentState(t *testing.T) {
	t.Parallel()

	now := testNow()
	valid, _, err := testIssuer(t, now, entropyBytes(1, 48)).Issue(
		context.Background(),
		testScope(t, testTenantID),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	tests := map[string]Record{
		"missing verifier": func() Record {
			result := valid
			result.verifier = [32]byte{}
			return result
		}(),
		"invalid scope": func() Record {
			result := valid
			result.scope = Scope{}
			return result
		}(),
		"invalid status": func() Record {
			result := valid
			result.status = Status(255)
			return result
		}(),
		"active with revocation time": func() Record {
			result := valid
			result.revokedAt = now.Add(time.Minute)
			return result
		}(),
		"revoked without revocation time": func() Record {
			result := valid
			result.status = StatusRevoked
			return result
		}(),
		"revocation before creation": func() Record {
			result := valid
			result.status = StatusRevoked
			result.revokedAt = now.Add(-time.Second)
			return result
		}(),
		"last use before creation": func() Record {
			result := valid
			result.lastUsedAt = now.Add(-time.Second)
			return result
		}(),
		"last use at expiry": func() Record {
			result := valid
			result.lastUsedAt = result.expiresAt
			return result
		}(),
	}

	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if record.Valid() {
				t.Fatal("corrupted persistent state was accepted")
			}
			if revoked, err := record.Revoke(now.Add(time.Minute)); !errors.Is(err, ErrInvalidLifecycle) || revoked.Valid() {
				t.Fatal("Revoke() accepted corrupted persistent state")
			}
		})
	}
}

func TestZeroValuesAndFormattingFailClosed(t *testing.T) {
	t.Parallel()

	if StatusActive.String() != "active" ||
		StatusRevoked.String() != "revoked" ||
		Status(0).String() != "invalid" {
		t.Fatal("Status.String() returned an unsafe lifecycle label")
	}

	var record Record
	if record.Valid() || record.ID() != "" || record.SafePrefix() != "" {
		t.Fatal("zero Record did not fail closed")
	}
	var principal ServicePrincipal
	if principal.Valid() || principal.TokenID() != "" {
		t.Fatal("zero ServicePrincipal did not fail closed")
	}

	now := testNow()
	record, credential, err := testIssuer(
		t,
		now,
		entropyBytes(1, 48),
	).Issue(
		context.Background(),
		testScope(t, testTenantID),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	principal, _, err = testAuthenticator(
		t,
		now.Add(time.Minute),
	).AuthenticateForTenant(
		context.Background(),
		credential,
		record,
		testTenantID,
	)
	if err != nil {
		t.Fatalf("AuthenticateForTenant() error = %v", err)
	}

	formatted := fmt.Sprintf(
		"%s %#v %+v",
		principal,
		principal,
		&principal,
	)
	if !strings.Contains(formatted, "redacted") ||
		strings.Contains(formatted, principal.TokenID()) ||
		strings.Contains(formatted, principal.TenantID()) {
		t.Fatal("ServicePrincipal formatting disclosed identity metadata")
	}
	if record.Scope().TenantID() != testTenantID {
		t.Fatal("Scope.TenantID() did not preserve the opaque identifier")
	}
	if NewIssuer() == nil || NewAuthenticator() == nil {
		t.Fatal("public constructors returned nil boundaries")
	}
}

func TestTenantScopeRejectsAmbiguousIdentifiers(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"tenant with space",
		"tenant\nnewline",
		"tenant-한글",
		strings.Repeat("x", maximumTenantIDBytes+1),
	}
	for _, tenantID := range tests {
		if scope, err := NewTenantScope(tenantID); !errors.Is(err, ErrInvalidScope) || scope.Valid() {
			t.Fatalf("NewTenantScope() accepted an ambiguous identifier")
		}
	}
}

func TestConstructorsRejectNilDependencies(t *testing.T) {
	t.Parallel()

	if issuer, err := newIssuer(nil, testClock(testNow())); !errors.Is(err, ErrIssuance) || issuer != nil {
		t.Fatalf("newIssuer(nil, clock) = (%v, %v)", issuer, err)
	}
	if issuer, err := newIssuer(bytes.NewReader(nil), nil); !errors.Is(err, ErrIssuance) || issuer != nil {
		t.Fatalf("newIssuer(reader, nil) = (%v, %v)", issuer, err)
	}
	if authenticator, err := newAuthenticator(nil); !errors.Is(err, ErrUnauthenticated) || authenticator != nil {
		t.Fatalf("newAuthenticator(nil) = (%v, %v)", authenticator, err)
	}
}

func testNow() time.Time {
	return time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
}

func testClock(value time.Time) func() time.Time {
	return func() time.Time { return value }
}

func testScope(t *testing.T, tenantID string) Scope {
	t.Helper()

	scope, err := NewTenantScope(tenantID)
	if err != nil {
		t.Fatalf("NewTenantScope() error = %v", err)
	}
	return scope
}

func testIssuer(t *testing.T, now time.Time, entropy []byte) *Issuer {
	t.Helper()

	issuer, err := newIssuer(bytes.NewReader(entropy), testClock(now))
	if err != nil {
		t.Fatalf("newIssuer() error = %v", err)
	}
	return issuer
}

func testAuthenticator(t *testing.T, now time.Time) *Authenticator {
	t.Helper()

	authenticator, err := newAuthenticator(testClock(now))
	if err != nil {
		t.Fatalf("newAuthenticator() error = %v", err)
	}
	return authenticator
}

func entropyBytes(start byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = start + byte(index%191)
	}
	return result
}

func mutateCredentialPart(t *testing.T, credential string, part int) string {
	t.Helper()

	parts := strings.Split(credential, ".")
	decoded := decodeTestPart(t, parts[part], map[int]int{
		1: tokenIDBytes,
		2: tokenSecretBytes,
	}[part])
	decoded[len(decoded)-1] ^= 1
	parts[part] = base64.RawURLEncoding.EncodeToString(decoded)
	return strings.Join(parts, ".")
}

func decodeTestPart(t *testing.T, value string, size int) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size {
		t.Fatalf("test credential part did not decode")
	}
	return decoded
}

func assertUnauthenticated(
	t *testing.T,
	principal ServicePrincipal,
	record Record,
	err error,
	credential string,
) {
	t.Helper()

	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("AuthenticateForTenant() error = %v, want ErrUnauthenticated", err)
	}
	if err != ErrUnauthenticated {
		t.Fatal("AuthenticateForTenant() did not return the uniform error value")
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatal("AuthenticateForTenant() disclosed the credential")
	}
	if principal.Valid() || record.Valid() {
		t.Fatal("failed authentication returned principal or record state")
	}
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type countingReader struct {
	reader io.Reader
	calls  int
}

func (r *countingReader) Read(destination []byte) (int, error) {
	r.calls++
	return r.reader.Read(destination)
}
