package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

const (
	testIssuer   = "https://identity.example.test"
	testAudience = "laf-secrets-test-client"
	testNonce    = "test-nonce-7f3c"
)

var (
	primaryKeyOnce sync.Once
	primaryKey     *rsa.PrivateKey
	primaryKeyErr  error

	secondaryKeyOnce sync.Once
	secondaryKey     *rsa.PrivateKey
	secondaryKeyErr  error
)

func TestVerifyIDTokenMapsImmutableHumanPrincipal(t *testing.T) {
	t.Parallel()

	now := testNow()
	verifier := newTestVerifier(t, testIssuer, now, primaryTestKey(t))
	claims := validTestClaims(now, testIssuer)
	claims["email"] = "changeable-profile@example.test"
	claims["name"] = "Changeable Profile"
	claims["nonce"] = testNonce

	rawIDToken := signTestIDToken(t, primaryTestKey(t), jose.RS256, claims)
	principal, err := verifier.VerifyIDToken(
		context.Background(),
		rawIDToken,
		testNonce,
	)
	if err != nil {
		t.Fatalf("VerifyIDToken() error = %v", err)
	}
	if !principal.Valid() {
		t.Fatal("VerifyIDToken() returned an invalid principal")
	}
	if principal.Issuer() != testIssuer {
		t.Fatalf("Issuer() = %q, want configured issuer", principal.Issuer())
	}
	if principal.Subject() != "human-subject-1" {
		t.Fatalf("Subject() = %q, want immutable subject", principal.Subject())
	}

	changedProfile := validTestClaims(now, testIssuer)
	changedProfile["email"] = "different-profile@example.test"
	changedProfile["name"] = "Different Profile"
	secondToken := signTestIDToken(
		t,
		primaryTestKey(t),
		jose.RS256,
		changedProfile,
	)
	secondPrincipal, err := verifier.VerifyIDToken(
		context.Background(),
		secondToken,
		"",
	)
	if err != nil {
		t.Fatalf("second VerifyIDToken() error = %v", err)
	}
	if principal != secondPrincipal {
		t.Fatal("profile claims changed the internal principal identity")
	}
}

func TestHumanPrincipalIncludesIssuerBoundary(t *testing.T) {
	t.Parallel()

	now := testNow()
	key := primaryTestKey(t)
	firstVerifier := newTestVerifier(t, testIssuer, now, key)
	firstToken := signTestIDToken(
		t,
		key,
		jose.RS256,
		validTestClaims(now, testIssuer),
	)
	first, err := firstVerifier.VerifyIDToken(
		context.Background(),
		firstToken,
		"",
	)
	if err != nil {
		t.Fatalf("first VerifyIDToken() error = %v", err)
	}

	const otherIssuer = "https://other-identity.example.test"
	secondVerifier := newTestVerifier(t, otherIssuer, now, key)
	secondToken := signTestIDToken(
		t,
		key,
		jose.RS256,
		validTestClaims(now, otherIssuer),
	)
	second, err := secondVerifier.VerifyIDToken(
		context.Background(),
		secondToken,
		"",
	)
	if err != nil {
		t.Fatalf("second VerifyIDToken() error = %v", err)
	}

	if first == second {
		t.Fatal("the same subject from different issuers mapped to one principal")
	}
}

func TestVerifyIDTokenRejectsAmbiguousOrInvalidClaims(t *testing.T) {
	t.Parallel()

	now := testNow()
	key := primaryTestKey(t)
	verifier := newTestVerifier(t, testIssuer, now, key)

	tests := map[string]func(map[string]any){
		"wrong issuer": func(claims map[string]any) {
			claims["iss"] = "https://unapproved.example.test"
		},
		"wrong audience": func(claims map[string]any) {
			claims["aud"] = "other-client"
		},
		"multiple audiences": func(claims map[string]any) {
			claims["aud"] = []string{testAudience, "other-client"}
		},
		"missing audience": func(claims map[string]any) {
			delete(claims, "aud")
		},
		"mismatched authorized party": func(claims map[string]any) {
			claims["azp"] = "other-client"
		},
		"empty authorized party": func(claims map[string]any) {
			claims["azp"] = ""
		},
		"missing expiry": func(claims map[string]any) {
			delete(claims, "exp")
		},
		"expired": func(claims map[string]any) {
			claims["exp"] = now.Unix()
		},
		"malformed expiry": func(claims map[string]any) {
			claims["exp"] = "not-a-numeric-date"
		},
		"out of range expiry": func(claims map[string]any) {
			claims["exp"] = float64(maxNumericDate) + 1
		},
		"missing issued at": func(claims map[string]any) {
			delete(claims, "iat")
		},
		"future issued at": func(claims map[string]any) {
			claims["iat"] = now.Add(time.Second).Unix()
		},
		"issued at after expiry": func(claims map[string]any) {
			claims["iat"] = now.Add(10 * time.Minute).Unix()
			claims["exp"] = now.Add(5 * time.Minute).Unix()
		},
		"future not before": func(claims map[string]any) {
			claims["nbf"] = now.Add(time.Second).Unix()
		},
		"not before at expiry": func(claims map[string]any) {
			claims["nbf"] = claims["exp"]
		},
		"null not before": func(claims map[string]any) {
			claims["nbf"] = nil
		},
		"missing subject": func(claims map[string]any) {
			delete(claims, "sub")
		},
		"empty subject": func(claims map[string]any) {
			claims["sub"] = ""
		},
		"non ASCII subject": func(claims map[string]any) {
			claims["sub"] = "human-subject-☃"
		},
		"oversized subject": func(claims map[string]any) {
			claims["sub"] = strings.Repeat("a", maxSubjectBytes+1)
		},
		"unexpected nonce": func(claims map[string]any) {
			claims["nonce"] = testNonce
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			claims := validTestClaims(now, testIssuer)
			mutate(claims)
			rawIDToken := signTestIDToken(t, key, jose.RS256, claims)

			principal, err := verifier.VerifyIDToken(
				context.Background(),
				rawIDToken,
				"",
			)
			assertUnauthenticated(t, principal, err)
		})
	}
}

func TestVerifyIDTokenRejectsSignatureAndAlgorithmFailures(t *testing.T) {
	t.Parallel()

	now := testNow()
	verifier := newTestVerifier(t, testIssuer, now, primaryTestKey(t))
	claims := validTestClaims(now, testIssuer)

	tests := map[string]string{
		"wrong signing key": signTestIDToken(
			t,
			secondaryTestKey(t),
			jose.RS256,
			claims,
		),
		"algorithm outside allowlist": signTestIDToken(
			t,
			primaryTestKey(t),
			jose.RS512,
			claims,
		),
		"malformed compact token": "not.a.valid-token",
	}

	for name, rawIDToken := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			principal, err := verifier.VerifyIDToken(
				context.Background(),
				rawIDToken,
				"",
			)
			assertUnauthenticated(t, principal, err)
		})
	}
}

func TestVerifyIDTokenRejectsDuplicateSecurityClaims(t *testing.T) {
	t.Parallel()

	now := testNow()
	verifier := newTestVerifier(t, testIssuer, now, primaryTestKey(t))
	prefix := fmt.Sprintf(
		`"sub":"human-subject-1","iat":%d,"nbf":%d`,
		now.Add(-time.Minute).Unix(),
		now.Add(-time.Minute).Unix(),
	)
	expiry := now.Add(5 * time.Minute).Unix()

	payloads := map[string]string{
		"issuer": fmt.Sprintf(
			`{"iss":%q,"iss":%q,"aud":%q,%s,"exp":%d}`,
			testIssuer,
			testIssuer,
			testAudience,
			prefix,
			expiry,
		),
		"audience": fmt.Sprintf(
			`{"iss":%q,"aud":%q,"aud":%q,%s,"exp":%d}`,
			testIssuer,
			testAudience,
			testAudience,
			prefix,
			expiry,
		),
		"expiry": fmt.Sprintf(
			`{"iss":%q,"aud":%q,%s,"exp":%d,"exp":%d}`,
			testIssuer,
			testAudience,
			prefix,
			expiry,
			expiry,
		),
	}

	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rawIDToken := signTestPayload(
				t,
				primaryTestKey(t),
				jose.RS256,
				[]byte(payload),
			)
			principal, err := verifier.VerifyIDToken(
				context.Background(),
				rawIDToken,
				"",
			)
			assertUnauthenticated(t, principal, err)
		})
	}
}

func TestVerifyIDTokenValidatesExpectedNonce(t *testing.T) {
	t.Parallel()

	now := testNow()
	verifier := newTestVerifier(t, testIssuer, now, primaryTestKey(t))
	claims := validTestClaims(now, testIssuer)
	claims["nonce"] = testNonce
	rawIDToken := signTestIDToken(
		t,
		primaryTestKey(t),
		jose.RS256,
		claims,
	)

	principal, err := verifier.VerifyIDToken(
		context.Background(),
		rawIDToken,
		"different-test-nonce",
	)
	assertUnauthenticated(t, principal, err)
}

func TestVerifyIDTokenBoundsInputBeforeSignatureWork(t *testing.T) {
	t.Parallel()

	keySet := &countingKeySet{}
	verifier, err := newHumanVerifier(
		testVerifierConfig(testIssuer),
		keySet,
		testClock(testNow()),
	)
	if err != nil {
		t.Fatalf("newHumanVerifier() error = %v", err)
	}

	principal, err := verifier.VerifyIDToken(
		context.Background(),
		strings.Repeat("x", maxRawIDTokenBytes+1),
		"",
	)
	assertUnauthenticated(t, principal, err)
	if keySet.calls != 0 {
		t.Fatalf("VerifySignature() calls = %d, want 0", keySet.calls)
	}
}

func TestVerifyIDTokenSanitizesDependencyFailures(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-key-provider-error-marker"
	verifier, err := newHumanVerifier(
		testVerifierConfig(testIssuer),
		failingKeySet{err: errors.New(marker)},
		testClock(testNow()),
	)
	if err != nil {
		t.Fatalf("newHumanVerifier() error = %v", err)
	}
	rawIDToken := signTestIDToken(
		t,
		primaryTestKey(t),
		jose.RS256,
		validTestClaims(testNow(), testIssuer),
	)

	principal, err := verifier.VerifyIDToken(
		context.Background(),
		rawIDToken,
		"",
	)
	assertUnauthenticated(t, principal, err)
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), rawIDToken) {
		t.Fatal("VerifyIDToken() disclosed dependency details or the raw token")
	}
}

func TestVerifyIDTokenPreservesContextCancellation(t *testing.T) {
	t.Parallel()

	verifier := newTestVerifier(
		t,
		testIssuer,
		testNow(),
		primaryTestKey(t),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	principal, err := verifier.VerifyIDToken(ctx, "unused-token", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyIDToken() error = %v, want context.Canceled", err)
	}
	if principal.Valid() {
		t.Fatal("VerifyIDToken() returned a valid principal after cancellation")
	}
}

func TestNewHumanVerifierRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	validKeySet := testStaticKeySet(primaryTestKey(t))
	var typedNilKeySet *oidc.StaticKeySet

	tests := map[string]struct {
		config HumanVerifierConfig
		keySet KeySet
		now    func() time.Time
	}{
		"empty issuer": {
			config: testVerifierConfig(""),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"non HTTPS issuer": {
			config: testVerifierConfig("http://identity.example.test"),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"issuer with query": {
			config: testVerifierConfig(testIssuer + "?tenant=unexpected"),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"issuer with fragment": {
			config: testVerifierConfig(testIssuer + "#unexpected"),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"empty audience": {
			config: func() HumanVerifierConfig {
				config := testVerifierConfig(testIssuer)
				config.Audience = ""
				return config
			}(),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"empty algorithm list": {
			config: func() HumanVerifierConfig {
				config := testVerifierConfig(testIssuer)
				config.AllowedSigningAlgorithms = nil
				return config
			}(),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"symmetric algorithm": {
			config: func() HumanVerifierConfig {
				config := testVerifierConfig(testIssuer)
				config.AllowedSigningAlgorithms = []string{"HS256"}
				return config
			}(),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"unsigned algorithm": {
			config: func() HumanVerifierConfig {
				config := testVerifierConfig(testIssuer)
				config.AllowedSigningAlgorithms = []string{"none"}
				return config
			}(),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"duplicate algorithm": {
			config: func() HumanVerifierConfig {
				config := testVerifierConfig(testIssuer)
				config.AllowedSigningAlgorithms = []string{"RS256", "RS256"}
				return config
			}(),
			keySet: validKeySet,
			now:    testClock(testNow()),
		},
		"nil key set": {
			config: testVerifierConfig(testIssuer),
			keySet: nil,
			now:    testClock(testNow()),
		},
		"typed nil key set": {
			config: testVerifierConfig(testIssuer),
			keySet: typedNilKeySet,
			now:    testClock(testNow()),
		},
		"nil clock": {
			config: testVerifierConfig(testIssuer),
			keySet: validKeySet,
			now:    nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier, err := newHumanVerifier(test.config, test.keySet, test.now)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf(
					"newHumanVerifier() error = %v, want ErrInvalidConfiguration",
					err,
				)
			}
			if verifier != nil {
				t.Fatal("newHumanVerifier() returned a verifier for unsafe configuration")
			}
		})
	}
}

func TestNewHumanVerifierCopiesAlgorithmAllowlist(t *testing.T) {
	t.Parallel()

	now := testNow()
	algorithms := []string{"RS256"}
	config := testVerifierConfig(testIssuer)
	config.AllowedSigningAlgorithms = algorithms
	verifier, err := newHumanVerifier(
		config,
		testStaticKeySet(primaryTestKey(t)),
		testClock(now),
	)
	if err != nil {
		t.Fatalf("newHumanVerifier() error = %v", err)
	}
	algorithms[0] = "none"

	rawIDToken := signTestIDToken(
		t,
		primaryTestKey(t),
		jose.RS256,
		validTestClaims(now, testIssuer),
	)
	if _, err := verifier.VerifyIDToken(
		context.Background(),
		rawIDToken,
		"",
	); err != nil {
		t.Fatalf("VerifyIDToken() error after config mutation = %v", err)
	}
}

func TestNewHumanVerifierAcceptsApprovedConfiguration(t *testing.T) {
	t.Parallel()

	verifier, err := NewHumanVerifier(
		testVerifierConfig(testIssuer),
		testStaticKeySet(primaryTestKey(t)),
	)
	if err != nil {
		t.Fatalf("NewHumanVerifier() error = %v", err)
	}
	if verifier == nil {
		t.Fatal("NewHumanVerifier() returned nil")
	}
}

func TestZeroHumanPrincipalIsInvalid(t *testing.T) {
	t.Parallel()

	if (HumanPrincipal{}).Valid() {
		t.Fatal("zero HumanPrincipal is valid")
	}
}

type failingKeySet struct {
	err error
}

func (f failingKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	return nil, f.err
}

type countingKeySet struct {
	calls int
}

func (k *countingKeySet) VerifySignature(
	context.Context,
	string,
) ([]byte, error) {
	k.calls++
	return nil, errors.New("unexpected signature verification")
}

func newTestVerifier(
	t *testing.T,
	issuer string,
	now time.Time,
	key *rsa.PrivateKey,
) *HumanVerifier {
	t.Helper()

	verifier, err := newHumanVerifier(
		testVerifierConfig(issuer),
		testStaticKeySet(key),
		testClock(now),
	)
	if err != nil {
		t.Fatalf("newHumanVerifier() error = %v", err)
	}
	return verifier
}

func testVerifierConfig(issuer string) HumanVerifierConfig {
	return HumanVerifierConfig{
		Issuer:                   issuer,
		Audience:                 testAudience,
		AllowedSigningAlgorithms: []string{"RS256"},
	}
}

func testStaticKeySet(key *rsa.PrivateKey) *oidc.StaticKeySet {
	return &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{&key.PublicKey},
	}
}

func validTestClaims(now time.Time, issuer string) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": "human-subject-1",
		"aud": testAudience,
		"iat": now.Add(-time.Minute).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
}

func signTestIDToken(
	t *testing.T,
	key *rsa.PrivateKey,
	algorithm jose.SignatureAlgorithm,
	claims map[string]any,
) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal test claims: %v", err)
	}
	return signTestPayload(t, key, algorithm, payload)
}

func signTestPayload(
	t *testing.T,
	key *rsa.PrivateKey,
	algorithm jose.SignatureAlgorithm,
	payload []byte,
) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: algorithm, Key: key},
		(&jose.SignerOptions{}).
			WithType("JWT").
			WithHeader("kid", "test-signing-key"),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner() error = %v", err)
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	serialized, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() error = %v", err)
	}
	return serialized
}

func primaryTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	primaryKeyOnce.Do(func() {
		primaryKey, primaryKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if primaryKeyErr != nil {
		t.Fatalf("generate primary test key: %v", primaryKeyErr)
	}
	return primaryKey
}

func secondaryTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	secondaryKeyOnce.Do(func() {
		secondaryKey, secondaryKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if secondaryKeyErr != nil {
		t.Fatalf("generate secondary test key: %v", secondaryKeyErr)
	}
	return secondaryKey
}

func testNow() time.Time {
	return time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
}

func testClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

func assertUnauthenticated(
	t *testing.T,
	principal HumanPrincipal,
	err error,
) {
	t.Helper()

	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("VerifyIDToken() error = %v, want ErrUnauthenticated", err)
	}
	if principal.Valid() {
		t.Fatal("VerifyIDToken() returned a valid principal after rejection")
	}
}
