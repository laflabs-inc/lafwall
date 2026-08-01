package identity

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	maxRawIDTokenBytes = 16 * 1024
	maxIssuerBytes     = 2048
	maxAudienceBytes   = 1024
	maxSubjectBytes    = 255
	maxNonceBytes      = 1024
	maxNumericDate     = 253402300799
)

var (
	ErrInvalidConfiguration = errors.New("invalid human identity configuration")
	ErrUnauthenticated      = errors.New("human authentication failed")
)

var supportedAsymmetricAlgorithms = map[string]struct{}{
	"RS256": {},
	"RS384": {},
	"RS512": {},
	"PS256": {},
	"PS384": {},
	"PS512": {},
	"ES256": {},
	"ES384": {},
	"ES512": {},
	"EdDSA": {},
}

// KeySet verifies a token signature using public keys owned by the approved
// issuer. Implementations must never select an issuer or key endpoint from an
// unverified token claim.
type KeySet interface {
	VerifySignature(context.Context, string) ([]byte, error)
}

// HumanVerifierConfig is the complete trust configuration for one approved
// human OIDC issuer. Values are matched exactly and are never inferred from a
// token.
type HumanVerifierConfig struct {
	Issuer                   string
	Audience                 string
	AllowedSigningAlgorithms []string
}

// HumanPrincipal is an immutable internal identity key. Profile and email
// claims are deliberately excluded because they are not identity proof.
type HumanPrincipal struct {
	issuer  string
	subject string
}

func (p HumanPrincipal) Issuer() string {
	return p.issuer
}

func (p HumanPrincipal) Subject() string {
	return p.subject
}

func (p HumanPrincipal) Valid() bool {
	return validIssuer(p.issuer) && validSubject(p.subject)
}

// HumanVerifier verifies signed OIDC ID tokens and maps their immutable issuer
// and subject claims to an internal principal. It is safe for concurrent use
// when its KeySet is safe for concurrent use.
type HumanVerifier struct {
	issuer   string
	audience string
	now      func() time.Time
	verifier *oidc.IDTokenVerifier
}

func NewHumanVerifier(
	config HumanVerifierConfig,
	keySet KeySet,
) (*HumanVerifier, error) {
	return newHumanVerifier(config, keySet, time.Now)
}

func newHumanVerifier(
	config HumanVerifierConfig,
	keySet KeySet,
	now func() time.Time,
) (*HumanVerifier, error) {
	algorithms, ok := validateAndCopyAlgorithms(
		config.AllowedSigningAlgorithms,
	)
	if !validIssuer(config.Issuer) ||
		!validAudience(config.Audience) ||
		!ok ||
		isNil(keySet) ||
		now == nil {
		return nil, ErrInvalidConfiguration
	}

	verifier := oidc.NewVerifier(
		config.Issuer,
		keySet,
		&oidc.Config{
			ClientID:             config.Audience,
			SupportedSigningAlgs: algorithms,
			Now:                  now,
		},
	)

	return &HumanVerifier{
		issuer:   config.Issuer,
		audience: config.Audience,
		now:      now,
		verifier: verifier,
	}, nil
}

// VerifyIDToken verifies rawIDToken without retaining it and validates the
// nonce when one was established by the initiating OIDC flow. An empty
// expectedNonce requires the token nonce to be absent.
func (v *HumanVerifier) VerifyIDToken(
	ctx context.Context,
	rawIDToken string,
	expectedNonce string,
) (HumanPrincipal, error) {
	if v == nil ||
		v.verifier == nil ||
		v.now == nil ||
		ctx == nil ||
		rawIDToken == "" ||
		len(rawIDToken) > maxRawIDTokenBytes ||
		!validNonce(expectedNonce) {
		return HumanPrincipal{}, authenticationError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return HumanPrincipal{}, err
	}

	token, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil || token == nil {
		return HumanPrincipal{}, authenticationError(ctx)
	}

	now := v.now()
	principal, ok := v.validateVerifiedToken(token, expectedNonce, now)
	if !ok {
		return HumanPrincipal{}, authenticationError(ctx)
	}

	return principal, nil
}

func (v *HumanVerifier) validateVerifiedToken(
	token *oidc.IDToken,
	expectedNonce string,
	now time.Time,
) (HumanPrincipal, bool) {
	if token.Issuer != v.issuer ||
		len(token.Audience) != 1 ||
		token.Audience[0] != v.audience ||
		!validTokenNonce(token.Nonce, expectedNonce) {
		return HumanPrincipal{}, false
	}

	var claims strictClaims
	if err := token.Claims(&claims); err != nil {
		return HumanPrincipal{}, false
	}

	subject, ok := requiredStringClaim(claims, "sub")
	if !ok || !validSubject(subject) {
		return HumanPrincipal{}, false
	}

	if authorizedParty, present, valid := optionalStringClaim(claims, "azp"); !valid || (present && authorizedParty != v.audience) {
		return HumanPrincipal{}, false
	}

	expiresAt, ok := requiredNumericDate(claims, "exp")
	if !ok || !now.Before(expiresAt) {
		return HumanPrincipal{}, false
	}

	issuedAt, ok := requiredNumericDate(claims, "iat")
	if !ok || issuedAt.After(now) || !issuedAt.Before(expiresAt) {
		return HumanPrincipal{}, false
	}

	if notBefore, present, valid := optionalNumericDate(claims, "nbf"); !valid || (present && (notBefore.After(now) || !notBefore.Before(expiresAt))) {
		return HumanPrincipal{}, false
	}

	principal := HumanPrincipal{issuer: token.Issuer, subject: subject}
	return principal, principal.Valid()
}

type strictClaims map[string]json.RawMessage

func (claims *strictClaims) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("OIDC claims must be a JSON object")
	}

	decoded := make(strictClaims)
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return errors.New("invalid OIDC claim name")
		}
		name, ok := nameToken.(string)
		if !ok || name == "" {
			return errors.New("invalid OIDC claim name")
		}
		if _, duplicate := decoded[name]; duplicate {
			return errors.New("duplicate OIDC claim")
		}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid OIDC claim value")
		}
		decoded[name] = value
	}

	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("invalid OIDC claims object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing OIDC claims data")
	}

	*claims = decoded
	return nil
}

func validateAndCopyAlgorithms(algorithms []string) ([]string, bool) {
	if len(algorithms) == 0 || len(algorithms) > len(supportedAsymmetricAlgorithms) {
		return nil, false
	}

	result := make([]string, 0, len(algorithms))
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if _, supported := supportedAsymmetricAlgorithms[algorithm]; !supported {
			return nil, false
		}
		if _, duplicate := seen[algorithm]; duplicate {
			return nil, false
		}
		seen[algorithm] = struct{}{}
		result = append(result, algorithm)
	}

	return result, true
}

func validIssuer(value string) bool {
	if !validText(value, maxIssuerBytes) ||
		strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}

	parsed, err := url.Parse(value)
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.Opaque == "" &&
		parsed.RawQuery == "" &&
		parsed.Fragment == ""
}

func validAudience(value string) bool {
	return validText(value, maxAudienceBytes) &&
		strings.IndexFunc(value, unicode.IsSpace) < 0
}

func validSubject(value string) bool {
	if value == "" || len(value) > maxSubjectBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validNonce(value string) bool {
	return value == "" ||
		(validText(value, maxNonceBytes) &&
			strings.IndexFunc(value, unicode.IsSpace) < 0)
}

func validTokenNonce(actual string, expected string) bool {
	if expected == "" {
		return actual == ""
	}
	if len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func validText(value string, maximum int) bool {
	return value != "" &&
		len(value) <= maximum &&
		utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func requiredStringClaim(
	claims strictClaims,
	name string,
) (string, bool) {
	value, found := claims[name]
	if !found {
		return "", false
	}

	var decoded string
	if err := json.Unmarshal(value, &decoded); err != nil || decoded == "" {
		return "", false
	}
	return decoded, true
}

func optionalStringClaim(
	claims strictClaims,
	name string,
) (value string, present bool, valid bool) {
	raw, found := claims[name]
	if !found {
		return "", false, true
	}

	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded == "" {
		return "", true, false
	}
	return decoded, true, true
}

func requiredNumericDate(
	claims strictClaims,
	name string,
) (time.Time, bool) {
	value, found := claims[name]
	if !found {
		return time.Time{}, false
	}
	return parseNumericDate(value)
}

func optionalNumericDate(
	claims strictClaims,
	name string,
) (value time.Time, present bool, valid bool) {
	raw, found := claims[name]
	if !found {
		return time.Time{}, false, true
	}

	decoded, ok := parseNumericDate(raw)
	return decoded, true, ok
}

func parseNumericDate(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || len(raw) > 64 {
		return time.Time{}, false
	}

	var numeric json.Number
	if err := json.Unmarshal(raw, &numeric); err != nil {
		return time.Time{}, false
	}

	seconds, err := numeric.Float64()
	if err != nil || math.IsInf(seconds, 0) || math.IsNaN(seconds) || seconds < 0 {
		return time.Time{}, false
	}

	whole, fraction := math.Modf(seconds)
	if whole > maxNumericDate || fraction < 0 {
		return time.Time{}, false
	}

	nanoseconds := int64(fraction * float64(time.Second))
	return time.Unix(int64(whole), nanoseconds), true
}

func isNil(value any) bool {
	if value == nil {
		return true
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func authenticationError(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return ErrUnauthenticated
}
