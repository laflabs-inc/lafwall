package encryption

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const (
	fakeKeyReference = "test-key-reference"
	fakeKeyAlgorithm = "TEST-STATEFUL-FAKE"
)

func TestEnvelopeKnownAnswerAndRoundTrip(t *testing.T) {
	t.Parallel()

	provider := newDeterministicFakeProvider()
	service := newTestService(t, provider, deterministicRandom(1))
	plaintext := []byte("encryption-boundary-fixture")

	envelope, err := service.Encrypt(
		context.Background(),
		testBinding(),
		plaintext,
	)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if envelope.FormatVersion != envelopeFormatVersion {
		t.Fatalf(
			"FormatVersion = %d, want %d",
			envelope.FormatVersion,
			envelopeFormatVersion,
		)
	}
	if envelope.AADFormatVersion != aadFormatVersion {
		t.Fatalf(
			"AADFormatVersion = %d, want %d",
			envelope.AADFormatVersion,
			aadFormatVersion,
		)
	}
	if envelope.DataAlgorithm != dataAlgorithm {
		t.Fatalf("DataAlgorithm = %q, want %q", envelope.DataAlgorithm, dataAlgorithm)
	}
	if envelope.WrappingAlgorithm != fakeKeyAlgorithm {
		t.Fatalf(
			"WrappingAlgorithm = %q, want %q",
			envelope.WrappingAlgorithm,
			fakeKeyAlgorithm,
		)
	}
	if envelope.KeyReference != fakeKeyReference {
		t.Fatalf(
			"KeyReference = %q, want %q",
			envelope.KeyReference,
			fakeKeyReference,
		)
	}

	assertHex(
		t,
		"Nonce",
		envelope.Nonce,
		"202122232425262728292a2b",
	)
	assertHex(
		t,
		"Ciphertext",
		envelope.Ciphertext,
		"b754c50215e86e6775126facae6d9a9db13b95b1e1e91b9a1984093aa635"+
			"c8f69b572c8de663035724d084",
	)
	if string(envelope.WrappedDEK) != "fake-wrapped-dek-0001" {
		t.Fatalf(
			"WrappedDEK = %q, want %q",
			envelope.WrappedDEK,
			"fake-wrapped-dek-0001",
		)
	}

	decrypted, err := service.Decrypt(
		context.Background(),
		testBinding(),
		envelope,
	)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() = %q, want original plaintext", decrypted)
	}
}

func TestDecryptFailsClosedForTamperAndWrongContext(t *testing.T) {
	t.Parallel()

	provider := newDeterministicFakeProvider()
	service := newTestService(t, provider, deterministicRandom(1))
	envelope, err := service.Encrypt(
		context.Background(),
		testBinding(),
		[]byte("tamper-test-fixture"),
	)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	tests := map[string]struct {
		binding Binding
		mutate  func(*Envelope)
		wantErr error
	}{
		"ciphertext": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.Ciphertext[0] ^= 0xff
			},
			wantErr: ErrDecryption,
		},
		"nonce": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.Nonce[0] ^= 0xff
			},
			wantErr: ErrDecryption,
		},
		"wrapped DEK": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.WrappedDEK[0] ^= 0xff
			},
			wantErr: ErrKeyProvider,
		},
		"envelope version": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.FormatVersion++
			},
			wantErr: ErrInvalidEnvelope,
		},
		"data algorithm": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.DataAlgorithm = "UNKNOWN"
			},
			wantErr: ErrInvalidEnvelope,
		},
		"wrapping algorithm": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.WrappingAlgorithm = "UNKNOWN"
			},
			wantErr: ErrKeyProvider,
		},
		"key reference": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.KeyReference = "unknown-key-reference"
			},
			wantErr: ErrKeyProvider,
		},
		"nonce length": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.Nonce = candidate.Nonce[:len(candidate.Nonce)-1]
			},
			wantErr: ErrInvalidEnvelope,
		},
		"ciphertext length": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.Ciphertext = candidate.Ciphertext[:gcmTagSize-1]
			},
			wantErr: ErrInvalidEnvelope,
		},
		"missing wrapped DEK": {
			binding: testBinding(),
			mutate: func(candidate *Envelope) {
				candidate.WrappedDEK = nil
			},
			wantErr: ErrInvalidEnvelope,
		},
		"tenant context": {
			binding: func() Binding {
				binding := testBinding()
				binding.TenantID = "tenant-2"
				return binding
			}(),
			wantErr: ErrDecryption,
		},
		"project context": {
			binding: func() Binding {
				binding := testBinding()
				binding.ProjectID = "project-2"
				return binding
			}(),
			wantErr: ErrDecryption,
		},
		"environment context": {
			binding: func() Binding {
				binding := testBinding()
				binding.EnvironmentID = "environment-2"
				return binding
			}(),
			wantErr: ErrDecryption,
		},
		"secret context": {
			binding: func() Binding {
				binding := testBinding()
				binding.SecretID = "secret-2"
				return binding
			}(),
			wantErr: ErrDecryption,
		},
		"version ID context": {
			binding: func() Binding {
				binding := testBinding()
				binding.SecretVersionID = "version-2"
				return binding
			}(),
			wantErr: ErrDecryption,
		},
		"version sequence context": {
			binding: func() Binding {
				binding := testBinding()
				binding.VersionSequence++
				return binding
			}(),
			wantErr: ErrDecryption,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneEnvelope(envelope)
			if test.mutate != nil {
				test.mutate(&candidate)
			}

			plaintext, err := service.Decrypt(
				context.Background(),
				test.binding,
				candidate,
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Decrypt() error = %v, want %v", err, test.wantErr)
			}
			if plaintext != nil {
				t.Fatalf("Decrypt() plaintext = %q, want nil", plaintext)
			}
		})
	}
}

func TestEachEnvelopeUsesAFreshDEKAndNonce(t *testing.T) {
	t.Parallel()

	provider := newDeterministicFakeProvider()
	service := newTestService(t, provider, deterministicRandom(2))

	first, err := service.Encrypt(
		context.Background(),
		testBinding(),
		[]byte("repeatable-fixture"),
	)
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}
	second, err := service.Encrypt(
		context.Background(),
		testBinding(),
		[]byte("repeatable-fixture"),
	)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}

	if len(provider.wrappedKeys) != 2 {
		t.Fatalf("wrapped key count = %d, want 2", len(provider.wrappedKeys))
	}
	if bytes.Equal(provider.wrappedKeys[0], provider.wrappedKeys[1]) {
		t.Fatal("Encrypt() reused a DEK")
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("Encrypt() reused a nonce")
	}
	if bytes.Equal(first.WrappedDEK, second.WrappedDEK) {
		t.Fatal("Encrypt() reused a wrapped DEK")
	}
}

func TestEnvelopeDoesNotContainPlaintextOrUnwrappedDEK(t *testing.T) {
	t.Parallel()

	provider := newDeterministicFakeProvider()
	service := newTestService(t, provider, deterministicRandom(1))
	plaintext := []byte("plaintext-persistence-canary-7d9f")

	envelope, err := service.Encrypt(
		context.Background(),
		testBinding(),
		plaintext,
	)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	byteFields := map[string][]byte{
		"nonce":       envelope.Nonce,
		"ciphertext":  envelope.Ciphertext,
		"wrapped DEK": envelope.WrappedDEK,
	}
	for name, field := range byteFields {
		if bytes.Contains(field, plaintext) {
			t.Fatalf("%s contains plaintext", name)
		}
		if bytes.Contains(field, provider.wrappedKeys[0]) {
			t.Fatalf("%s contains an unwrapped DEK", name)
		}
	}

	stringFields := []string{
		envelope.DataAlgorithm,
		envelope.WrappingAlgorithm,
		envelope.KeyReference,
	}
	for _, field := range stringFields {
		if strings.Contains(field, string(plaintext)) {
			t.Fatal("envelope metadata contains plaintext")
		}
	}
}

func TestDEKBuffersAreClearedAfterUse(t *testing.T) {
	t.Parallel()

	provider := &zeroizationProbeProvider{}
	service := newTestService(t, provider, deterministicRandom(1))
	envelope, err := service.Encrypt(
		context.Background(),
		testBinding(),
		[]byte("zeroization-fixture"),
	)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if !allZero(provider.wrapAlias) {
		t.Fatal("Encrypt() left the provider input DEK populated")
	}

	if _, err := service.Decrypt(
		context.Background(),
		testBinding(),
		envelope,
	); err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !allZero(provider.unwrapAlias) {
		t.Fatal("Decrypt() left the unwrapped DEK populated")
	}
}

func TestProviderAndRandomFailuresAreSanitized(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-provider-error-marker"

	t.Run("wrap", func(t *testing.T) {
		provider := newDeterministicFakeProvider()
		provider.wrapErr = errors.New(marker)
		service := newTestService(t, provider, deterministicRandom(1))

		_, err := service.Encrypt(
			context.Background(),
			testBinding(),
			[]byte("provider-failure-fixture"),
		)
		assertSanitizedError(t, err, ErrKeyProvider, marker)
	})

	t.Run("unwrap", func(t *testing.T) {
		provider := newDeterministicFakeProvider()
		service := newTestService(t, provider, deterministicRandom(1))
		envelope, err := service.Encrypt(
			context.Background(),
			testBinding(),
			[]byte("provider-failure-fixture"),
		)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}

		provider.unwrapErr = errors.New(marker)
		_, err = service.Decrypt(
			context.Background(),
			testBinding(),
			envelope,
		)
		assertSanitizedError(t, err, ErrKeyProvider, marker)
	})

	t.Run("random source", func(t *testing.T) {
		provider := newDeterministicFakeProvider()
		service, err := newService(provider, failingReader{err: errors.New(marker)})
		if err != nil {
			t.Fatalf("newService() error = %v", err)
		}

		_, err = service.Encrypt(
			context.Background(),
			testBinding(),
			[]byte("random-failure-fixture"),
		)
		assertSanitizedError(t, err, ErrEncryption, marker)
	})
}

func TestEncryptRejectsProviderThatReturnsPlaintextDEK(t *testing.T) {
	t.Parallel()

	service := newTestService(t, echoProvider{}, deterministicRandom(1))
	_, err := service.Encrypt(
		context.Background(),
		testBinding(),
		[]byte("provider-contract-fixture"),
	)
	if !errors.Is(err, ErrKeyProvider) {
		t.Fatalf("Encrypt() error = %v, want ErrKeyProvider", err)
	}
}

func TestCanceledProviderOperationsPreserveCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := newDeterministicFakeProvider()
	service := newTestService(t, provider, deterministicRandom(1))
	_, err := service.Encrypt(
		ctx,
		testBinding(),
		[]byte("cancellation-fixture"),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Encrypt() error = %v, want context.Canceled", err)
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	if _, err := New(nil); !errors.Is(err, ErrKeyProvider) {
		t.Fatalf("New(nil) error = %v, want ErrKeyProvider", err)
	}
	if _, err := newService(newDeterministicFakeProvider(), nil); !errors.Is(
		err,
		ErrKeyProvider,
	) {
		t.Fatalf("newService(provider, nil) error = %v, want ErrKeyProvider", err)
	}
}

type deterministicFakeProvider struct {
	next        int
	keys        map[string][]byte
	wrappedKeys [][]byte
	wrapErr     error
	unwrapErr   error
}

func newDeterministicFakeProvider() *deterministicFakeProvider {
	return &deterministicFakeProvider{keys: make(map[string][]byte)}
}

func (p *deterministicFakeProvider) WrapDEK(
	ctx context.Context,
	dek []byte,
) (WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return WrappedDEK{}, err
	}
	if p.wrapErr != nil {
		return WrappedDEK{}, p.wrapErr
	}

	p.next++
	token := fmt.Sprintf("fake-wrapped-dek-%04d", p.next)
	key := append([]byte(nil), dek...)
	p.keys[token] = key
	p.wrappedKeys = append(p.wrappedKeys, key)

	return WrappedDEK{
		Ciphertext:   []byte(token),
		KeyReference: fakeKeyReference,
		Algorithm:    fakeKeyAlgorithm,
	}, nil
}

func (p *deterministicFakeProvider) UnwrapDEK(
	ctx context.Context,
	wrapped WrappedDEK,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.unwrapErr != nil {
		return nil, p.unwrapErr
	}
	if wrapped.KeyReference != fakeKeyReference ||
		wrapped.Algorithm != fakeKeyAlgorithm {
		return nil, errors.New("unknown fake key metadata")
	}

	key, ok := p.keys[string(wrapped.Ciphertext)]
	if !ok {
		return nil, errors.New("unknown fake wrapped key")
	}
	return append([]byte(nil), key...), nil
}

type zeroizationProbeProvider struct {
	key         []byte
	wrapAlias   []byte
	unwrapAlias []byte
}

func (p *zeroizationProbeProvider) WrapDEK(
	_ context.Context,
	dek []byte,
) (WrappedDEK, error) {
	p.wrapAlias = dek
	p.key = append([]byte(nil), dek...)

	return WrappedDEK{
		Ciphertext:   []byte("zeroization-probe-wrapped-key"),
		KeyReference: fakeKeyReference,
		Algorithm:    fakeKeyAlgorithm,
	}, nil
}

func (p *zeroizationProbeProvider) UnwrapDEK(
	_ context.Context,
	_ WrappedDEK,
) ([]byte, error) {
	p.unwrapAlias = append([]byte(nil), p.key...)
	return p.unwrapAlias, nil
}

type echoProvider struct{}

func (echoProvider) WrapDEK(
	_ context.Context,
	dek []byte,
) (WrappedDEK, error) {
	return WrappedDEK{
		Ciphertext:   dek,
		KeyReference: fakeKeyReference,
		Algorithm:    fakeKeyAlgorithm,
	}, nil
}

func (echoProvider) UnwrapDEK(
	_ context.Context,
	_ WrappedDEK,
) ([]byte, error) {
	return nil, errors.New("not implemented")
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}

func testBinding() Binding {
	return Binding{
		TenantID:        "tenant-1",
		ProjectID:       "project-1",
		EnvironmentID:   "environment-1",
		SecretID:        "secret-1",
		SecretVersionID: "version-1",
		VersionSequence: 7,
	}
}

func deterministicRandom(envelopes int) io.Reader {
	random := make([]byte, envelopes*(dekSize+gcmNonceSize))
	for index := range random {
		random[index] = byte(index)
	}
	return bytes.NewReader(random)
}

func newTestService(
	t *testing.T,
	provider KekProvider,
	random io.Reader,
) *Service {
	t.Helper()

	service, err := newService(provider, random)
	if err != nil {
		t.Fatalf("newService() error = %v", err)
	}
	return service
}

func cloneEnvelope(envelope Envelope) Envelope {
	envelope.Nonce = append([]byte(nil), envelope.Nonce...)
	envelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	envelope.WrappedDEK = append([]byte(nil), envelope.WrappedDEK...)
	return envelope
}

func assertHex(t *testing.T, name string, value []byte, wantHex string) {
	t.Helper()

	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(%s) error = %v", name, err)
	}
	if !bytes.Equal(value, want) {
		t.Fatalf("%s = %x, want %x", name, value, want)
	}
}

func assertSanitizedError(
	t *testing.T,
	err error,
	want error,
	marker string,
) {
	t.Helper()

	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error disclosed provider detail: %v", err)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
