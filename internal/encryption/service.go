package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	dekSize        = 32
	gcmNonceSize   = 12
	gcmTagSize     = 16
	maxMetadataLen = 4096
)

type Service struct {
	provider KekProvider
	random   io.Reader
}

func New(provider KekProvider) (*Service, error) {
	return newService(provider, rand.Reader)
}

func newService(provider KekProvider, random io.Reader) (*Service, error) {
	if provider == nil || random == nil {
		return nil, ErrKeyProvider
	}

	return &Service{
		provider: provider,
		random:   random,
	}, nil
}

func (s *Service) Encrypt(
	ctx context.Context,
	binding Binding,
	plaintext []byte,
) (Envelope, error) {
	if s == nil || s.provider == nil || s.random == nil || ctx == nil {
		return Envelope{}, ErrEncryption
	}
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}

	aad, err := encodeAAD(binding)
	if err != nil {
		return Envelope{}, err
	}

	var dek [dekSize]byte
	defer clear(dek[:])

	if _, err := io.ReadFull(s.random, dek[:]); err != nil {
		return Envelope{}, ErrEncryption
	}

	block, err := aes.NewCipher(dek[:])
	if err != nil {
		return Envelope{}, ErrEncryption
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != gcmNonceSize {
		return Envelope{}, ErrEncryption
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.random, nonce); err != nil {
		return Envelope{}, ErrEncryption
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	wrapped, err := s.provider.WrapDEK(ctx, dek[:])
	if err != nil {
		return Envelope{}, providerError(ctx)
	}
	if !validWrappedDEK(wrapped) ||
		(len(wrapped.Ciphertext) == dekSize &&
			subtle.ConstantTimeCompare(wrapped.Ciphertext, dek[:]) == 1) {
		return Envelope{}, ErrKeyProvider
	}

	return Envelope{
		FormatVersion:     envelopeFormatVersion,
		AADFormatVersion:  aadFormatVersion,
		DataAlgorithm:     dataAlgorithm,
		WrappingAlgorithm: wrapped.Algorithm,
		KeyReference:      wrapped.KeyReference,
		Nonce:             append([]byte(nil), nonce...),
		Ciphertext:        append([]byte(nil), ciphertext...),
		WrappedDEK:        append([]byte(nil), wrapped.Ciphertext...),
	}, nil
}

func (s *Service) Decrypt(
	ctx context.Context,
	binding Binding,
	envelope Envelope,
) ([]byte, error) {
	if s == nil || s.provider == nil || ctx == nil {
		return nil, ErrDecryption
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	aad, err := encodeAAD(binding)
	if err != nil {
		return nil, err
	}
	if !validEnvelope(envelope) {
		return nil, ErrInvalidEnvelope
	}

	wrapped := WrappedDEK{
		Ciphertext:   append([]byte(nil), envelope.WrappedDEK...),
		KeyReference: envelope.KeyReference,
		Algorithm:    envelope.WrappingAlgorithm,
	}
	dek, err := s.provider.UnwrapDEK(ctx, wrapped)
	if err != nil {
		return nil, providerError(ctx)
	}
	if len(dek) != dekSize {
		clear(dek)
		return nil, ErrKeyProvider
	}
	defer clear(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecryption
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != gcmNonceSize {
		return nil, ErrDecryption
	}

	plaintext, err := aead.Open(
		nil,
		envelope.Nonce,
		envelope.Ciphertext,
		aad,
	)
	if err != nil {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

func validEnvelope(envelope Envelope) bool {
	return envelope.FormatVersion == envelopeFormatVersion &&
		envelope.AADFormatVersion == aadFormatVersion &&
		envelope.DataAlgorithm == dataAlgorithm &&
		validMetadata(envelope.WrappingAlgorithm) &&
		validMetadata(envelope.KeyReference) &&
		len(envelope.Nonce) == gcmNonceSize &&
		len(envelope.Ciphertext) >= gcmTagSize &&
		len(envelope.WrappedDEK) > 0
}

func validWrappedDEK(wrapped WrappedDEK) bool {
	return len(wrapped.Ciphertext) > 0 &&
		validMetadata(wrapped.KeyReference) &&
		validMetadata(wrapped.Algorithm)
}

func validMetadata(value string) bool {
	return value != "" &&
		len(value) <= maxMetadataLen &&
		utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func providerError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrKeyProvider
}
