package encryption

import (
	"context"
	"errors"
)

const (
	envelopeFormatVersion uint16 = 1
	aadFormatVersion      uint16 = 1

	dataAlgorithm = "AES-256-GCM"
)

var (
	ErrInvalidBinding  = errors.New("invalid encryption binding")
	ErrInvalidEnvelope = errors.New("invalid encryption envelope")
	ErrKeyProvider     = errors.New("key provider operation failed")
	ErrEncryption      = errors.New("encryption failed")
	ErrDecryption      = errors.New("decryption failed")
)

// Binding identifies the immutable domain context authenticated by an
// encryption envelope. Resource identifiers are treated as opaque values.
type Binding struct {
	TenantID        string
	ProjectID       string
	EnvironmentID   string
	SecretID        string
	SecretVersionID string
	VersionSequence uint64
}

// WrappedDEK is the opaque result returned by a KekProvider.
//
// Ciphertext and key references are sensitive even though they are not
// plaintext. Callers must not log them.
type WrappedDEK struct {
	Ciphertext   []byte
	KeyReference string
	Algorithm    string
}

// KekProvider wraps and unwraps data-encryption keys using key-encryption
// authority held outside the Laf Secrets application database.
//
// Production implementations must be safe for concurrent use, respect
// context cancellation, never export the KEK, never retain or log plaintext
// DEKs, return caller-owned byte slices, and return errors without sensitive
// material. They must use an established provider SDK or reviewed library
// rather than implementing a wrapping primitive. UnwrapDEK must reject an
// unknown or mismatched key reference or wrapping algorithm.
type KekProvider interface {
	WrapDEK(context.Context, []byte) (WrappedDEK, error)
	UnwrapDEK(context.Context, WrappedDEK) ([]byte, error)
}

// Envelope contains the complete encrypted representation of one immutable
// secret version. Every field must be persisted together and treated as
// sensitive. Plaintext and unwrapped DEKs are never part of an Envelope.
type Envelope struct {
	FormatVersion     uint16
	AADFormatVersion  uint16
	DataAlgorithm     string
	WrappingAlgorithm string
	KeyReference      string
	Nonce             []byte
	Ciphertext        []byte
	WrappedDEK        []byte
}
