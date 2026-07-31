package encryption

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

const aadDomain = "LAFSECRETS\x00SECRET-VERSION\x00"

func encodeAAD(binding Binding) ([]byte, error) {
	fields := [...]string{
		binding.TenantID,
		binding.ProjectID,
		binding.EnvironmentID,
		binding.SecretID,
		binding.SecretVersionID,
	}

	size := len(aadDomain) + 2 + 2 + 8
	for _, field := range fields {
		if field == "" ||
			!utf8.ValidString(field) ||
			uint64(len(field)) > math.MaxUint32 {
			return nil, ErrInvalidBinding
		}
		size += 4 + len(field)
	}
	if binding.VersionSequence == 0 {
		return nil, ErrInvalidBinding
	}

	aad := make([]byte, 0, size)
	aad = append(aad, aadDomain...)
	aad = binary.BigEndian.AppendUint16(aad, aadFormatVersion)
	aad = binary.BigEndian.AppendUint16(aad, envelopeFormatVersion)
	for _, field := range fields {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(field)))
		aad = append(aad, field...)
	}
	aad = binary.BigEndian.AppendUint64(aad, binding.VersionSequence)

	return aad, nil
}
