package encryption

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestEncodeAADKnownAnswer(t *testing.T) {
	t.Parallel()

	aad, err := encodeAAD(testBinding())
	if err != nil {
		t.Fatalf("encodeAAD() error = %v", err)
	}

	const wantHex = "4c414653454352455453005345435245542d56455253494f4e000001" +
		"0001" +
		"0000000874656e616e742d31" +
		"0000000970726f6a6563742d31" +
		"0000000d656e7669726f6e6d656e742d31" +
		"000000087365637265742d31" +
		"0000000976657273696f6e2d31" +
		"0000000000000007"

	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	if !bytes.Equal(aad, want) {
		t.Fatalf("encodeAAD() = %x, want %x", aad, want)
	}
}

func TestEncodeAADUsesUnambiguousLengthPrefixes(t *testing.T) {
	t.Parallel()

	left := testBinding()
	left.TenantID = "ab"
	left.ProjectID = "c"

	right := testBinding()
	right.TenantID = "a"
	right.ProjectID = "bc"

	leftAAD, err := encodeAAD(left)
	if err != nil {
		t.Fatalf("encodeAAD(left) error = %v", err)
	}
	rightAAD, err := encodeAAD(right)
	if err != nil {
		t.Fatalf("encodeAAD(right) error = %v", err)
	}
	if bytes.Equal(leftAAD, rightAAD) {
		t.Fatal("distinct bindings produced identical AAD")
	}
}

func TestEncodeAADRejectsIncompleteBindings(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Binding){
		"tenant": func(binding *Binding) {
			binding.TenantID = ""
		},
		"project": func(binding *Binding) {
			binding.ProjectID = ""
		},
		"environment": func(binding *Binding) {
			binding.EnvironmentID = ""
		},
		"secret": func(binding *Binding) {
			binding.SecretID = ""
		},
		"secret version": func(binding *Binding) {
			binding.SecretVersionID = ""
		},
		"version sequence": func(binding *Binding) {
			binding.VersionSequence = 0
		},
		"invalid UTF-8": func(binding *Binding) {
			binding.SecretID = string([]byte{0xff})
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			binding := testBinding()
			mutate(&binding)

			_, err := encodeAAD(binding)
			if !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("encodeAAD() error = %v, want ErrInvalidBinding", err)
			}
		})
	}
}
