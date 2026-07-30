package config

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUsesSecureLocalDefault(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		"UNRELATED=value",
		RuntimeModeVariable + "=development",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.RuntimeMode != RuntimeModeDevelopment {
		t.Fatalf("RuntimeMode = %q, want %q", cfg.RuntimeMode, RuntimeModeDevelopment)
	}
	if cfg.HTTPAddress != defaultHTTPAddress {
		t.Fatalf("HTTPAddress = %q, want %q", cfg.HTTPAddress, defaultHTTPAddress)
	}
}

func TestParseAcceptsExplicitStagingAddress(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]string{
		RuntimeModeVariable + "=staging",
		HTTPAddressVariable + "=[::1]:9090",
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.RuntimeMode != RuntimeModeStaging {
		t.Fatalf("RuntimeMode = %q, want %q", cfg.RuntimeMode, RuntimeModeStaging)
	}
	if cfg.HTTPAddress != "[::1]:9090" {
		t.Fatalf("HTTPAddress = %q, want %q", cfg.HTTPAddress, "[::1]:9090")
	}
}

func TestParseRejectsProductionUntilDependenciesExist(t *testing.T) {
	t.Parallel()

	_, err := Parse([]string{RuntimeModeVariable + "=production"})
	if !errors.Is(err, ErrProductionUnavailable) {
		t.Fatalf("Parse() error = %v, want ErrProductionUnavailable", err)
	}
}

func TestParseRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"missing runtime mode": nil,
		"empty runtime mode": {
			RuntimeModeVariable + "=",
		},
		"unsupported runtime mode": {
			RuntimeModeVariable + "=preview",
		},
		"unknown variable": {
			RuntimeModeVariable + "=development",
			"LAFSECRETS_UNEXPECTED=marker",
		},
		"duplicate variable": {
			RuntimeModeVariable + "=development",
			RuntimeModeVariable + "=staging",
		},
		"malformed variable": {
			RuntimeModeVariable + "=development",
			"LAFSECRETS_UNEXPECTED",
		},
		"missing port": {
			RuntimeModeVariable + "=development",
			HTTPAddressVariable + "=127.0.0.1",
		},
		"zero port": {
			RuntimeModeVariable + "=development",
			HTTPAddressVariable + "=127.0.0.1:0",
		},
		"out of range port": {
			RuntimeModeVariable + "=development",
			HTTPAddressVariable + "=127.0.0.1:65536",
		},
		"whitespace in address": {
			RuntimeModeVariable + "=development",
			HTTPAddressVariable + "=127.0.0.1:8080 ",
		},
	}

	for name, environ := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Parse(environ)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Parse() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestParseErrorsDoNotEchoConfigurationValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-marker"
	_, err := Parse([]string{
		RuntimeModeVariable + "=development",
		HTTPAddressVariable + "=" + marker,
	})
	if err == nil {
		t.Fatal("Parse() error = nil, want an error")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("Parse() error disclosed the rejected value: %v", err)
	}
}
