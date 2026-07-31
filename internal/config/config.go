package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

const (
	RuntimeModeVariable = "LAFSECRETS_RUNTIME_MODE"
	HTTPAddressVariable = "LAFSECRETS_HTTP_ADDRESS"

	defaultHTTPAddress = "127.0.0.1:8080"
	variablePrefix     = "LAFSECRETS_"
)

var (
	ErrInvalidConfiguration  = errors.New("invalid configuration")
	ErrProductionUnavailable = errors.New(
		"production mode is unavailable until required security providers are configured",
	)
)

type RuntimeMode string

const (
	RuntimeModeDevelopment RuntimeMode = "development"
	RuntimeModeStaging     RuntimeMode = "staging"
	RuntimeModeProduction  RuntimeMode = "production"
)

type Config struct {
	RuntimeMode RuntimeMode
	HTTPAddress string
}

func Parse(environ []string) (Config, error) {
	values := make(map[string]string, 2)

	for _, entry := range environ {
		name, value, found := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, variablePrefix) {
			continue
		}
		if !found {
			return Config{}, fmt.Errorf(
				"%w: malformed Laf Secrets environment variable",
				ErrInvalidConfiguration,
			)
		}
		if name != RuntimeModeVariable && name != HTTPAddressVariable {
			return Config{}, fmt.Errorf(
				"%w: unknown Laf Secrets environment variable",
				ErrInvalidConfiguration,
			)
		}
		if _, duplicate := values[name]; duplicate {
			return Config{}, fmt.Errorf(
				"%w: duplicate Laf Secrets environment variable",
				ErrInvalidConfiguration,
			)
		}
		values[name] = value
	}

	runtimeMode, err := parseRuntimeMode(values)
	if err != nil {
		return Config{}, err
	}

	httpAddress := defaultHTTPAddress
	if value, configured := values[HTTPAddressVariable]; configured {
		httpAddress = value
	}
	if err := validateHTTPAddress(httpAddress); err != nil {
		return Config{}, err
	}

	return Config{
		RuntimeMode: runtimeMode,
		HTTPAddress: httpAddress,
	}, nil
}

func parseRuntimeMode(values map[string]string) (RuntimeMode, error) {
	value, configured := values[RuntimeModeVariable]
	if !configured || value == "" {
		return "", fmt.Errorf(
			"%w: %s is required",
			ErrInvalidConfiguration,
			RuntimeModeVariable,
		)
	}

	runtimeMode := RuntimeMode(value)
	switch runtimeMode {
	case RuntimeModeDevelopment, RuntimeModeStaging:
		return runtimeMode, nil
	case RuntimeModeProduction:
		return "", ErrProductionUnavailable
	default:
		return "", fmt.Errorf(
			"%w: %s has an unsupported value",
			ErrInvalidConfiguration,
			RuntimeModeVariable,
		)
	}
}

func validateHTTPAddress(address string) error {
	if address == "" ||
		len(address) > 255 ||
		strings.IndexFunc(address, unicode.IsSpace) >= 0 ||
		strings.IndexFunc(address, unicode.IsControl) >= 0 {
		return fmt.Errorf(
			"%w: %s is invalid",
			ErrInvalidConfiguration,
			HTTPAddressVariable,
		)
	}

	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf(
			"%w: %s is invalid",
			ErrInvalidConfiguration,
			HTTPAddressVariable,
		)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf(
			"%w: %s is invalid",
			ErrInvalidConfiguration,
			HTTPAddressVariable,
		)
	}

	return nil
}
