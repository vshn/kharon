package emcred

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vshn/kharon/internal/pkg/config"
)

// ReadPassboltKey reads the Passbolt private key from the config directory.
func ReadPassboltKey() (string, error) {
	configDir, err := config.ConfigDir()
	if err != nil {
		return "", fmt.Errorf("error getting config dir: %w", err)
	}

	keyFile := filepath.Join(configDir, "passbolt_key")
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("error reading passbolt key %q: %w", keyFile, err)
	}

	return string(keyBytes), nil
}

// WritePassboltKey writes the Passbolt private key to the config directory.
func WritePassboltKey(key string) error {
	configDir, err := config.ConfigDir()
	if err != nil {
		return fmt.Errorf("error getting config dir: %w", err)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("error creating config dir %q: %w", configDir, err)
	}

	keyFile := filepath.Join(configDir, "passbolt_key")
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		return fmt.Errorf("error writing passbolt key %q: %w", keyFile, err)
	}

	return nil
}
