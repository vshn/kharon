package emcred

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"sigs.k8s.io/yaml"
)

type legacyConfig struct {
	PassboltKey string `json:"passbolt_key"`
}

// legacyEMRConfigDir returns the path to the config directory used by the legacy emergency-credentials-receive tool.
// Config path precedence: EMR_CONFIG_DIR, XDG_CONFIG_HOME, AppData (windows only), HOME.
func legacyEMRConfigDir() (string, error) {
	const configDirName = "emergency-credentials-receive"
	var path string
	if a := os.Getenv("EMR_CONFIG_DIR"); a != "" {
		path = a
	} else if b := os.Getenv("XDG_CONFIG_HOME"); b != "" {
		path = filepath.Join(b, configDirName)
	} else if c := os.Getenv("AppData"); runtime.GOOS == "windows" && c != "" {
		path = filepath.Join(c, configDirName)
	} else {
		d, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(d, ".config", configDirName)
	}
	return path, nil
}

func readLegacyConfig() (legacyConfig, error) {
	configPath, err := legacyEMRConfigDir()
	if err != nil {
		return legacyConfig{}, fmt.Errorf("error getting config file path: %w", err)
	}

	configFile := filepath.Join(configPath, "config.yaml")
	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return legacyConfig{}, fmt.Errorf("error reading config file %q: %w", configFile, err)
	}

	var config legacyConfig
	if err := yaml.Unmarshal([]byte(yamlFile), &config); err != nil {
		return legacyConfig{}, fmt.Errorf("error parsing config file %q: %w", configFile, err)
	}

	return config, nil
}
