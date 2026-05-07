package cache

import (
	"path/filepath"
)

// ProxyMappingFilePath returns the file path where the proxy expects the domain to jumphost mapping file to be located.
func ProxyMappingFilePath() (string, error) {
	cp, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cp, "proxy", "domain_jumphost_mapping.json"), nil
}
