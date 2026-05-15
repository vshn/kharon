package cache

import (
	"fmt"
	"path/filepath"

	"github.com/vshn/kharon/internal/pkg/proxy/mapping"
)

// ProxyMappingFileVersion is the version of the proxy file format. It can be used to detect incompatible changes in the file format.
// It should be incremented whenever a change is made to the proxy file format that is not backwards compatible.
const proxyMappingFileVersion = 2

type jumphostMapping struct {
	DomainToJumphost    map[string]string `json:"domainToJumphost"`
	DirectAccessDomains []string          `json:"directAccessDomains"`
}

type proxyMappingFile struct {
	Version int             `json:"version"`
	Mapping jumphostMapping `json:"mapping"`
}

func ProxyMappingFilePath() (string, error) {
	cd, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cd, "proxy", "domain_jumphost_mapping.json"), nil
}

// WriteProxyMappingFile writes the given clusters to the proxy file in JSON format.
// If the file path is empty, it will be determined by ProxyMappingFilePath.
func WriteProxyMappingFile(file string, mapping mapping.JumphostMapping) error {
	if file == "" {
		var err error
		file, err = ProxyMappingFilePath()
		if err != nil {
			return err
		}
	}
	return writeJSONToFile(proxyMappingFile{
		Version: proxyMappingFileVersion,
		Mapping: jumphostMapping(mapping),
	}, file)
}

// ReadProxyMappingFile reads the proxy file from the given file path and returns the clusters.
// If the file path is empty, it will be determined by ProxyMappingFilePath.
// It returns an error if the file cannot be read or if the file format version does not match the expected version.
func ReadProxyMappingFile(file string) (mapping.JumphostMapping, error) {
	if file == "" {
		var err error
		file, err = ProxyMappingFilePath()
		if err != nil {
			return mapping.JumphostMapping{}, err
		}
	}
	var inv proxyMappingFile
	if err := readJSONFromFile(file, &inv); err != nil {
		return mapping.JumphostMapping{}, err
	}
	if inv.Version != proxyMappingFileVersion {
		return mapping.JumphostMapping{}, fmt.Errorf("proxy file version %d does not match expected version %d", inv.Version, proxyMappingFileVersion)
	}
	return mapping.JumphostMapping(inv.Mapping), nil
}
