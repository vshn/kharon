package cache

import (
	"fmt"
	"path/filepath"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

// InventoryFileVersion is the version of the inventory file format. It can be used to detect incompatible changes in the file format.
// It should be incremented whenever a change is made to the inventory file format that is not backwards compatible.
const inventoryFileVersion = 1

type inventoryFile struct {
	Version  int                  `json:"version"`
	Clusters []lieutenant.Cluster `json:"clusters"`
}

func InventoryFilePath() (string, error) {
	cd, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cd, "inventory.json"), nil
}

// WriteInventoryFile writes the given clusters to the inventory file in JSON format.
// If the file path is empty, it will be determined by InventoryFilePath.
func WriteInventoryFile(file string, clusters []lieutenant.Cluster) error {
	if file == "" {
		var err error
		file, err = InventoryFilePath()
		if err != nil {
			return err
		}
	}
	return writeJSONToFile(inventoryFile{
		Version:  inventoryFileVersion,
		Clusters: clusters,
	}, file)
}

// ReadInventoryFile reads the inventory file from the given file path and returns the clusters.
// If the file path is empty, it will be determined by InventoryFilePath.
// It returns an error if the file cannot be read or if the file format version does not match the expected version.
func ReadInventoryFile(file string) ([]lieutenant.Cluster, error) {
	if file == "" {
		var err error
		file, err = InventoryFilePath()
		if err != nil {
			return nil, err
		}
	}
	var inv inventoryFile
	if err := readJSONFromFile(file, &inv); err != nil {
		return nil, err
	}
	if inv.Version != inventoryFileVersion {
		return nil, fmt.Errorf("inventory file version %d does not match expected version %d", inv.Version, inventoryFileVersion)
	}
	return inv.Clusters, nil
}
