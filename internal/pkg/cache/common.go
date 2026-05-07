package cache

import (
	"os"
	"path/filepath"
)

const label = "io.vshn.kharon"

// CacheDir returns the directory path where kharon stores its various cache files.
func CacheDir() (string, error) {
	cp, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cp, label), nil
}
