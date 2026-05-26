package config

import (
	"os"
	"path/filepath"
)

const label = "io.vshn.kharon"

var userConfigDirFunc = os.UserConfigDir

// ConfigDir returns the directory path where kharon stores its various config files.
func ConfigDir() (string, error) {
	cp, err := userConfigDirFunc()
	if err != nil {
		return "", err
	}
	return filepath.Join(cp, label), nil
}
