package cache

import (
	"encoding/json"
	"fmt"
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

func writeJSONToFile(data any, filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory path %q: %w", dir, err)
	}
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %q for writing: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("failed to encode data to JSON and write to file %q: %w", filePath, err)
	}
	return nil
}

func readJSONFromFile(filePath string, data any) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %q for reading: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()
	if err := json.NewDecoder(f).Decode(data); err != nil {
		return fmt.Errorf("failed to decode JSON data from file %q: %w", filePath, err)
	}
	return nil
}
