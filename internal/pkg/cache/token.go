package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	Expiry time.Time
	Token  string
}

// GetToken retrieves a cached token for the API URL.
// It does not care about [Entry.Expiry].
func GetToken(apiURL string) (Entry, error) {
	tokenFile, err := tokenCacheFile(apiURL)
	if err != nil {
		return Entry{}, err
	}

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Entry{}, nil // No token cached, return empty string without error
		}
		return Entry{}, err
	}
	var entry Entry
	return entry, json.Unmarshal(data, &entry)
}

func WriteToken(apiURL string, token Entry) error {
	tokenFile, err := tokenCacheFile(apiURL)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(tokenFile), 0700); err != nil {
		return err
	}

	raw, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	return os.WriteFile(tokenFile, raw, 0600)
}

func tokenCacheFile(apiURL string) (string, error) {
	cd, err := CacheDir()
	if err != nil {
		return "", err
	}

	b := sha256.Sum256([]byte(apiURL))
	hash := base64.RawURLEncoding.EncodeToString(b[:])
	filename := "token_v2_" + hash

	return filepath.Join(cd, "tokens", filename), nil
}
