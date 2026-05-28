package cache

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
)

func GetToken(apiURL string) (string, error) {
	tokenFile, err := tokenCacheFile(apiURL)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No token cached, return empty string without error
		}
		return "", err
	}
	return string(data), nil
}

func WriteToken(apiURL, token string) error {
	tokenFile, err := tokenCacheFile(apiURL)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(tokenFile), 0700); err != nil {
		return err
	}

	return os.WriteFile(tokenFile, []byte(token), 0600)
}

func tokenCacheFile(apiURL string) (string, error) {
	cd, err := CacheDir()
	if err != nil {
		return "", err
	}

	b := sha256.Sum256([]byte(apiURL))
	hash := base64.RawURLEncoding.EncodeToString(b[:])
	filename := "token_" + hash

	return filepath.Join(cd, "tokens", filename), nil
}
