//go:build linux

package browser

import (
	"os/exec"
	"strings"
)

func executable() (string, error) {
	providers := []string{"xdg-open", "x-www-browser"}

	for _, provider := range providers {
		if _, err := exec.LookPath(provider); err == nil {
			return provider, nil
		}
	}

	return "", &exec.Error{Name: strings.Join(providers, ","), Err: exec.ErrNotFound}
}
