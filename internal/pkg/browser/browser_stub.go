//go:build !linux && !darwin

package browser

import (
	"fmt"
	"runtime"
)

func executable() (string, error) {
	return "", fmt.Errorf("unsupported operating system: %v", runtime.GOOS)
}
