//go:build !darwin

package activation

import (
	"fmt"
	"net"
)

func LaunchdListener(socketName string) func() (net.Listener, error) {
	return func() (net.Listener, error) {
		return nil, fmt.Errorf("launchd is not supported on this platform")
	}
}
