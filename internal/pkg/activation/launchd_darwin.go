//go:build darwin

package activation

import (
	"net"

	launchd "github.com/bored-engineer/go-launchd"
)

func LaunchdListener(socketName string) func() (net.Listener, error) {
	return func() (net.Listener, error) {
		return launchd.Activate(socketName)
	}
}
