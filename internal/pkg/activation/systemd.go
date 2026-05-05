//go:build unix

package activation

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
)

func SystemdListener(name string) func() (net.Listener, error) {
	names := os.Getenv("LISTEN_FDNAMES")
	if names == "" {
		return func() (net.Listener, error) {
			return nil, fmt.Errorf("LISTEN_FDNAMES environment variable is not set, cannot determine file descriptor for systemd socket")
		}
	}
	index := slices.Index(strings.Split(names, ":"), name)
	if index == -1 {
		return func() (net.Listener, error) {
			return nil, fmt.Errorf("socket name '%s' not found in LISTEN_FDNAMES", name)
		}
	}
	fd := 3 + index

	return func() (net.Listener, error) {
		syscall.CloseOnExec(fd)
		return net.FileListener(os.NewFile(uintptr(fd), name))
	}
}
