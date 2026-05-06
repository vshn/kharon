//go:build unix

package activation

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
)

// https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html#Description
const (
	systemdListenFDStart       = 3
	systemdListenFDNamesEnvVar = "LISTEN_FDNAMES"
)

func SystemdListener(name string) func() (net.Listener, error) {
	slog.Debug("systemd socket activation", "socket_name", name, systemdListenFDNamesEnvVar, os.Getenv(systemdListenFDNamesEnvVar))
	names := os.Getenv(systemdListenFDNamesEnvVar)
	if names == "" {
		return func() (net.Listener, error) {
			return nil, fmt.Errorf("%s environment variable is not set, cannot determine file descriptor for systemd socket", systemdListenFDNamesEnvVar)
		}
	}
	index := slices.Index(strings.Split(names, ":"), name)
	if index == -1 {
		return func() (net.Listener, error) {
			return nil, fmt.Errorf("socket name '%s' not found in %s", name, systemdListenFDNamesEnvVar)
		}
	}
	fd := systemdListenFDStart + index

	return func() (net.Listener, error) {
		syscall.CloseOnExec(fd)
		return net.FileListener(os.NewFile(uintptr(fd), name))
	}
}
