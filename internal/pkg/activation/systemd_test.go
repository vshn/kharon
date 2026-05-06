package activation

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func Test_SystemdListener(t *testing.T) {
	cmd := exec.Command("go", "run", "./testdata")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to listen for test server")
	f, err := l.(*net.TCPListener).File()
	require.NoError(t, err, "failed to get file for test server listener")

	require.NoError(t, err)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=activation.socket", systemdListenFDNamesEnvVar))

	var wg errgroup.Group
	wg.Go(func() error {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return fmt.Errorf("failed to connect to test server: %w", err)
		}
		defer c.Close()
		raw, err := io.ReadAll(c)
		if err != nil {
			return fmt.Errorf("failed to read from test server: %w", err)
		}
		if string(raw) != "Hello from systemd socket activation!\n" {
			return fmt.Errorf("unexpected output from activation.go: %s", string(raw))
		}
		return nil
	})
	wg.Go(func() error {
		defer l.Close()
		defer f.Close()

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to run activation.go: %v\nOutput: %s", err, string(output))
		}
		return nil
	})

	require.NoError(t, wg.Wait())
}
