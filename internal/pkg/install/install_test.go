package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InstallLaunchdService(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive=%v", interactive), func(t *testing.T) {
			tmpHome := withTempHome(t)
			calls := withMockedExecutable(t)
			if interactive {
				withStdin(t, "y\n")
			} else {
				withStdin(t, "")
			}
			withUID(t, 1000)

			err := InstallLaunchdService(!interactive)
			require.NoError(t, err)

			contents := requireReadFileContent(t, filepath.Join(tmpHome, "Library", "LaunchAgents", "io.vshn.Kharon.plist"))
			assert.Contains(t, contents, requireExecutable(t))
			assert.Contains(t, contents, tmpHome)
			assert.Contains(t, contents, "12000")

			expectedPath := filepath.Join(tmpHome, "Library", "LaunchAgents", "io.vshn.Kharon.plist")
			assert.Contains(t, calls(), fmt.Sprintf("launchctl bootout gui/1000/%s", launchdServiceLabel))
			assert.Contains(t, calls(), fmt.Sprintf("launchctl bootstrap gui/1000 %s", expectedPath))
		})
	}
}

func Test_InstallSystemdService(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive=%v", interactive), func(t *testing.T) {
			tmpHome := withTempHome(t)
			calls := withMockedExecutable(t)

			if interactive {
				withStdin(t, "y\ny\n")
			} else {
				withStdin(t, "")
			}

			withUID(t, 1000)
			err := InstallSystemdService(!interactive)
			require.NoError(t, err)

			serviceContents := requireReadFileContent(t, filepath.Join(tmpHome, ".config", "systemd", "user", "kharon.service"))
			assert.Contains(t, serviceContents, requireExecutable(t))
			socketContents := requireReadFileContent(t, filepath.Join(tmpHome, ".config", "systemd", "user", "kharon.socket"))
			assert.Contains(t, socketContents, "12000")

			assert.Contains(t, calls(), "systemctl --user enable kharon.socket")
			assert.Contains(t, calls(), "systemctl --user enable --now kharon.service")
		})
	}
}

func requireExecutable(t *testing.T) string {
	t.Helper()

	executable, err := os.Executable()
	require.NoError(t, err)
	return executable
}

func requireReadFileContent(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

func withUID(t *testing.T, uid int) {
	t.Helper()

	oldUIDFunc := uidFunc
	t.Cleanup(func() {
		uidFunc = oldUIDFunc
	})
	uidFunc = func() int {
		return uid
	}
}

func withStdin(t *testing.T, input string) {
	t.Helper()

	oldStdin := stdin
	t.Cleanup(func() {
		stdin = oldStdin
	})
	stdin = strings.NewReader(input)
}

func withMockedExecutable(t *testing.T) func() string {
	t.Helper()

	tmpPath := t.TempDir()
	logFile := filepath.Join(tmpPath, "out.log")
	require.NoError(t, os.WriteFile(logFile, []byte{}, 0644))

	os.Setenv("PATH", fmt.Sprintf("%s%s%s", tmpPath, string(os.PathListSeparator), os.Getenv("PATH")))
	for _, name := range []string{"launchctl", "systemctl"} {
		mockPath := filepath.Join(tmpPath, name)
		err := os.WriteFile(mockPath, []byte("#!/bin/bash\necho \"$0\" \"$@\" >> "+logFile), 0755)
		require.NoError(t, err)
	}

	return func() string {
		content, err := os.ReadFile(logFile)
		require.NoError(t, err)
		return string(content)
	}
}

func withTempHome(t *testing.T) string {
	t.Helper()

	tmpHome := t.TempDir()
	oldUserHomeFunc := userHomeFunc
	t.Cleanup(func() {
		userHomeFunc = oldUserHomeFunc
	})
	userHomeFunc = func() (string, error) {
		return tmpHome, nil
	}
	return tmpHome
}
