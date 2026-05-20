package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"sigs.k8s.io/yaml"
)

const stubShellScript = `#!/bin/sh
printf '%s' "$(basename -- "$0")"

for arg in "$@"; do
  printf ' %s' "$arg"
done

printf "\nKUBECONFIG"
cat $KUBECONFIG
`

func Test_RunShell(t *testing.T) {
	tmpInventoryFile := filepath.Join(t.TempDir(), "inventory.json")
	require.NoError(t, cache.WriteInventoryFile(tmpInventoryFile, []lieutenant.Cluster{
		{
			ID: "c-inventory",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.cluster-inventory.example.com",
			},
		},
	}))

	tmpPath := t.TempDir()
	t.Setenv("PATH", strings.Join([]string{tmpPath, os.Getenv("PATH")}, string(os.PathListSeparator)))
	for _, bin := range []string{"stubsh", "tool1", "tool2"} {
		require.NoError(t, os.WriteFile(filepath.Join(tmpPath, bin), []byte(stubShellScript), 0755))
	}
	t.Setenv("SHELL", "stubsh")

	for _, tc := range []struct {
		name string
		args []string

		expectedExitCode       int
		expectedErrorContains  string
		expectedStdout         string
		expectedStderr         string
		expectedCurrentContext string
	}{
		{
			name: "defaults to login shell and first cluster with ID in inventory",
			args: []string{},

			expectedStdout: "stubsh --login",

			expectedCurrentContext: "c-inventory",
		},
		{
			name: "defaults to login shell",
			args: []string{"c-cluster"},

			expectedStdout: "stubsh --login",

			expectedCurrentContext: "c-cluster",
		},
		{
			name: "passes arguments to shell",
			args: []string{"--", "-c", "hello"},

			expectedStdout: "stubsh -c hello",
		},
		{
			name: "passes arguments to shell",
			args: []string{"c-cluster", "--", "-c", "hello"},

			expectedStdout: "stubsh -c hello",

			expectedCurrentContext: "c-cluster",
		},
		{
			name: "uses provided command instead of shell",
			args: []string{"--command", "--", "tool1"},

			expectedStdout: "tool1",
		},
		{
			name: "uses provided command instead of shell",
			args: []string{"--command", "cluster1", "tool1"},

			expectedStdout: "tool1",

			expectedCurrentContext: "cluster1",
		},
		{
			name: "uses provided command instead of shell",
			args: []string{"--command", "cluster1", "--", "tool1", "--option", "value"},

			expectedStdout: "tool1 --option value",

			expectedCurrentContext: "cluster1",
		},
		{
			name: "command provided with --command flag but no command",
			args: []string{"--command"},

			expectedExitCode:      1,
			expectedErrorContains: "no command provided to run",
		},
		{
			name: "command exits with non-zero code",
			args: []string{"--command", "--", "sh", "-c", "exit 42"},

			expectedExitCode:      42,
			expectedErrorContains: "exit status 42",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newShellCmd()
			cmd.SetArgs(append([]string{"--inventory-file", tmpInventoryFile}, tc.args...))
			stdout := new(bytes.Buffer)
			cmd.SetOut(stdout)
			stderr := new(bytes.Buffer)
			cmd.SetErr(stderr)

			err := cmd.Execute()
			if tc.expectedErrorContains != "" {
				assert.ErrorContains(t, err, tc.expectedErrorContains)
			} else {
				assert.NoError(t, err)
			}
			if tc.expectedExitCode != 0 {
				if assert.Error(t, err) {
					code := 1
					exerr, ok := errors.AsType[*ErrWithExitCode](err)
					if ok {
						code = exerr.ExitCode
					} else {
						t.Logf("error without exit code, using 1: %v", err)
					}
					assert.Equal(t, tc.expectedExitCode, code, "unexpected exit code")
				}
			}
			if tc.expectedStdout != "" {
				stdoutCleaned, _, _ := cutOutputKubeconfig(stdout.String())
				assert.Equal(t, tc.expectedStdout, strings.TrimSpace(stdoutCleaned))
			}
			if tc.expectedStderr != "" {
				assert.Equal(t, tc.expectedStderr, strings.TrimSpace(stderr.String()))
			}
			if tc.expectedCurrentContext != "" {
				_, kubeconfigRaw, found := cutOutputKubeconfig(stdout.String())
				require.True(t, found, "KUBECONFIG not found in output")
				var kubeconfig map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(kubeconfigRaw), &kubeconfig), "failed to unmarshal kubeconfig")
				assert.Equal(t, tc.expectedCurrentContext, kubeconfig["current-context"], "unexpected current context in kubeconfig", "kubeconfig", kubeconfigRaw)
			}
		})
	}
}

func cutOutputKubeconfig(output string) (rest string, kubeconfig string, found bool) {
	return strings.Cut(output, "KUBECONFIG")
}
