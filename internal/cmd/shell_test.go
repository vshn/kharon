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
	"sigs.k8s.io/yaml"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
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
			ID: "c-no-api-url",
		},
		{
			ID: "c-inventory-1",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.cluster-inventory-1.example.com",
			},
		}, {
			ID: "c-inventory-2",
			Facts: map[string]any{
				"env": "prod",
			},
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.cluster-inventory-2.example.com",
			},
		}, {
			ID: "c-other-cluster",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.cluster-other-cluster.example.com",
				"huh": "ugh",
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

			expectedCurrentContext: "c-inventory-1",
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
		}, {
			name: "filters clusters with wildcard pattern and uses first match as context",

			args: []string{"*inventory*", "--each", "--", "go", "run", "./testdata/kubectx"},

			expectedStdout: `--- # c-inventory-1
c-inventory-1
--- # c-inventory-2
c-inventory-2`,
		}, {
			name: "execution does not fail on first cluster failure when using --each",

			args: []string{"*inventory*", "--each", "--", "sh", "-c", "echo 'oh no';exit 34"},

			expectedStdout: `--- # c-inventory-1
oh no

--- # c-inventory-2
oh no`,
			expectedErrorContains: "failed to run command for cluster c-inventory-1: provided command exited with code 34: exit status 34; failed to run command for cluster c-inventory-2: provided command exited with code 34: exit status 34",
		}, {
			name: "--exclude-cluster",

			args: []string{"*inventory*", "--each", "--exclude-cluster", "c-inventory-1", "--", "sh", "-c", "exit 0"},

			expectedStdout: `--- # c-inventory-2`,
		}, {
			name: "--each forces cluster pattern matching even without wildcards",

			args: []string{"c-inventory-1", "--each", "--", "sh", "-c", "exit 0"},

			expectedStdout: `--- # c-inventory-1`,
		}, {
			name: "match facts with --fact-selector",

			args: []string{"--each", "--fact-selector", "env=prod", "--", "sh", "-c", "exit 0"},

			expectedStdout: `--- # c-inventory-2`,
		}, {
			name: "match facts with --dynamic-fact-selector",

			args: []string{"--each", "--dynamic-fact-selector", "huh=ugh", "--", "sh", "-c", "exit 0"},

			expectedStdout: `--- # c-other-cluster`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newShellCmd()
			cmd.SilenceUsage = true
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
