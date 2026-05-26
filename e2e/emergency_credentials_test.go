package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/config"
)

const (
	clusterId = "c-appuio-lab-cloudscale-rma-0"
)

func Test_EmergencyCredentials_NonInteractive(t *testing.T) {
	if os.Getenv("WANT_E2E") == "" {
		t.Skip("Set WANT_E2E=1 to run this test")
	}

	tmpDir := t.TempDir()
	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	key := mustEnv(t, "E2E_PASSBOLT_PRIVATE_KEY")
	passphrase := mustEnv(t, "E2E_PASSBOLT_PASSPHRASE")
	totp := mustEnv(t, "E2E_PASSBOLT_TOTP_KEY_BASE32")

	kharonCmd := exec.CommandContext(t.Context(), "go", "run", "..", "emergency-credentials", "-v", "-100", "--proxy-addr", "", "--inventory-file", "testdata/inventory.json", clusterId)
	kharonCmd.Env = append(os.Environ(),
		"KHARON_PASSBOLT_KEY="+key,
		"KHARON_PASSBOLT_PASSPHRASE="+passphrase,
		"KHARON_PASSBOLT_TOTP="+mustGenerateTOTPCode(t, totp),
		"KUBECONFIG="+kubeconfigPath,
	)
	kharonCmd.Stdout = t.Output()
	kharonCmd.Stderr = t.Output()

	require.NoError(t, kharonCmd.Run(), "Emergency credentials command failed")

	mustHavePassboltKeyWritten(t)

	mustHaveNodeDeletePermissions(t, kubeconfigPath)
}

func Test_EmergencyCredentials_WithLegacyConfig(t *testing.T) {
	if os.Getenv("WANT_E2E") == "" {
		t.Skip("Set WANT_E2E=1 to run this test")
	}

	tmpDir := t.TempDir()
	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	key := mustEnv(t, "E2E_PASSBOLT_PRIVATE_KEY")
	passphrase := mustEnv(t, "E2E_PASSBOLT_PASSPHRASE")
	totp := mustEnv(t, "E2E_PASSBOLT_TOTP_KEY_BASE32")

	legacyConfigJson, err := json.Marshal(map[string]string{"passbolt_key": key})
	require.NoError(t, err, "Failed to marshal legacy config")

	legacyConfigPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(legacyConfigPath, legacyConfigJson, 0600), "Failed to write legacy config file")

	kharonCmd := exec.CommandContext(t.Context(), "go", "run", "..", "emergency-credentials", "-v", "-100", "--proxy-addr", "", "--inventory-file", "testdata/inventory.json", clusterId)
	kharonCmd.Env = append(os.Environ(),
		"EMR_CONFIG_DIR="+tmpDir,
		"KHARON_PASSBOLT_PASSPHRASE="+passphrase,
		"KHARON_PASSBOLT_TOTP="+mustGenerateTOTPCode(t, totp),
		"KUBECONFIG="+kubeconfigPath,
	)
	kharonCmd.Stdout = t.Output()
	kharonCmd.Stderr = t.Output()

	require.NoError(t, kharonCmd.Run(), "Emergency credentials command failed")

	mustHavePassboltKeyWritten(t)

	mustHaveNodeDeletePermissions(t, kubeconfigPath)
}

func Test_EmergencyCredentials_Interactive(t *testing.T) {
	if os.Getenv("WANT_E2E") == "" {
		t.Skip("Set WANT_E2E=1 to run this test")
	}

	tmpDir := t.TempDir()
	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	key := mustEnv(t, "E2E_PASSBOLT_PRIVATE_KEY")
	passphrase := mustEnv(t, "E2E_PASSBOLT_PASSPHRASE")
	totp := mustEnv(t, "E2E_PASSBOLT_TOTP_KEY_BASE32")

	kharonCmd := exec.CommandContext(t.Context(), "go", "run", "..", "emergency-credentials", "-v", "-100", "--proxy-addr", "", "--inventory-file", "testdata/inventory.json", clusterId)
	kharonCmd.Env = append(os.Environ(),
		"KHARON_PASSBOLT_KEY=",
		"KHARON_PASSBOLT_PASSPHRASE=",
		"KHARON_PASSBOLT_TOTP=",
		"KUBECONFIG="+kubeconfigPath,
	)
	pty, err := pty.Start(kharonCmd)
	require.NoError(t, err, "Failed to setup pty for kharon command")
	var out bytes.Buffer
	var wg sync.WaitGroup
	wg.Go(func() {
		defer pty.Close()
		io.Copy(&out, pty)
	})

	sendToPrompt(t, pty, &out, "Please paste the passbolt key", key+"\n\x04")

	sendToPrompt(t, pty, &out, "Please enter your Passbolt passphrase", passphrase+"\n")

	sendToPrompt(t, pty, &out, "Please enter the Passbolt TOTP code", mustGenerateTOTPCode(t, totp)+"\n")

	wg.Wait()

	mustHavePassboltKeyWritten(t)

	mustHaveNodeDeletePermissions(t, kubeconfigPath)
}

func sendToPrompt(t *testing.T, pty *os.File, out *bytes.Buffer, prompt string, response string) {
	timeout := time.After(30 * time.Second)
	t.Helper()

	t.Logf("Waiting for prompt: %s", prompt)
	lastOutputLen := 0
	for range time.Tick(100 * time.Millisecond) {
		if bytes.Contains(out.Bytes(), []byte(prompt)) {
			break
		}
		if out.Len() > lastOutputLen {
			t.Log("Current output:", sanitizeOutput(out.String()))
			lastOutputLen = out.Len()
		}
		select {
		case <-timeout:
			t.Fatalf("Timed out waiting for prompt: %s. Final output: %s", prompt, sanitizeOutput(out.String()))
		default:
		}
	}
	_, err := pty.WriteString(response)
	require.NoError(t, err, "Failed to write response to stdin")
}

func mustHaveNodeDeletePermissions(t *testing.T, kubeconfigPath string) {
	t.Helper()

	kubectlCmd := exec.Command("kubectl", "auth", "can-i", "delete", "nodes")
	kubectlCmd.Env = append(os.Environ(),
		"KUBECONFIG="+kubeconfigPath,
	)
	kubectlCmd.Stdout = t.Output()
	kubectlCmd.Stderr = t.Output()
	require.NoError(t, kubectlCmd.Run(), "Current user does not have permissions to delete nodes")
}

func mustHavePassboltKeyWritten(t *testing.T) {
	t.Helper()

	dir, err := config.ConfigDir()
	require.NoError(t, err, "Failed to get config dir")

	keyFile := filepath.Join(dir, "passbolt_key")
	_, err = os.Stat(keyFile)
	require.NoError(t, err, "Passbolt key file does not exist in config dir")

	require.NoError(t, os.Remove(keyFile), "Failed to remove passbolt key file after test")
}

func mustEnv(t *testing.T, envVar string) string {
	t.Helper()

	value := os.Getenv(envVar)
	if value == "" {
		t.Fatalf("Environment variable %s is required but not set", envVar)
	}
	return value
}

// mustGenerateTOTPCode generates a TOTP code for the given base32-encoded secret.
func mustGenerateTOTPCode(t *testing.T, in string) string {
	t.Helper()

	out, err := totp.GenerateCode(in, time.Now())
	require.NoError(t, err, "Failed to generate TOTP code")
	return out
}

var privateKeyRegex = regexp.MustCompile(`(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.+?-----END PGP PRIVATE KEY BLOCK-----`)

func sanitizeOutput(output string) string {
	return privateKeyRegex.ReplaceAllString(output, "*** REDACTED PRIVATE KEY ***")
}
