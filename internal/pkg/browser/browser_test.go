package browser_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/browser"
)

func Test_BrowserFromEnv(t *testing.T) {
	t.Setenv("BROWSER", "printf %s")
	oldStdout := browser.Stdout
	browser.Stdout = &strings.Builder{}
	t.Cleanup(func() {
		browser.Stdout = oldStdout
	})

	const url = "https://example.com"
	require.NoError(t, browser.OpenURL(t.Context(), url))
	require.Equal(t, url, browser.Stdout.(*strings.Builder).String())
}

func Test_Browser(t *testing.T) {
	td := t.TempDir()
	t.Setenv("PATH", strings.Join([]string{td, os.Getenv("PATH")}, string(os.PathListSeparator)))
	for _, name := range []string{"xdg-open", "open"} {
		require.NoError(t, os.WriteFile(filepath.Join(td, name), []byte("#!/bin/sh\nprintf %s \"$1\""), 0o755))
	}

	oldStdout := browser.Stdout
	browser.Stdout = &strings.Builder{}
	t.Cleanup(func() {
		browser.Stdout = oldStdout
	})

	const url = "https://example.com"
	require.NoError(t, browser.OpenURL(t.Context(), url))
	require.Equal(t, url, browser.Stdout.(*strings.Builder).String())
}
