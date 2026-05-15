package browser_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/browser"
)

func Test_Browser(t *testing.T) {
	td := t.TempDir()
	t.Setenv("PATH", strings.Join([]string{td, os.Getenv("PATH")}, string(os.PathListSeparator)))
	for _, name := range []string{"xdg-open", "open"} {
		require.NoError(t, os.WriteFile(filepath.Join(td, name), []byte("#!/bin/sh\nprintf \"OPEN %s\" \"$1\""), 0o755))
	}

	tcs := []struct {
		name string

		KHARON_BROWSER string
		BROWSER        string

		expectedMarker string
	}{
		{
			name:           "KHARON_BROWSER takes precedence over BROWSER",
			KHARON_BROWSER: "printf \"KHARON_BROWSER %s\"",
			BROWSER:        "printf \"BROWSER %s\"",
			expectedMarker: "KHARON_BROWSER",
		},
		{
			name:           "BROWSER is used if KHARON_BROWSER is not set",
			BROWSER:        "printf \"BROWSER %s\"",
			expectedMarker: "BROWSER",
		},
		{
			name:           "default browser is used if neither KHARON_BROWSER nor BROWSER is set",
			expectedMarker: "OPEN",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KHARON_BROWSER", tc.KHARON_BROWSER)
			t.Setenv("BROWSER", tc.BROWSER)

			oldStdout := browser.Stdout
			browser.Stdout = &strings.Builder{}
			t.Cleanup(func() {
				browser.Stdout = oldStdout
			})

			const url = "https://example.com"
			require.NoError(t, browser.OpenURL(t.Context(), url))
			require.Equal(t, strings.Join([]string{tc.expectedMarker, url}, " "), browser.Stdout.(*strings.Builder).String())
		})
	}
}
