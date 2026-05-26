package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConfigDir(t *testing.T) {
	mockUserConfigDir(t, func() (string, error) {
		return "/config", nil
	})

	configDir, err := ConfigDir()
	require.NoError(t, err)
	require.Equal(t, "/config/io.vshn.kharon", configDir)
}

func Test_ConfigDir_Error(t *testing.T) {
	mockUserConfigDir(t, func() (string, error) {
		return "", assert.AnError
	})

	_, err := ConfigDir()
	require.ErrorIs(t, err, assert.AnError)
}

func mockUserConfigDir(t *testing.T, f func() (string, error)) {
	originalFunc := userConfigDirFunc
	userConfigDirFunc = f
	t.Cleanup(func() {
		userConfigDirFunc = originalFunc
	})
}
