package cache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GetAndWriteToken(t *testing.T) {
	mockUserCacheDir(t)
	apiURL := "https://api.example.com"

	token, err := GetToken(apiURL)
	require.NoError(t, err)
	require.Empty(t, token)

	err = WriteToken(apiURL, "test-token")
	require.NoError(t, err)

	token, err = GetToken(apiURL)
	require.NoError(t, err)
	require.Equal(t, "test-token", token)

	token, err = GetToken(apiURL + ":8080")
	require.NoError(t, err)
	require.Empty(t, token)
}
