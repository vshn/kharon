package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_GetAndWriteToken(t *testing.T) {
	mockUserCacheDir(t)
	apiURL := "https://api.example.com"

	token, err := GetToken(apiURL)
	require.NoError(t, err)
	require.Empty(t, token)

	writtenToken := Entry{
		Expiry: time.Date(2025, time.January, 1, 23, 12, 0, 0, time.UTC),
		Token:  "test-token",
	}
	err = WriteToken(apiURL, writtenToken)
	require.NoError(t, err)

	token, err = GetToken(apiURL)
	require.NoError(t, err)
	require.Equal(t, writtenToken, token)

	token, err = GetToken(apiURL + ":8080")
	require.NoError(t, err)
	require.Empty(t, token)
}
