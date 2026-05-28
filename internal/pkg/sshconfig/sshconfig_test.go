package sshconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ConfigForHost(t *testing.T) {
	c, err := ConfigForHost("example.com")
	require.NoError(t, err)
	require.Contains(t, c, "hostname")
}
