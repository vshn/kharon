package sshconfig

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SSHConfig_ConfigForHost(t *testing.T) {
	c, err := SSHConfig{}.ConfigForHost("example.com")
	require.NoError(t, err)
	require.Equal(t, "example.com", c.Get("hostname"))
}

func Test_SSHConfigWithCache_ConfigForHost(t *testing.T) {
	confFile := t.TempDir() + "/ssh_config"
	os.WriteFile(confFile, []byte("Host example.com\n  Hostname blubber\n"), 0600)

	ca := NewSSHConfigWithCache(confFile)

	c, err := ca.ConfigForHost("example.com")
	require.NoError(t, err)
	require.Equal(t, "blubber", c.Get("hostname"))

	require.NoError(t, os.Remove(confFile))
	c, err = ca.ConfigForHost("example.com")
	require.NoError(t, err)
	require.Equal(t, "blubber", c.Get("hostname"))
}

func Test_SSHConfig_ConfigForHostWithConfigFile(t *testing.T) {
	c, err := SSHConfig{ConfigFile: "testdata/ssh_config"}.ConfigForHost("example.com")
	require.NoError(t, err)
	require.Equal(t, "example.com", c.Get("hostname"))
	require.Equal(t, "2222", c.Get("port"))
	require.Equal(t, "user1", c.Get("user"))
	require.Equal(t, "~/.idglobal", c.Get("identityfile"))
	require.Equal(t, []string{"~/.idglobal", "~/.id1"}, c.GetAll("identityfile"))
	require.Equal(t, "yes", c.Get("batchmode"))
	require.Equal(t, "", c.Get("unknownkeyveryweirdkeyhopefullyneverinupstream"))
}

func Test_SSHConfig_ConfigForHost_NonExistingFile(t *testing.T) {
	_, err := SSHConfig{ConfigFile: t.TempDir() + "/non_existing_file"}.ConfigForHost("example.com")
	var expectedErr *exec.ExitError
	require.ErrorAs(t, err, &expectedErr)
}
