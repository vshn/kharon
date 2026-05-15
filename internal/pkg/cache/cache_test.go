package cache

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"github.com/vshn/kharon/internal/pkg/proxy/mapping"
)

func Test_CacheDir(t *testing.T) {
	tempDir := mockUserCacheDir(t)

	cacheDir, err := CacheDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tempDir, label), cacheDir)
}

func Test_InventoryFilePath(t *testing.T) {
	tempDir := mockUserCacheDir(t)

	inventoryFilePath, err := InventoryFilePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tempDir, label, "inventory.json"), inventoryFilePath)
}

func Test_WriteAndReadInventoryFile(t *testing.T) {
	mockUserCacheDir(t)

	clusters := []lieutenant.Cluster{
		{
			ID: "cluster-1",
		},
		{
			ID: "cluster-2",
		},
	}

	require.NoError(t, WriteInventoryFile("", clusters))

	readClusters, err := ReadInventoryFile("")
	require.NoError(t, err)
	require.Equal(t, clusters, readClusters)
}

func Test_ReadInventoryFile_VersionMismatch(t *testing.T) {
	tmpFile := t.TempDir() + "/inventory.json"
	require.NoError(t, writeJSONToFile(inventoryFile{
		Version: inventoryFileVersion + 1,
	}, tmpFile))

	_, err := ReadInventoryFile(tmpFile)
	require.ErrorContains(t, err, "inventory file version 2 does not match expected version 1")
}

func Test_ProxyMappingFilePath(t *testing.T) {
	tempDir := mockUserCacheDir(t)

	proxyMappingFilePath, err := ProxyMappingFilePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tempDir, label, "proxy", "domain_jumphost_mapping.json"), proxyMappingFilePath)
}

func Test_WriteAndReadProxyMappingFile(t *testing.T) {
	mockUserCacheDir(t)

	proxyMappings := mapping.JumphostMapping{
		DomainToJumphost: map[string]string{
			"cluster-1": "jumphost-1",
			"cluster-2": "jumphost-2",
		},
		DirectAccessDomains: []string{"cluster-3", "cluster-4"},
	}

	require.NoError(t, WriteProxyMappingFile("", proxyMappings))

	readProxyMappings, err := ReadProxyMappingFile("")
	require.NoError(t, err)
	require.Equal(t, proxyMappings, readProxyMappings)
}

func Test_ProxyMappingFile_VersionMismatch(t *testing.T) {
	tmpFile := t.TempDir() + "/proxy_mapping.json"
	require.NoError(t, writeJSONToFile(proxyMappingFile{
		Version: proxyMappingFileVersion + 1,
	}, tmpFile))

	_, err := ReadProxyMappingFile(tmpFile)
	assert.ErrorContains(t, err, "proxy file version")
	assert.ErrorContains(t, err, "does not match expected version")
}

func mockUserCacheDir(t *testing.T) string {
	originalFunc := userCacheDirFunc
	tempDir := t.TempDir()
	userCacheDirFunc = func() (string, error) {
		return tempDir, nil
	}
	t.Cleanup(func() {
		userCacheDirFunc = originalFunc
	})
	return tempDir
}
