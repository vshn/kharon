package completion_test

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func Test_ClusterID(t *testing.T) {
	t.Run("Returns no suggestions when positional args are present and stopAfterFirst is set", func(t *testing.T) {
		inventoryFile := filepath.Join(t.TempDir(), "inventory.json")
		require.NoError(t, cache.WriteInventoryFile(inventoryFile, []lieutenant.Cluster{{ID: "c-test-1"}}))

		subject := completion.ClusterID(inventoryFile, true, nil)

		suggestions, directive := subject(nil, []string{"already-present"}, "c")
		assert.Len(t, suggestions, 0)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	})

	t.Run("Returns further suggestions when stopAfterFirst is not set", func(t *testing.T) {
		inventoryFile := filepath.Join(t.TempDir(), "inventory.json")
		require.NoError(t, cache.WriteInventoryFile(inventoryFile, []lieutenant.Cluster{{ID: "c-test-1"}}))

		subject := completion.ClusterID(inventoryFile, false, nil)

		suggestions, directive := subject(nil, []string{"already-present"}, "c")
		assert.Len(t, suggestions, 1)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	})

	t.Run("Returns sorted and filtered suggestions", func(t *testing.T) {
		inventoryFile := filepath.Join(t.TempDir(), "inventory.json")
		require.NoError(t, cache.WriteInventoryFile(inventoryFile, []lieutenant.Cluster{
			{ID: "c-gamma"},
			{ID: ""},
			{ID: "c-alpha"},
			{ID: "x-outside-prefix"},
			{ID: "c-beta"},
		}))

		subject := completion.ClusterID(inventoryFile, false, func(cluster lieutenant.Cluster) bool {
			return cluster.ID != "c-beta"
		})

		suggestions, directive := subject(nil, nil, "c-")
		assert.Equal(t, []string{"c-alpha", "c-gamma"}, suggestions)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	})

	t.Run("Returns error directive when inventory file cannot be read", func(t *testing.T) {
		subject := completion.ClusterID(filepath.Join(t.TempDir(), "missing.json"), false, nil)

		suggestions, directive := subject(nil, nil, "")
		assert.Len(t, suggestions, 0)
		assert.Equal(t, cobra.ShellCompDirectiveNoFileComp|cobra.ShellCompDirectiveError, directive)
	})
}
