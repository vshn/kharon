package completion

import (
	"log/slog"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

// ClusterID returns a cobra.CompletionFunc that provides cluster IDs from the inventory file as suggestions.
// The suggestions are filtered by the provided filter function and the current input prefix.
func ClusterID(clustersInventoryFile string, stopAfterFirst bool, filter func(lieutenant.Cluster) bool) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, cur string) ([]string, cobra.ShellCompDirective) {
		if stopAfterFirst && len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
		if err != nil {
			slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
			return nil, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveError
		}

		suggestions := make([]string, 0, len(clusters))
		for _, cluster := range clusters {
			if cluster.ID == "" {
				continue
			}
			if filter != nil && !filter(cluster) {
				continue
			}
			if cur == "" || strings.HasPrefix(cluster.ID, cur) {
				suggestions = append(suggestions, cluster.ID)
			}
		}
		slices.Sort(suggestions)

		return suggestions, cobra.ShellCompDirectiveNoFileComp
	}
}
