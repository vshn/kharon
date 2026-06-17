package completion

import (
	"log/slog"
	"slices"
	"strings"
	"unicode/utf8"

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

		return suggestClusterIDs(clusters, cur, filter), cobra.ShellCompDirectiveNoFileComp
	}
}

func suggestClusterIDs(clusters []lieutenant.Cluster, cur string, filter func(lieutenant.Cluster) bool) []string {
	type rankedSuggestion struct {
		suggestion string
		distance   int
	}

	suggestions := make([]rankedSuggestion, 0, len(clusters))
	for _, cluster := range clusters {
		if cluster.ID == "" {
			continue
		}
		if filter != nil && !filter(cluster) {
			continue
		}

		if !match(cluster.ID, cur) && !match(strings.ToLower(cur), strings.ToLower(cluster.DisplayName)) {
			continue
		}

		idDistance := levenshteinDistance(cur, cluster.ID)
		displayNameDistance := 100 * levenshteinDistance(strings.ToLower(cur), strings.ToLower(cluster.DisplayName))
		suggestions = append(suggestions, rankedSuggestion{suggestion: cluster.ID, distance: idDistance + displayNameDistance})
	}

	slices.SortFunc(suggestions, func(a, b rankedSuggestion) int {
		return 10*(a.distance-b.distance) + strings.Compare(a.suggestion, b.suggestion)
	})

	result := make([]string, len(suggestions))
	for i, s := range suggestions {
		result[i] = s.suggestion
	}
	return result
}

func match(source, target string) bool {
	if source == target {
		return true
	}
	if len(target)-len(source) < 0 {
		return false
	}

outer:
	for _, r1 := range source {
		for i, r2 := range target {
			if r1 == r2 {
				target = target[i+utf8.RuneLen(r2):]
				continue outer
			}
		}
		return false
	}

	return true
}

func levenshteinDistance(s, t string) int {
	r1, r2 := []rune(s), []rune(t)
	column := make([]int, len(r1)+1)

	for j := range column {
		column[j] = j
	}

	for x := 1; x <= len(r2); x++ {
		column[0] = x

		for y, lastDiag := 1, x-1; y <= len(r1); y++ {
			oldDiag := column[y]
			cost := 0
			if r1[y-1] != r2[x-1] {
				cost = 1
			}
			column[y] = min(column[y]+1, column[y-1]+1, lastDiag+cost)
			lastDiag = oldDiag
		}
	}

	return column[len(r1)]
}
