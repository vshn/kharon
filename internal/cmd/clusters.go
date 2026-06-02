package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

var clustersInventoryFile string
var clustersExcludePatterns []string
var clustersFactSelector labels.Requirements
var clustersDynamicFactSelector labels.Requirements

func init() {
	RootCmd.AddCommand(clustersCmd)

	flag := clustersCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringArrayVar(&clustersExcludePatterns, "exclude-cluster", nil, "Exclude clusters matching the given wildcard pattern. Can be specified multiple times to exclude multiple patterns.")
	flag.Func("fact-selector", "Label selector to filter clusters based on their facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersFactSelector))
	flag.Func("dynamic-fact-selector", "Label selector to filter clusters based on their dynamic facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersDynamicFactSelector))
}

var clustersCmd = &cobra.Command{
	Use:   "clusters [c-cluster-id | c-pattern-*]",
	Short: "List clusters and their details.",
	Long:  "List clusters and their details. Works on the inventory downloaded by the `update` command, so it does not require access to the Lieutenant API.",
	Run:   runClusters,
}

func runClusters(cmd *cobra.Command, args []string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	var includePattern []string
	if len(args) > 0 {
		includePattern = []string{args[0]}
	}

	filteredClusters := lieutenant.Filter(clusters,
		includePattern,
		clustersExcludePatterns,
		labels.Everything().Add(clustersFactSelector...),
		labels.Everything().Add(clustersDynamicFactSelector...),
		nil,
	)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join([]string{"ID", "Display Name", "Jumphost", "Console URL"}, "\t"))
	for _, c := range filteredClusters {
		console, _, _ := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL)
		jumphost, _, _ := c.StringFact(lieutenant.KnownFactJumphost)
		_, _ = fmt.Fprintln(w, strings.Join([]string{c.ID, c.DisplayName, jumphost, console}, "\t"))
	}
	_ = w.Flush()
}

func selectorFlagFunc(v *labels.Requirements) func(string) error {
	return func(s string) error {
		reqs, err := labels.ParseToRequirements(s)
		if err != nil {
			return fmt.Errorf("failed to parse fact selector: %w", err)
		}
		*v = append(*v, reqs...)
		return nil
	}
}
