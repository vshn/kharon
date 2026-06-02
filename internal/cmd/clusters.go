package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

var clustersInventoryFile string
var clustersExcludePatterns []string
var clustersFactSelector labels.Requirements
var clustersDynamicFactSelector labels.Requirements
var clustersOutputFormat string

func init() {
	RootCmd.AddCommand(clustersCmd)

	flag := clustersCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringArrayVar(&clustersExcludePatterns, "exclude-cluster", nil, "Exclude clusters matching the given wildcard pattern. Can be specified multiple times to exclude multiple patterns.")
	flag.Func("fact-selector", "Label selector to filter clusters based on their facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersFactSelector))
	flag.Func("dynamic-fact-selector", "Label selector to filter clusters based on their dynamic facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersDynamicFactSelector))
	flag.VarP(&clustersOutputValue{val: &clustersOutputFormat}, "output", "o", "Output format. One of: table, json.")
	must(clustersCmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"table", "json"}, cobra.ShellCompDirectiveNoFileComp)))
	must(clustersCmd.RegisterFlagCompletionFunc("exclude-cluster", completion.ClusterID(clustersInventoryFile, true, nil)))
}

var clustersCmd = &cobra.Command{
	Use:   "clusters [c-cluster-id | c-pattern-* ...]",
	Short: "List clusters and their details.",
	Long:  "List clusters and their details. Works on the inventory downloaded by the `update` command, so it does not require access to the Lieutenant API.",
	RunE:  runClusters,
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, false, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runClusters(cmd *cobra.Command, args []string) error {
	if clustersInventoryFile == "" {
		return fmt.Errorf("inventory file path is required: inventory-file flag is empty and failed to determine default path")
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		return fmt.Errorf("failed to read inventory file. You might need to run the `update` command first: %w", err)
	}

	filteredClusters := lieutenant.Filter(clusters,
		args,
		clustersExcludePatterns,
		labels.Everything().Add(clustersFactSelector...),
		labels.Everything().Add(clustersDynamicFactSelector...),
		nil,
	)

	if clustersOutputFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Clusters []lieutenant.Cluster `json:"clusters"`
		}{
			Clusters: filteredClusters,
		})
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join([]string{"ID", "Display Name", "Jumphost", "Console URL"}, "\t"))
	for _, c := range filteredClusters {
		console, _, _ := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL)
		jumphost, _, _ := c.StringFact(lieutenant.KnownFactJumphost)
		_, _ = fmt.Fprintln(w, strings.Join([]string{c.ID, c.DisplayName, jumphost, console}, "\t"))
	}
	return w.Flush()
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

type clustersOutputValue struct {
	val *string
}

func (c *clustersOutputValue) String() string {
	if c.val == nil {
		return ""
	}
	return *c.val
}

func (c *clustersOutputValue) Set(s string) error {
	switch s {
	case "table", "json":
		*c.val = s
		return nil
	default:
		return fmt.Errorf("invalid output format: %s. Allowed values are: table, json", s)
	}
}

func (c *clustersOutputValue) Type() string {
	return "string"
}
