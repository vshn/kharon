package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const kubeconfigCmdLongDesc = `Builds a kubeconfig file from the inventory set up to use the proxy.
Clusters added to the kubeconfig can be filtered by providing cluster IDs or wildcard patterns as arguments, or by using the fact-selector and dynamic-fact-selector flags to filter clusters based on their facts and dynamic facts.
If no filter is provided, the generated kubeconfig will contain all clusters from the inventory.
The current context is set to the first cluster in the kubeconfig.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const kubeconfigCmdExample = `# Write a kubeconfig to a file and set the KUBECONFIG environment variable to use it
kharon kubeconfig c-12345 > kubeconfig.yaml
export KUBECONFIG=kubeconfig.yaml

# Get a kubeconfig with the specified cluster as the current context
kharon kubeconfig c-12345`

var proxyAddr string

func init() {
	RootCmd.AddCommand(kubeconfigCmd)

	flag := kubeconfigCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
	flag.StringArrayVar(&clustersExcludePatterns, "exclude-cluster", nil, "Exclude clusters matching the given wildcard pattern. Can be specified multiple times to exclude multiple patterns.")
	flag.Func("fact-selector", "Label selector to filter clusters based on their facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersFactSelector))
	flag.Func("dynamic-fact-selector", "Label selector to filter clusters based on their dynamic facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersDynamicFactSelector))
	must(kubeconfigCmd.RegisterFlagCompletionFunc("exclude-cluster", completion.ClusterID(clustersInventoryFile, true, nil)))
}

var kubeconfigCmd = &cobra.Command{
	Use:     "kubeconfig [c-cluster-id | c-pattern-* ...]",
	Short:   "Builds a kubeconfig file from the inventory set up to use the proxy.",
	Long:    kubeconfigCmdLongDesc,
	Example: kubeconfigCmdExample,
	Run:     runKubeconfig,
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, false, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runKubeconfig(cmd *cobra.Command, args []string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	filteredClusters := lieutenant.Filter(clusters,
		args,
		clustersExcludePatterns,
		labels.Everything().Add(clustersFactSelector...),
		labels.Everything().Add(clustersDynamicFactSelector...),
		nil,
	)

	// Kubeconfig wants a socks5 url not socks5h, but they are treated the same by Go.
	if err := kubeconfig.Encode(kubeconfig.FromClusters(filteredClusters, proxyAddrForKubeconfig(proxyAddr), ""), os.Stdout); err != nil {
		slog.Error("Failed to encode kubeconfig", "error", err)
		os.Exit(1)
	}
}
