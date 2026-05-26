package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const kubeconfigCmdLongDesc = `Builds a kubeconfig file from the inventory set up to use the proxy.
The generated kubeconfig contains all clusters from the inventory with an OpenShift API URL.
The kubeconfig context can be set to a specific cluster by providing the cluster ID as the first argument.
If no argument is provided, the context is set to the first found cluster with a valid OpenShift API URL.

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
}

var kubeconfigCmd = &cobra.Command{
	Use:     "kubeconfig [c-cluster-id]",
	Short:   "Builds a kubeconfig file from the inventory set up to use the proxy.",
	Long:    kubeconfigCmdLongDesc,
	Example: kubeconfigCmdExample,
	Run:     runKubeconfig,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runKubeconfig(cmd *cobra.Command, args []string) {
	var clusterID string
	if len(args) > 0 {
		clusterID = args[0]
	}

	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	// Kubeconfig wants a socks5 url not socks5h, but they are treated the same by Go.
	if err := kubeconfig.Encode(kubeconfig.FromClusters(clusters, proxyAddrForKubeconfig(proxyAddr), clusterID), os.Stdout); err != nil {
		slog.Error("Failed to encode kubeconfig", "error", err)
		os.Exit(1)
	}
}
