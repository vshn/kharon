package cmd

import (
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const switchCmdLongDesc = `Switches the context to the given cluster in the current kubeconfig file.
Inspired by kubectx but backed by the Lieutenant inventory.
Either a Lieutenant cluster ID or an API URL can be given.
The given cluster must exist in the Lieutenant inventory.

When given a dash (-) as the argument the command restores the last context overridden by kharon.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const switchCmdExample = `# Switch the kubeconfig context to the given cluster
kharon switch c-12345

# Switch back to the last used cluster
kharon switch -`

func init() {
	RootCmd.AddCommand(switchCmd)

	flag := switchCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use when inserting into the kubeconfig file.")
}

var switchCmd = &cobra.Command{
	Use:     "switch [- | c-cluster-id | https://api.example.com:6443]",
	Short:   "Switches the context to the given cluster in the current kubeconfig file.",
	Long:    switchCmdLongDesc,
	Example: switchCmdExample,
	Run:     runSwitch,
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, false, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.ApiURL()
		return api != ""
	}),
}

func runSwitch(cmd *cobra.Command, args []string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	clusterIDOrURL := args[0]
	var cluster lieutenant.Cluster
	if clusterIDOrURL == "-" {
		if err := kubeconfig.RestoreLastContext(); err != nil {
			slog.Error("Failed to restore context", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	} else if strings.HasPrefix(clusterIDOrURL, "http://") || strings.HasPrefix(clusterIDOrURL, "https://") {
		c, ok := lieutenant.FindByAPIURL(clusters, clusterIDOrURL)
		if !ok {
			slog.Error("Could not find cluster with given API url", "api_url", clusterIDOrURL)
			os.Exit(1)
		}
		cluster = c
	} else {
		c, ok := lieutenant.FindByID(clusters, clusterIDOrURL)
		if !ok {
			slog.Error("Could not find cluster with given cluster ID", "cluster_id", clusterIDOrURL)
			os.Exit(1)
		}
		cluster = c
	}

	if err := kubeconfig.InsertClusterConnectionInfo(proxyAddrForKubeconfig(proxyAddr), cluster); err != nil {
		slog.Error("Failed to insert connection details", "error", err)
		os.Exit(1)
	}
}
