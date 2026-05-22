package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/browser"
	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func init() {
	RootCmd.AddCommand(consoleCmd)

	flag := consoleCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
}

const consoleCmdLongDesc = `Open the web console for supported clusters in the default browser.
Currently, only OpenShift clusters with a known console URL are supported.

The command to open the console can be overridden by setting the KHARON_BROWSER or BROWSER environment variables.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const consoleCmdExample = `# Open the console for the current cluster
kharon console

# Open the console for a specific cluster
kharon console c-12345

# Open the cluster console in the non-default browser (e.g. Firefox) on macOS
BROWSER="open -a firefox" kharon console c-12345`

var consoleCmd = &cobra.Command{
	Use:     "console [c-cluster-id]",
	Short:   "Open the web console for supported clusters.",
	Long:    consoleCmdLongDesc,
	Example: consoleCmdExample,
	Run:     runConsole,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL)
		return api != ""
	}),
}

func runConsole(cmd *cobra.Command, args []string) {
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

	var cluster lieutenant.Cluster
	if clusterID != "" {
		c, found := lieutenant.FindByID(clusters, clusterID)
		if !found {
			slog.Error("Cluster not found", "cluster_id", clusterID)
			os.Exit(1)
		}
		cluster = c
	} else {
		kcc, err := kubeconfig.CurrentClusterConfig()
		if err != nil {
			slog.Error("Failed to get current cluster config from kubeconfig", "error", err)
			os.Exit(1)
		}
		c, found := lieutenant.FindByAPIURL(clusters, kcc.Server)
		if !found {
			slog.Error("No cluster found in inventory with API URL matching current kubeconfig context", "api_url", kcc.Server)
			os.Exit(1)
		}
		cluster = c
	}

	consoleURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL)
	if consoleURL == "" {
		slog.Error("No console URL found for the specified cluster", "cluster_id", clusterID)
		os.Exit(1)
	}
	if err := browser.OpenURL(cmd.Context(), consoleURL); err != nil {
		slog.Error("Failed to open browser", "error", err)
		os.Exit(1)
	}
}
