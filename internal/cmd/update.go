package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

var updateMappingFile, updateInventoryFile string
var lieutenantAPIURL string

func init() {
	RootCmd.AddCommand(updateCmd)

	flag := updateCmd.Flags()
	flag.StringVar(&updateMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file that should be written by this command.")
	flag.StringVar(&updateInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be written by this command.")
	flag.StringVar(&lieutenantAPIURL, "lieutenant-url", lieutenantURLFromEnv(), "URL of the Lieutenant API.")
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the proxy configuration.",
	Long:  "Update the proxy configuration by loading the latest domain to jumphost mapping file from Lieutenant.",
	Run:   runUpdate,
}

func runUpdate(cmd *cobra.Command, _ []string) {
	if updateMappingFile == "" {
		slog.Error("Mapping file path is required", "error", "mapping-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	if lieutenantAPIURL == "" {
		slog.Error("Neither --lieutenant-url flag nor LIEUTENANT_URL or COMMODORE_API_URL environment variables are set. One of these is required to determine the Lieutenant API URL.")
		os.Exit(1)
	}

	clusters, err := lieutenant.NewClient(lieutenantAPIURL, nil).GetClusters(cmd.Context())
	if err != nil {
		slog.Error("Failed to get clusters", "error", err)
		os.Exit(1)
	}

	if err := cache.WriteInventoryFile(updateInventoryFile, clusters); err != nil {
		slog.Error("Failed to write inventory file", "error", err)
		os.Exit(1)
	}
	slog.Info("Wrote cluster inventory to file.", "file", updateInventoryFile)
	mapping, err := lieutenant.JumphostMappingFromClusters(clusters)
	if err != nil {
		slog.Warn("Jumphost mapping may be incomplete", "error", err)
	}
	if err := cache.WriteProxyMappingFile(updateMappingFile, mapping); err != nil {
		slog.Error("Failed to write proxy mapping file", "error", err)
		os.Exit(1)
	}
	slog.Info("Wrote domain to jumphost mapping to file.", "file", updateMappingFile)
}

func lieutenantURLFromEnv() string {
	apiURL := os.Getenv("LIEUTENANT_URL")
	if apiURL == "" {
		apiURL = os.Getenv("COMMODORE_API_URL")
	}
	return apiURL
}

func inventoryFilePath() string {
	cd, err := cache.InventoryFilePath()
	if err != nil {
		slog.Warn("Failed to get inventory file path", slog.Any("error", err))
		return ""
	}
	return cd
}
