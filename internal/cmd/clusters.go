package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

var clustersInventoryFile string

func init() {
	RootCmd.AddCommand(clustersCmd)

	flag := clustersCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
}

var clustersCmd = &cobra.Command{
	Use:   "clusters",
	Short: "List clusters and their details.",
	Long:  "List clusters and their details. Works on the inventory downloaded by the `update` command, so it does not require access to the Lieutenant API.",
	Run:   runClusters,
}

func runClusters(cmd *cobra.Command, _ []string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join([]string{"ID", "Display Name", "Jumphost", "Console URL"}, "\t"))
	for _, c := range clusters {
		console, _, _ := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL)
		jumphost, _, _ := c.StringFact(lieutenant.KnownFactJumphost)
		_, _ = fmt.Fprintln(w, strings.Join([]string{c.ID, c.DisplayName, jumphost, console}, "\t"))
	}
	_ = w.Flush()
}
