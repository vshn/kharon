package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

var clustersInventoryFile string

func init() {
	RootCmd.AddCommand(clustersCmd)

	flag := clustersCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be written by this command.")
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

	var clusters []lieutenant.Cluster
	f, err := os.Open(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to open inventory file", "file", clustersInventoryFile, "error", err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()
	if err := json.NewDecoder(f).Decode(&clusters); err != nil {
		slog.Error("Failed to decode inventory file", "file", clustersInventoryFile, "error", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join([]string{"ID", "Display Name", "Jumphost", "Console URL"}, "\t"))
	for _, c := range clusters {
		console, _, _ := c.DynamicStringFact("openshiftConsoleURL")
		jumphost, _, _ := c.StringFact("jumphost")
		_, _ = fmt.Fprintln(w, strings.Join([]string{c.ID, c.DisplayName, jumphost, console}, "\t"))
	}
	_ = w.Flush()
}
