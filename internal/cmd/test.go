package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/conntest"
	"github.com/vshn/kharon/internal/pkg/proxy"
)

func init() {
	RootCmd.AddCommand(testCmd)

	flag := testCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file. This file can be generated with the `update` subcommand.")
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test cluster connections.",
	Long:  "TODO Test cluster connections.",
	Run:   runTest,
}

func runTest(cmd *cobra.Command, _ []string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}
	if proxyMappingFile == "" {
		slog.Error("Mapping file path is required", "error", "mapping-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	dialer, err := proxy.NewRoutingDialer(nil, net.Dialer{}, 0, proxyMappingFile)
	if err != nil {
		slog.Error("Failed to create routing dialer", "error", err)
		os.Exit(1)
	}
	defer dialer.Close()
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
		Timeout: 5 * time.Second,
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	for report := range conntest.TestClusters(httpClient, clusters) {
		fmt.Printf("Cluster: %s\n", report.ClusterName)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(w, joinTabbed(errToStatus(report.APIServerConnectionErr), "API Server", report.APIServerURL, errMsg(report.APIServerConnectionErr)))
		fmt.Fprintln(w, joinTabbed(errToStatus(report.ConsoleConnectionErr), "Console", report.ConsoleURL, errMsg(report.ConsoleConnectionErr)))
		fmt.Fprintln(w, joinTabbed(errToStatus(report.OAuthConnectionErr), "OAuth", report.OAuthURL, errMsg(report.OAuthConnectionErr)))
		w.Flush()
		fmt.Println()
	}
}

func joinTabbed(cols ...string) string {
	return strings.Join(cols, "\t")
}

func errToStatus(err error) string {
	if err == nil {
		return "✅"
	}
	return "❌"
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
