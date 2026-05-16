package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/minio/pkg/v3/wildcard"
	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/conntest"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"github.com/vshn/kharon/internal/pkg/proxy"
)

var testExcludesClusters []string

func init() {
	RootCmd.AddCommand(testCmd)

	flag := testCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file. This file can be generated with the `update` subcommand.")
	flag.StringArrayVar(&testExcludesClusters, "exclude-cluster", []string{}, "Exclude clusters matching the pattern (supports wildcards, e.g. `--exclude-cluster=c-dev-*` to exclude all clusters starting with `c-dev-`).")
	testCmd.RegisterFlagCompletionFunc("exclude-cluster", completion.ClusterID(clustersInventoryFile, nil))
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

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}
	if len(testExcludesClusters) > 0 {
		filtered := make([]lieutenant.Cluster, 0, len(clusters))
		for _, cluster := range clusters {
			exclude := false
			for _, pattern := range testExcludesClusters {
				if wildcard.Match(pattern, cluster.ID) {
					exclude = true
					break
				}
			}
			if !exclude {
				filtered = append(filtered, cluster)
			}
		}
		clusters = filtered
	}

	var hasErrors bool
	for report := range conntest.TestClusters(dialer, clusters) {
		hasErrors = hasErrors || report.HasErrors()
		var jumphostInfo string
		if report.Jumphost != "" {
			jumphostInfo = color.MagentaString(fmt.Sprintf(" (%s)", report.Jumphost))
		}
		bold := color.New(color.Bold)
		fmt.Printf("%s%s\n", bold.Sprint(report.ClusterName), jumphostInfo)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(w, joinTabbed(errToStatus(report.APIServerConnectionErr), "API Server", report.APIServerURL, errMsg(report.APIServerConnectionErr)))
		fmt.Fprintln(w, joinTabbed(errToStatus(report.ConsoleConnectionErr), "Console", report.ConsoleURL, errMsg(report.ConsoleConnectionErr)))
		fmt.Fprintln(w, joinTabbed(errToStatus(report.OAuthConnectionErr), "OAuth", report.OAuthURL, errMsg(report.OAuthConnectionErr)))
		w.Flush()
		fmt.Println()
		if len(report.Warnings) > 0 {
			for _, warning := range report.Warnings {
				fmt.Printf("⚠️  %s\n", color.YellowString(warning))
			}
			fmt.Println()
		}
	}
	if hasErrors {
		fmt.Println(color.RedString("Some connections could not be established. Please check the error messages above."))
		fmt.Printf("Run %s and check the %s https://vshnwiki.atlassian.net/wiki/x/I4GbLQ.\n", color.CyanString("kharon update; sshop_update"), color.YellowString("known weird jumphosts"))
		fmt.Printf("You can exclude clusters using the %s flag.\n", color.CyanString("--exclude-cluster=<pattern>"))
		os.Exit(7)
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
