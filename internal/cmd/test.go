package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/conntest"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"github.com/vshn/kharon/internal/pkg/proxy"
)

const testCmdLongDesc = `Test cluster connections to all clusters in the inventory, optionally filtered by a pattern.
The pattern can include wildcards, e.g. ` + "`c-prod-*`" + ` to match all clusters starting with ` + "`c-dev-`" + `.
` + "`--exclude-cluster=c-dev-*`" + ` can be used to exclude clusters matching a pattern.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const testCmdExample = `# Test all known clusters
kharon test

# Test clusters starting with c-prod-
kharon test 'c-prod-*'

# Exclude all patterns ending with -poc? or -dev?
kharon test --exclude-cluster='*-poc?' --exclude-cluster='*-dev?'`

func init() {
	RootCmd.AddCommand(testCmd)

	flag := testCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file. This file can be generated with the `update` subcommand.")
	flag.StringArrayVar(&clustersExcludePatterns, "exclude-cluster", nil, "Exclude clusters matching the given wildcard pattern. Can be specified multiple times to exclude multiple patterns.")
	flag.Func("fact-selector", "Label selector to filter clusters based on their facts. Example: 'distribution=openshift4,release_channel=fast'", selectorFlagFunc(&clustersFactSelector))
	flag.Func("dynamic-fact-selector", "Label selector to filter clusters based on their dynamic facts. Example: 'openshiftBaseDomain in (cloudscale-lpg-2.appuio.cloud,exoscale-ch-gva-2-0.appuio.cloud)'", selectorFlagFunc(&clustersDynamicFactSelector))
	must(testCmd.RegisterFlagCompletionFunc("exclude-cluster", completion.ClusterID(clustersInventoryFile, true, nil)))
}

var testCmd = &cobra.Command{
	Use:     "test [flags] [c-pattern-* ...] [--exclude-cluster=pattern]",
	Short:   "Test cluster connections.",
	Long:    testCmdLongDesc,
	Example: testCmdExample,
	Run:     runTest,
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, false, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runTest(cmd *cobra.Command, args []string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}
	if proxyMappingFile == "" {
		slog.Error("Mapping file path is required", "error", "mapping-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	dialer, err := proxy.NewRoutingDialer("", net.Dialer{}, 0, proxyMappingFile)
	if err != nil {
		slog.Error("Failed to create routing dialer", "error", err)
		os.Exit(1)
	}
	defer func() { _ = dialer.Close() }()

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

	bold := color.New(color.Bold)

	var hasErrors bool
	for report := range conntest.TestClusters(dialer, filteredClusters) {
		if report.Skipped() {
			fmt.Printf("%s\nSKIPPED  %s\n\n", bold.Sprint(report.ClusterName), report.SkippedReason)
			continue
		}
		hasErrors = hasErrors || report.HasErrors()
		var jumphostInfo string
		if report.Jumphost != "" {
			jumphostInfo = color.MagentaString(fmt.Sprintf(" (%s)", report.Jumphost))
		}
		fmt.Printf("%s%s\n", bold.Sprint(report.ClusterName), jumphostInfo)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		_, _ = fmt.Fprintln(w, joinTabbed(errToStatus(report.APIServerConnectionErr), "API Server", report.APIServerURL, errMsg(report.APIServerConnectionErr)))
		_, _ = fmt.Fprintln(w, joinTabbed(errToStatus(report.ConsoleConnectionErr), "Console", report.ConsoleURL, errMsg(report.ConsoleConnectionErr)))
		_, _ = fmt.Fprintln(w, joinTabbed(errToStatus(report.OAuthConnectionErr), "OAuth", report.OAuthURL, errMsg(report.OAuthConnectionErr)))
		_ = w.Flush()
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
		fmt.Println()
		fmt.Printf("Run %s and check the %s.\n", color.CyanString("kharon update; sshop_update"), color.YellowString("known weird jumphosts https://vshnwiki.atlassian.net/wiki/x/I4GbLQ"))
		fmt.Println()
		fmt.Printf("Check if you can reach the jumphost non-interactively using %s and the %s shown in the output above.\n", color.CyanString("ssh -o BatchMode=yes JUMPHOST -- hostname"), color.MagentaString("jumphost"))
		fmt.Printf("If the failing jumphost is listed as a known weird jumphost, you might need to update the SSH configuration, upload your public key, or add the trust the host key.\n")
		fmt.Println()
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

func must(err error) {
	if err != nil {
		panic(err)
	}
}
