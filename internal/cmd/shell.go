package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const shellCmdLongDesc = `Run a shell with a kubeconfig generated from the inventory, set up to use the proxy.
The generated kubeconfig contains all clusters from the inventory with an OpenShift API URL.
The kubeconfig context can be set to a specific cluster by providing the cluster ID as the first argument.
If no argument is provided, the context is set to the first found cluster with a valid OpenShift API URL.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const shellCmdExample = `# Get a shell
kharon shell

# Get a shell for a specific cluster
kharon shell c-12345`

func init() {
	RootCmd.AddCommand(shellCmd)

	flag := shellCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
}

var shellCmd = &cobra.Command{
	Use:     "shell [c-cluster-id]",
	Short:   "Run a shell with a kubeconfig generated from the inventory, set up to use the proxy.",
	Long:    shellCmdLongDesc,
	Example: shellCmdExample,
	Run:     runShell,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runShell(cmd *cobra.Command, args []string) {
	// Allows deferred functions to be run for cleanup.
	exitCode := 0
	defer func() { os.Exit(exitCode) }()

	var clusterID string
	if len(args) > 0 {
		clusterID = args[0]
	}

	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		exitCode = 1
		return
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		slog.Error("SHELL environment variable is not set")
		exitCode = 1
		return
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		exitCode = 1
		return
	}

	tmpKubeconfig, err := writeKubeconfigToTempFile(kubeconfig.FromClusters(clusters, clusterID))
	if err != nil {
		slog.Error("Failed to write kubeconfig to temporary file", "error", err)
		exitCode = 1
		return
	}
	defer func() {
		if err := os.Remove(tmpKubeconfig); err != nil {
			slog.Warn("Failed to remove temporary kubeconfig file", "file", tmpKubeconfig, "error", err)
		}
	}()

	ex := exec.Command(shell)
	ex.Env = append(os.Environ(), "KHARON_SHELL=1", fmt.Sprintf("KUBECONFIG=%s", tmpKubeconfig))
	for _, ev := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		ex.Env = append(ex.Env, fmt.Sprintf("%s=socks5h://localhost:12000", ev))
	}
	ex.Stdin = os.Stdin
	ex.Stdout = os.Stdout
	ex.Stderr = os.Stderr
	if err := ex.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			exitCode = exitErr.ExitCode()
			return
		}
		slog.Error("Failed to run shell", "error", err)
		exitCode = 1
		return
	}
}

func writeKubeconfigToTempFile(kc *kubeconfig.Config) (string, error) {
	tmpFile, err := os.CreateTemp("", "kharon-shell-*.kubeconfig")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary kubeconfig file: %w", err)
	}
	defer func() { _ = tmpFile.Close() }()
	if err := kubeconfig.Encode(kc, tmpFile); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig to temporary file: %w", err)
	}
	return tmpFile.Name(), nil
}
