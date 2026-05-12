package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	kubeconfig "k8s.io/client-go/tools/clientcmd/api"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func init() {
	RootCmd.AddCommand(shellCmd)

	flag := shellCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be written by this command.")
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Run a shell with kubeconfig setup to use the proxy.",
	Long:  "Run a shell with kubeconfig setup to use the proxy. Works on the inventory downloaded by the `update` command, so it does not require access to the Lieutenant API.",
	Run:   runShell,
}

func runShell(cmd *cobra.Command, _ []string) {
	// Allows deferred functions to be run for cleanup.
	exitCode := 0
	defer func() { os.Exit(exitCode) }()

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

	tmpKubeconfig, err := writeKubeconfigToTempFile(kubeconfigFromClusters(clusters))
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

func kubeconfigFromClusters(clusters []lieutenant.Cluster) *kubeconfig.Config {
	kc := kubeconfig.NewConfig()
	currentContextSet := false
	for _, c := range clusters {
		api, _, _ := c.DynamicStringFact("openshiftApiURL")
		if api == "" {
			continue
		}
		clusterName := c.ID
		contextName := c.ID
		kc.Clusters[clusterName] = &kubeconfig.Cluster{
			Server: api,
		}
		kc.Contexts[contextName] = &kubeconfig.Context{
			Cluster: clusterName,
		}
		if !currentContextSet {
			kc.CurrentContext = contextName
			currentContextSet = true
		}
	}
	return kc
}

func writeKubeconfigToTempFile(kc *kubeconfig.Config) (string, error) {
	tmpFile, err := os.CreateTemp("", "kharon-shell-*.kubeconfig")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary kubeconfig file: %w", err)
	}
	// We only need the name, so we can close it immediately.
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close temporary kubeconfig file: %w", err)
	}
	tmpFileName := tmpFile.Name()
	if err := clientcmd.WriteToFile(*kc, tmpFileName); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig to temporary file: %w", err)
	}
	return tmpFileName, nil
}
