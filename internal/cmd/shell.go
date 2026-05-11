package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"k8s.io/client-go/tools/clientcmd"
	kubeconfig "k8s.io/client-go/tools/clientcmd/api"
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
	tmpFile, err := os.CreateTemp("", "kharon-shell-*.kubeconfig")
	if err != nil {
		slog.Error("Failed to create temporary kubeconfig file", "error", err)
		os.Exit(1)
	}
	_ = f.Close() // We only need the name, so we can close it immediately.
	tmpFileName := tmpFile.Name()
	defer func() { _ = os.Remove(tmpFileName) }()
	if err := clientcmd.WriteToFile(*kc, tmpFileName); err != nil {
		slog.Error("Failed to write kubeconfig", "error", err)
		os.Exit(1)
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		slog.Error("SHELL environment variable is not set")
		os.Exit(1)
	}
	ex := exec.Command(shell)
	ex.Env = append(os.Environ(), "KUBECONFIG="+tmpFileName, "KHARON_SHELL=1")
	for _, ev := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		ex.Env = append(ex.Env, fmt.Sprintf("%s=socks5h://localhost:12000", ev))
	}
	ex.Stdin = os.Stdin
	ex.Stdout = os.Stdout
	ex.Stderr = os.Stderr
	if err := ex.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exitErr.ExitCode())
		}
		slog.Error("Failed to run shell", "error", err)
		os.Exit(1)
	}
}
