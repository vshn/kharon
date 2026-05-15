package cmd

import (
	"log/slog"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/vshn/kharon/internal/pkg/install"
)

const installCmdLongDesc = `TODO: Add long description for the install command.`

const installCmdExample = `# Install kharon
kharon install`

func init() {
	RootCmd.AddCommand(installCmd)

	flag := installCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
}

var installCmd = &cobra.Command{
	Use:     "install [c-cluster-id]",
	Short:   "Install kharon systemd/launchd services.",
	Long:    installCmdLongDesc,
	Example: installCmdExample,
	Run:     runInstall,
	Args:    cobra.ExactArgs(0),
}

func runInstall(cmd *cobra.Command, args []string) {
	switch runtime.GOOS {
	case "linux":
		if err := install.InstallSystemdService(); err != nil {
			slog.Error("Failed to install systemd service", "error", err)
			os.Exit(1)
		}
	case "darwin":
		if err := install.InstallLaunchdService(); err != nil {
			slog.Error("Failed to install launchd service", "error", err)
			os.Exit(1)
		}
	default:
		slog.Error("Unsupported operating system for installation, supported OS are Linux (with systemd) and MacOS", "os", runtime.GOOS)
		os.Exit(1)
	}
}
