package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/install"
)

const installCmdLongDesc = `Install kharon systemd or launchd services depending on the operating system.
The command will create the necessary service files to enable the kharon proxy as a background service.

The proxy will be installed as a user service (systemctl --user, launchctl gui/<uid>).
The proxy will be configured with on-demand activation and only be started when a connection to the proxy socket is made.`

const installCmdExample = `# Install kharon
kharon install`

func init() {
	RootCmd.AddCommand(installCmd)

	flag := installCmd.Flags()
	flag.StringVar(&proxyMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file. This file can be generated with the `update` subcommand. The installer tests if the file can be read and parsed correctly before proceeding.")
}

var installCmd = &cobra.Command{
	Use:     "install",
	Short:   "Install kharon systemd/launchd services.",
	Long:    installCmdLongDesc,
	Example: installCmdExample,
	Run:     runInstall,
	Args:    cobra.ExactArgs(0),
}

func runInstall(cmd *cobra.Command, args []string) {
	if _, err := cache.ReadProxyMappingFile(proxyMappingFile); err != nil {
		fmt.Printf("Failed to read the proxy mapping file %s.\n", color.MagentaString(proxyMappingFile))
		fmt.Printf("Please run %s before continuing.\n", color.CyanString("kharon update"))
		os.Exit(1)
	}

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
	install.ShellCompletionNotice()
}
