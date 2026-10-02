package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	kubelogin "github.com/int128/kubelogin/pkg/di"
	"github.com/int128/kubelogin/pkg/infrastructure/clock"
	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/spf13/cobra"

	browser "github.com/vshn/kharon/internal/pkg/browser/kubelogin"
)

func init() {
	RootCmd.AddCommand(kubeloginCmd)
}

var kubeloginCmd = &cobra.Command{
	Use:   "kubelogin [-h]",
	Short: "Runs a vendored version of the `kubelogin` tool.",
	Long:  "Runs a vendored version of the `kubelogin` tool.",
	Run:   runKubelogin,

	// DisableFlagParsing disables the default flag parsing behavior of Cobra, allowing the command to pass all flags and arguments to the underlying kubelogin command without interference.
	DisableFlagParsing: true,
}

func runKubelogin(cmd *cobra.Command, _ []string) {
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	embeddedCmd := kubelogin.NewCmdForHeadless(
		new(clock.Real),
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		logger.New(),
		new(browser.Browser),
	)

	os.Exit(embeddedCmd.Run(ctx, os.Args[1:], kubeloginVersion()))
}

func kubeloginVersion() string {
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/int128/kubelogin" {
				return fmt.Sprintf("kharon+%s@%s", dep.Path, dep.Version)
			}
		}
	}
	return "kharon+unknown"
}
