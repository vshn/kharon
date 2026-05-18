package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var fullVersionInfo bool

func init() {
	RootCmd.AddCommand(versionCmd)

	flag := versionCmd.Flags()
	flag.BoolVar(&fullVersionInfo, "full", false, "Display full version information")
}

const versionCmdLongDesc = `Display version information.

Use the --full flag to display detailed build information, including module dependencies and build settings.
The full output matches the output of 'go version -m <executable>'.`

var versionCmd = &cobra.Command{
	Use:   "version [--full]",
	Short: "Display version information.",
	Long:  versionCmdLongDesc,
	Run:   runVersion,
	Args:  cobra.ExactArgs(0),
}

func runVersion(cmd *cobra.Command, args []string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		slog.Error("Failed to read build info")
		os.Exit(1)
	}
	if fullVersionInfo {
		fmt.Println(info)
	} else {
		fmt.Println(info.Main.Path, info.Main.Version, info.GoVersion, runtime.GOOS, runtime.GOARCH)
	}
}
