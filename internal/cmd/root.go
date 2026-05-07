package cmd

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "kharon",
	Short: "Kharon helps you access VSHN managed Kubernetes clusters.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cmd.SilenceUsage = true
		slog.SetLogLoggerLevel(slog.Level(verbosity))
	},
}

var verbosity int

func init() {
	flag := RootCmd.PersistentFlags()
	flag.IntVarP(&verbosity, "verbosity", "v", 0, "Verbosity level for logging. Lower values produce more detailed logs. Default is 0 (info). See https://pkg.go.dev/log/slog#Level for thresholds.")
}

func Execute() {
	RootCmd.ExecuteContext(context.Background())
}
