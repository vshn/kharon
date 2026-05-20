package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "kharon",
	Short: "Kharon helps you access VSHN managed Kubernetes clusters.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		slog.SetLogLoggerLevel(slog.Level(verbosity))
	},
}

var verbosity int

func init() {
	flag := RootCmd.PersistentFlags()
	flag.IntVarP(&verbosity, "verbosity", "v", 0, "Verbosity level for logging. Lower values produce more detailed logs. Default is 0 (info). See https://pkg.go.dev/log/slog#Level for thresholds.")
}

func Execute() {
	if err := RootCmd.ExecuteContext(context.Background()); err != nil {
		_, _ = fmt.Fprintln(RootCmd.ErrOrStderr(), "Error:", err)
		if exerr, ok := errors.AsType[*ErrWithExitCode](err); ok {
			os.Exit(exerr.ExitCode)
		}
		os.Exit(1)
	}
}

type ErrWithExitCode struct {
	error

	ExitCode int
}

func (e *ErrWithExitCode) Unwrap() error {
	if e.error == nil {
		return nil
	}
	return e.error
}

func (e *ErrWithExitCode) Error() string {
	if e.error == nil {
		return ""
	}
	return e.error.Error()
}
