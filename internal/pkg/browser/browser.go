package browser

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/google/shlex"
)

// Stdout is the io.Writer to which executed commands write standard output.
var Stdout io.Writer = os.Stdout

// Stderr is the io.Writer to which executed commands write standard error.
var Stderr io.Writer = os.Stderr

// Browser is a struct that provides methods to open URLs in the default web browser of the user.
// It is initialized with default values for Stdout and Stderr on first use, which can be overridden if needed.
type Browser struct {
	Stdout io.Writer
	Stderr io.Writer
}

// OpenURL calls [Browser.OpenURL] with a new, default Browser.
func OpenURL(ctx context.Context, url string) error {
	return new(Browser).OpenURL(ctx, url)
}

// OpenURL opens the specified URL in the default web browser of the user.
// The provided context is used to interrupt the process (by calling cmd.Cancel or os.Process.Kill) if the context becomes done before the command completes on its own.
// The function first checks the KHARON_BROWSER environment variable, then BROWSER, and if neither is set, it looks for the default browser executable in the system's PATH.
func (b *Browser) OpenURL(ctx context.Context, url string) error {
	if b.Stdout == nil {
		b.Stdout = Stdout
	}
	if b.Stderr == nil {
		b.Stderr = Stderr
	}

	e := os.Getenv("KHARON_BROWSER")
	if e == "" {
		e = os.Getenv("BROWSER")
	}
	if e != "" {
		return b.parseAndRunCmd(ctx, e, url)
	}

	exec, err := executable()
	if err != nil {
		return err
	}
	return b.runCmd(ctx, exec, url)
}

func (b *Browser) parseAndRunCmd(ctx context.Context, cmdStr string, url string) error {
	args, err := shlex.Split(cmdStr)
	if err != nil {
		return fmt.Errorf("failed to parse command string: %w", err)
	}
	return b.runCmd(ctx, args[0], append(args[1:], url)...)
}

func (b *Browser) runCmd(ctx context.Context, prog string, args ...string) error {
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Stdout = b.Stdout
	cmd.Stderr = b.Stderr
	return cmd.Run()
}
