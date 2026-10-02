package kubelogin

import (
	"context"
	"os"
	"os/exec"

	"github.com/vshn/kharon/internal/pkg/browser"
)

// Browser is a thin shim to adapt kharons browser package to the kubelogin Browser interface.
type Browser struct{}

// Open opens the default browser.
func (*Browser) Open(url string) error {
	// In credential plugin mode, some browser launcher writes a message to stdout
	// and it may break the credential json for client-go.
	// This prevents the browser launcher from breaking the credential json.
	return new(browser.Browser{
		Stdout: os.Stderr,
		Stderr: os.Stderr,
	}).OpenURL(context.Background(), url)
}

// OpenCommand opens the browser using the command.
func (*Browser) OpenCommand(ctx context.Context, url, command string) error {
	c := exec.CommandContext(ctx, command, url)
	c.Stdout = os.Stderr // see above
	c.Stderr = os.Stderr
	return c.Run()
}
