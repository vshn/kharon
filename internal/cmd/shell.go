package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const shellCmdLongDesc = `Run a shell with a kubeconfig generated from the inventory, set up to use the proxy.
The generated kubeconfig contains all clusters from the inventory with an OpenShift API URL.
The kubeconfig context can be set to a specific cluster by providing the cluster ID as the first argument.
If no argument is provided, the context is set to the first found cluster with a valid OpenShift API URL.

The shell is started as a login shell by default, this can be disabled with the --login flag.
Additional shell arguments can be provided after the cluster ID or after a '--' separator.
If additional arguments are provided the login flag is ignored.
If the --command flag is used, the provided command is run instead of the default shell, and the --login flag is ignored.
See examples below for details.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const shellCmdExample = `# Get a default login shell
kharon shell

# Get a login shell for a specific cluster
kharon shell c-12345

# Get all nodes on a specific cluster
kharon shell c-12345 -- -c 'kharon oc-web-login; kubectl get nodes'

# Execute a custom command instead of a shell
kharon shell c-12345 --command -- my-kube-tool -x
`

func init() {
	RootCmd.AddCommand(newShellCmd())
}

type shellCmdFlags struct {
	InventoryFile string
	ProxyAddr     string

	Login   bool
	Command bool
}

func newShellCmd() *cobra.Command {
	flags := &shellCmdFlags{}
	cmd := &cobra.Command{
		Use:     "shell [c-cluster-id]",
		Short:   "Run a shell with a kubeconfig generated from the inventory, set up to use the proxy.",
		Long:    shellCmdLongDesc,
		Example: shellCmdExample,
		RunE:    func(cmd *cobra.Command, args []string) error { return runShell(cmd, flags, args) },
		ValidArgsFunction: completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
			api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
			return api != ""
		}),
	}
	flag := cmd.Flags()
	flag.StringVar(&flags.InventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&flags.ProxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
	flag.BoolVarP(&flags.Login, "login", "l", true, "Start the shell as a login shell.")
	flag.BoolVar(&flags.Command, "command", false, "Run the command at the first argument after cluster ID instead of the default shell.")

	return cmd
}

func runShell(cmd *cobra.Command, flags *shellCmdFlags, args []string) error {
	var clusterID string
	if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
		clusterID = args[0]
		args = args[1:]
	}

	if flags.InventoryFile == "" {
		return fmt.Errorf("inventory-file flag is empty and failed to determine default path")
	}

	clusters, err := cache.ReadInventoryFile(flags.InventoryFile)
	if err != nil {
		return fmt.Errorf("failed to read inventory file. You might need to run the `update` command first: %w", err)
	}

	// Kubeconfig wants a socks5 url not socks5h, but they are treated the same by Go.
	tmpKubeconfig, err := writeKubeconfigToTempFile(kubeconfig.FromClusters(clusters, fmt.Sprintf("socks5://%s", flags.ProxyAddr), clusterID))
	if err != nil {
		return fmt.Errorf("failed to write kubeconfig to temporary file: %w", err)
	}
	defer func() {
		if err := os.Remove(tmpKubeconfig); err != nil {
			slog.Warn("Failed to remove temporary kubeconfig file", "file", tmpKubeconfig, "error", err)
		}
	}()

	var execCmd string
	var execArgs []string

	if flags.Command {
		if len(args) == 0 {
			return fmt.Errorf("no command provided to run")
		}
		execCmd = args[0]
		execArgs = args[1:]
	} else {
		shell := os.Getenv("SHELL")
		if shell == "" {
			return fmt.Errorf("SHELL environment variable is not set")
		}
		execCmd = shell
		execArgs = args
		if len(args) == 0 && flags.Login {
			execArgs = append(execArgs, "--login")
		}
	}

	ex := exec.Command(execCmd, execArgs...)
	ex.Env = append(os.Environ(), "KHARON_SHELL=1", fmt.Sprintf("KUBECONFIG=%s", tmpKubeconfig))
	for _, ev := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		ex.Env = append(ex.Env, fmt.Sprintf("%s=socks5h://%s", ev, flags.ProxyAddr))
	}
	ex.Stdin = cmd.InOrStdin()
	ex.Stdout = cmd.OutOrStdout()
	ex.Stderr = cmd.ErrOrStderr()
	if err := ex.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return &ErrWithExitCode{error: fmt.Errorf("provided command exited with code %d: %w", exitErr.ExitCode(), err), ExitCode: exitErr.ExitCode()}
		}
		return fmt.Errorf("failed to run shell: %w", err)
	}
	return nil
}

func writeKubeconfigToTempFile(kc *kubeconfig.Config) (string, error) {
	tmpFile, err := os.CreateTemp("", "kharon-shell-*.kubeconfig")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary kubeconfig file: %w", err)
	}
	defer func() { _ = tmpFile.Close() }()
	if err := kubeconfig.Encode(kc, tmpFile); err != nil {
		return "", fmt.Errorf("failed to write kubeconfig to temporary file: %w", err)
	}
	return tmpFile.Name(), nil
}
