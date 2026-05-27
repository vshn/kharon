package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"

	"github.com/fatih/color"
	"github.com/minio/pkg/v3/wildcard"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const shellCmdLongDesc = `Run a shell with a kubeconfig generated from the inventory, set up to use the proxy.
The generated kubeconfig contains all clusters from the inventory with an OpenShift API URL.
The kubeconfig context can be set to a specific cluster by providing the cluster ID as the first argument.
If the first argument contains wildcards, it is treated as a pattern to filter the clusters included in the kubeconfig.
If multiple clusters match the pattern, the context is set to the first cluster in the filtered list.
If no argument is provided, the context is set to the first found cluster with a valid OpenShift API URL.

The shell is started as a login shell by default, this can be disabled with the --login flag.
Additional shell arguments can be provided after the cluster ID or after a '--' separator.
If additional arguments are provided the shell is not started as a login shell, even if the --login flag is set.
If the --command flag is used, the provided command is run instead of the default shell, and the --login flag is ignored.
See examples below for details.

Using the --each flag, the command can be run for each cluster individually instead of once with a kubeconfig containing all clusters.
In this case, the command is run once per cluster with the current context set to that cluster. Failures for individual clusters do not stop the execution for other clusters, but are reported at the end.
The output of each command is prefixed with the cluster ID for clarity. The --command flag is implied when using --each.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const shellCmdExample = `# Get a default login shell
kharon shell

# Get a login shell for a specific cluster
kharon shell c-12345

# Get all nodes on a specific cluster
kharon shell c-12345 -- -c 'kharon oc-web-login; kubectl get nodes'

# Collect node information for all clusters
kharon shell --each -- sh -c 'kharon oc-web-login; kubectl get nodes'

# Collect node information for all prod clusters, excluding a certain customer
kharon shell '*prod*' --exclude-cluster 'customer-*' --each -- sh -c 'kharon oc-web-login; kubectl get nodes'

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
	Each    bool

	ClusterExcludePatterns []string
}

func newShellCmd() *cobra.Command {
	flags := &shellCmdFlags{}
	cmd := &cobra.Command{
		Use:               "shell [c-cluster-id | c-pattern-*] [-- command [args...]]",
		Short:             "Run a shell or command with a kubeconfig generated from the inventory, set up to use the proxy.",
		Long:              shellCmdLongDesc,
		Example:           shellCmdExample,
		RunE:              func(cmd *cobra.Command, args []string) error { return runShell(cmd, flags, args) },
		ValidArgsFunction: shellCmdArgsValidator,
	}
	flag := cmd.Flags()
	flag.StringVar(&flags.InventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&flags.ProxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
	flag.BoolVarP(&flags.Login, "login", "l", true, "Start the shell as a login shell.")
	flag.BoolVar(&flags.Command, "command", false, "Run the command at the first argument after cluster ID instead of the default shell.")
	flag.BoolVar(&flags.Each, "each", false, "Run the command for each cluster individually instead of once with a kubeconfig containing all clusters. This flag implies --command.")
	flag.StringSliceVar(&flags.ClusterExcludePatterns, "exclude-cluster", nil, "Exclude clusters matching the given patterns. Supports wildcards, e.g. `--exclude-cluster=c-dev-*` to exclude all clusters starting with `c-dev-`. This flag can be used multiple times to exclude multiple patterns. Useful in combination with --each to exclude certain clusters from the per-cluster execution.")
	must(cmd.RegisterFlagCompletionFunc("exclude-cluster", completion.ClusterID(flags.InventoryFile, nil)))

	return cmd
}

func shellCmdArgsValidator(cmd *cobra.Command, args []string, cur string) ([]string, cobra.ShellCompDirective) {
	// Stop cluster completion after the first argument or the first '--' separator.
	// [cobra.Command.ArgsLenAtDash] is not yet initialized when this function is called for completion,
	// so we check for the presence of '--' in os.Args instead.
	if len(args) == 0 && !slices.Contains(os.Args, "--") {
		return completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
			api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
			return api != ""
		})(cmd, args, cur)
	}
	return nil, cobra.ShellCompDirectiveDefault
}

func runShell(cmd *cobra.Command, flags *shellCmdFlags, args []string) error {
	var clusterIDOrPattern string
	if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
		clusterIDOrPattern = args[0]
		args = args[1:]
	}

	if flags.InventoryFile == "" {
		return fmt.Errorf("inventory-file flag is empty and failed to determine default path")
	}

	clusters, err := cache.ReadInventoryFile(flags.InventoryFile)
	if err != nil {
		return fmt.Errorf("failed to read inventory file. You might need to run the `update` command first: %w", err)
	}

	var pattern, clusterID string
	if clusterIDOrPattern != "" {
		if wildcard.Has(clusterIDOrPattern) {
			pattern = clusterIDOrPattern
		} else {
			clusterID = clusterIDOrPattern
		}
	}

	filtered := make([]lieutenant.Cluster, 0, len(clusters))
	for _, cluster := range clusters {
		if apiURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL); apiURL == "" {
			continue
		}
		if pattern != "" && !wildcard.Match(pattern, cluster.ID) {
			continue
		}
		for _, excludePattern := range flags.ClusterExcludePatterns {
			if wildcard.Match(excludePattern, cluster.ID) {
				continue
			}
		}
		filtered = append(filtered, cluster)
	}

	// Kubeconfig wants a socks5 url not socks5h, but they are treated the same by Go.
	tmpKubeconfig, err := writeKubeconfigToTempFile(kubeconfig.FromClusters(filtered, proxyAddrForKubeconfig(flags.ProxyAddr), clusterID))
	if err != nil {
		return fmt.Errorf("failed to write kubeconfig to temporary file: %w", err)
	}
	defer func() {
		if err := os.Remove(tmpKubeconfig); err != nil {
			slog.Warn("Failed to remove temporary kubeconfig file", "file", tmpKubeconfig, "error", err)
		}
	}()
	if err := os.Setenv("KUBECONFIG", tmpKubeconfig); err != nil {
		return fmt.Errorf("failed to set KUBECONFIG environment variable: %w", err)
	}

	var execCmd string
	var execArgs []string

	if flags.Command || flags.Each {
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

	if flags.Each {
		var errors []error
		for _, cluster := range filtered {
			clusterID := cluster.ID
			_, _ = color.New(color.Bold).Fprintf(cmd.OutOrStdout(), "--- # %s\n", clusterID)
			if err := kubeconfig.SetCurrentContext(clusterID); err != nil {
				errors = append(errors, fmt.Errorf("failed to set current context to %s: %w", clusterID, err))
				continue
			}
			if err := runCommand(execCmd, execArgs, cmd, flags.ProxyAddr); err != nil {
				_, _ = color.New(color.FgRed).Fprintf(cmd.ErrOrStderr(), "Error running command for cluster %s: %v\n", clusterID, err)
				errors = append(errors, fmt.Errorf("failed to run command for cluster %s: %w", clusterID, err))
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}
		return multierr.Combine(errors...)
	}

	return runCommand(execCmd, execArgs, cmd, flags.ProxyAddr)
}

func runCommand(execCmd string, execArgs []string, cmd *cobra.Command, proxyAddr string) error {
	ex := exec.Command(execCmd, execArgs...)
	ex.Env = append(os.Environ(), "KHARON_SHELL=1")
	for _, ev := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		ex.Env = append(ex.Env, fmt.Sprintf("%s=%s", ev, proxyAddrForShell(proxyAddr)))
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
