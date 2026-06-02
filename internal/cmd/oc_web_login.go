package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"github.com/vshn/kharon/internal/pkg/ocptoken"
)

var ocWebLoginIDP string

func init() {
	RootCmd.AddCommand(ocWebLoginCmd)

	flag := ocWebLoginCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
	flag.StringVar(&ocWebLoginIDP, "idp", "vshn-idp", "The name of the Identity Provider to use for login. If not specified, the user might be prompted to choose one on the OCP login page.")
}

const ocWebLoginCmdLongDesc = `Log in to OpenShift clusters with a web-based login.
Works similarly to 'oc login --web' but can be used without having the 'oc' CLI installed, respects the proxy settings from the kubeconfig, and supports querying authentication URLs from the inventory.
If not arguments are provided, it will attempt to log in to the cluster of the current kubeconfig context.
If a cluster ID or API server URL is provided, it will attempt to log in to that cluster.

The command to open the console can be overridden by setting the KHARON_BROWSER or BROWSER environment variables.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const ocWebLoginCmdExample = `# Login to the current cluster
kharon oc-web-login

# Open the cluster console in the non-default browser (e.g. Firefox) on macOS
BROWSER="open -a firefox" kharon oc-web-login

# Login to a specific cluster by ID
kharon oc-web-login c-12345

# Login to a specific cluster by API server URL
kharon oc-web-login https://api.c-12345.example.com:6443`

var ocWebLoginCmd = &cobra.Command{
	Use:     "oc-web-login [c-cluster-id | https://api-server]",
	Short:   "Log in to OpenShift clusters with a web-based login.",
	Long:    ocWebLoginCmdLongDesc,
	Example: ocWebLoginCmdExample,
	RunE:    runOCWebLogin,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, true, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runOCWebLogin(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return loginCurrentContext(cmd.Context())
	}

	clusterIDOrURL := args[0]
	if strings.HasPrefix(clusterIDOrURL, "http://") || strings.HasPrefix(clusterIDOrURL, "https://") {
		return loginWithURL(cmd.Context(), clusterIDOrURL)
	} else {
		return loginWithClusterID(cmd.Context(), clusterIDOrURL)
	}
}

func loginWithClusterID(ctx context.Context, clusterID string) error {
	if clustersInventoryFile == "" {
		return fmt.Errorf("inventory file path is required: inventory-file flag is empty and failed to determine default path")
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		return fmt.Errorf("failed to read inventory file. You might need to run the `update` command first: %w", err)
	}

	cluster, found := lieutenant.FindByID(clusters, clusterID)
	if !found {
		return fmt.Errorf("cluster %q not found", clusterID)
	}
	apiURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
	if apiURL == "" {
		return fmt.Errorf("cluster %q does not have a known API URL", clusterID)
	}
	if err := setProxyEnv(proxyAddrForShell(proxyAddr)); err != nil {
		return fmt.Errorf("failed to set proxy environment variables: %w", err)
	}
	tok, err := ocptoken.EnsureToken(ctx, "", apiURL, ocWebLoginIDP)
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}
	if err := kubeconfig.InsertConnectionInfoIntoKubeconfig(clusterID, apiURL, proxyAddrForKubeconfig(proxyAddr), tok); err != nil {
		return fmt.Errorf("failed to insert connection info into kubeconfig: %w", err)
	}
	return nil
}

func loginWithURL(ctx context.Context, apiURL string) error {
	if err := setProxyEnv(proxyAddrForShell(proxyAddr)); err != nil {
		return fmt.Errorf("failed to set proxy environment variables: %w", err)
	}
	tok, err := ocptoken.EnsureToken(ctx, "", apiURL, ocWebLoginIDP)
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}
	if err := kubeconfig.InsertConnectionInfoIntoKubeconfig("", apiURL, proxyAddrForKubeconfig(proxyAddr), tok); err != nil {
		return fmt.Errorf("failed to insert connection info into kubeconfig: %w", err)
	}
	return nil
}

func loginCurrentContext(ctx context.Context) error {
	kc, err := kubeconfig.CurrentClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get current cluster config: %w", err)
	}
	if kc.ProxyURL != "" {
		// While the url might have a `socks5://` scheme, Go treats `socks5://` and `socks5h://` the same.
		if err := setProxyEnv(kc.ProxyURL); err != nil {
			return fmt.Errorf("failed to set proxy environment variables: %w", err)
		}
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	tok, err := ocptoken.EnsureToken(ctx, cfg.BearerToken, kc.Server, ocWebLoginIDP)
	if err != nil {
		return fmt.Errorf("failed to ensure token: %w", err)
	}

	if err := kubeconfig.InsertTokenIntoCurrentContext(tok); err != nil {
		return fmt.Errorf("failed to insert token into kubeconfig: %w", err)
	}
	return nil
}

func setProxyEnv(proxyURL string) error {
	// OCP login does not respect the kubeconfig proxy settings, but does support the standard environment variables for proxies, so we set them here if a proxy URL is configured in the kubeconfig.
	//
	// https://cs.opensource.google/go/x/net/+/refs/tags/v0.54.0:http/httpproxy/proxy.go;l=90
	for _, envVar := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if err := os.Setenv(envVar, proxyURL); err != nil {
			return fmt.Errorf("failed to set proxy environment variable %s: %w", envVar, err)
		}
	}
	return nil
}

func proxyAddrForShell(addr string) string {
	if addr == "" {
		return ""
	}
	return fmt.Sprintf("socks5h://%s", addr)
}
