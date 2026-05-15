package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	userv1typedclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vshn/kharon/internal/pkg/browser"
	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func init() {
	RootCmd.AddCommand(ocWebLoginCmd)

	flag := ocWebLoginCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
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
	Run:     runOCWebLogin,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runOCWebLogin(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		loginCurrentContext(cmd.Context())
		return
	}

	clusterIDOrURL := args[0]
	if strings.HasPrefix(clusterIDOrURL, "http://") || strings.HasPrefix(clusterIDOrURL, "https://") {
		loginWithURL(cmd.Context(), clusterIDOrURL)
	} else {
		loginWithClusterID(cmd.Context(), clusterIDOrURL)
	}
}

func loginWithClusterID(ctx context.Context, clusterID string) {
	if clustersInventoryFile == "" {
		slog.Error("Inventory file path is required", "error", "inventory-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		slog.Error("Failed to read inventory file. You might need to run the `update` command first.", "error", err)
		os.Exit(1)
	}

	var apiURL string
	for _, c := range clusters {
		if c.ID == clusterID {
			apiURL, _, _ = c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
			break
		}
	}
	if apiURL == "" {
		slog.Error("Cluster not found or does not have a known API URL", "clusterID", clusterID)
		os.Exit(1)
	}
	if err := setProxyEnv(fmt.Sprintf("socks5h://%s", proxyAddr)); err != nil {
		slog.Error("Failed to set proxy environment variables", slog.Any("error", err))
		os.Exit(1)
	}
	tok, err := requestToken(ctx, apiURL)
	if err != nil {
		slog.Error("Failed to request token", slog.Any("error", err))
		os.Exit(1)
	}
	if err := kubeconfig.InsertConnectionInfoIntoKubeconfig(clusterID, apiURL, fmt.Sprintf("socks5://%s", proxyAddr), tok); err != nil {
		slog.Error("Failed to insert connection info into kubeconfig", slog.Any("error", err))
		os.Exit(1)
	}
}

func loginWithURL(ctx context.Context, apiURL string) {
	if err := setProxyEnv(fmt.Sprintf("socks5h://%s", proxyAddr)); err != nil {
		slog.Error("Failed to set proxy environment variables", slog.Any("error", err))
		os.Exit(1)
	}
	tok, err := requestToken(ctx, apiURL)
	if err != nil {
		slog.Error("Failed to request token", slog.Any("error", err))
		os.Exit(1)
	}
	if err := kubeconfig.InsertConnectionInfoIntoKubeconfig("", apiURL, fmt.Sprintf("socks5://%s", proxyAddr), tok); err != nil {
		slog.Error("Failed to insert connection info into kubeconfig", slog.Any("error", err))
		os.Exit(1)
	}
}

func loginCurrentContext(ctx context.Context) {
	kc, err := kubeconfig.CurrentClusterConfig()
	if err != nil {
		slog.Error("Failed to get current cluster config", slog.Any("error", err))
		os.Exit(1)
	}
	if kc.ProxyURL != "" {
		// While the url might have a `socks5://` scheme, Go treats `socks5://` and `socks5h://` the same.
		if err := setProxyEnv(kc.ProxyURL); err != nil {
			slog.Error("Failed to set proxy environment variables", slog.Any("error", err))
			os.Exit(1)
		}
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		slog.Error("Failed to load kubeconfig", slog.Any("error", err))
		os.Exit(1)
	}

	client, err := userv1typedclient.NewForConfig(cfg)
	if err != nil {
		slog.Error("Failed to create user client", slog.Any("error", err))
		os.Exit(1)
	}

	if _, err = client.Users().Get(ctx, "~", metav1.GetOptions{}); err == nil {
		slog.Info("Already logged in.")
		return
	}

	tok, err := requestToken(ctx, cfg.Host)
	if err != nil {
		slog.Error("Failed to request token", slog.Any("error", err))
		os.Exit(1)
	}
	if err := kubeconfig.InsertTokenIntoCurrentContext(tok); err != nil {
		slog.Error("Failed to insert token into kubeconfig", slog.Any("error", err))
		os.Exit(1)
	}
}

func requestToken(ctx context.Context, apiURL string) (string, error) {
	return tokenrequest.RequestTokenWithLocalCallback(&rest.Config{
		Host: apiURL,
	}, func(url *url.URL) error {
		return browser.OpenURL(ctx, url.String())
	}, 0)
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
