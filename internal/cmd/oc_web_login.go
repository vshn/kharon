package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vshn/kharon/internal/pkg/browser"
	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
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

	cluster, found := lieutenant.FindByID(clusters, clusterID)
	if !found {
		slog.Error("Cluster not found", "cluster_id", clusterID)
		os.Exit(1)
	}
	apiURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
	if apiURL == "" {
		slog.Error("Cluster not found or does not have a known API URL", "cluster_id", clusterID)
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

	resp, err := lightSSR(cfg)
	l := slog.With("error", err)
	if resp != nil {
		l = l.With("status", resp.Status)
	}
	l.Debug("SelfSubjectReview response")
	if err == nil && resp.StatusCode == 201 {
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

// Including the openshift or kubenetes client more than doubles the size of the binary, so we implement a very minimal version of the SelfSubjectReview API call.
func lightSSR(cfg *rest.Config) (*http.Response, error) {
	c, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client for kubeconfig: %w", err)
	}
	url, _, err := rest.DefaultServerUrlFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to determine API server URL from kubeconfig: %w", err)
	}
	url.Path = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	return c.Post(url.String(), "application/json", strings.NewReader(`{"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1"}`))
}

func requestToken(ctx context.Context, apiURL string) (string, error) {
	return tokenrequest.RequestTokenWithLocalCallback(&rest.Config{
		Host: apiURL,
	}, func(url *url.URL) error {
		if ocWebLoginIDP != "" {
			q := url.Query()
			q.Set("idp", ocWebLoginIDP)
			url.RawQuery = q.Encode()
		}
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
