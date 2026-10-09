package cmd

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vshn/kharon/v2/internal/pkg/cache"
	"github.com/vshn/kharon/v2/internal/pkg/completion"
	"github.com/vshn/kharon/v2/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/v2/internal/pkg/lieutenant"
	"github.com/vshn/kharon/v2/internal/pkg/ocptoken"
)

var ocWebLoginIDP string
var ocWebLoginExecCredential, ocWebLoginForceRefreshToken bool

func init() {
	RootCmd.AddCommand(ocWebLoginCmd)

	flag := ocWebLoginCmd.Flags()
	flag.BoolVar(&ocWebLoginExecCredential, "exec-credential", false, "Return token for use with the kubectl credential exec plugin.")
	flag.BoolVar(&ocWebLoginForceRefreshToken, "force-refresh-token", false, "Force refreshes the cached token.")
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
	flag.StringVar(&ocWebLoginIDP, "idp", "vshn-idp", "The name of the Identity Provider to use for login. If not specified, the user might be prompted to choose one on the OCP login page.")
}

const ocWebLoginCmdLongDesc = `Log in to OpenShift clusters with a web-based login.

Deprecated: Consider using 'kharon switch' which is distribution agnostic and supports automatic token refresh.

Works similarly to 'oc login --web' but can be used without having the 'oc' CLI installed, respects the proxy settings from the kubeconfig, and supports querying authentication URLs from the inventory.
The command can be used as a kubectl credential plugin (--exec-credential) and enable automatic login to OpenShift clusters through kubectl.
See the example section for an example to enable automatic login.
If not arguments are provided, it will attempt to log in to the cluster of the current kubeconfig context.
If a cluster ID or API server URL is provided, it will attempt to log in to that cluster.

The command to open the console can be overridden by setting the KHARON_BROWSER or BROWSER environment variables.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const ocWebLoginCmdExample = `# Configure cluster for automatic login
cat > autologin.yml <<YAML
apiVersion: v1
clusters:
- cluster:
    proxy-url: socks5://localhost:12000
    server: https://api.example.com:6443
  name: c-example
contexts:
- context:
    cluster: c-example
    user: c-example
  name: c-example
current-context: c-example
kind: Config
users:
- name: c-example
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      args:
      - oc-web-login
      - https://api.example.com:6443
      - --exec-credential
      command: kharon
      env: null
      interactiveMode: Never
      provideClusterInfo: false
YAML
KUBECONFIG=autologin.yml kubectl get nodes

# Login to the current cluster
kharon oc-web-login

# Open the cluster console in the non-default browser (e.g. Firefox) on macOS
BROWSER="open -a firefox" kharon oc-web-login

# Login to a specific cluster by ID
kharon oc-web-login c-12345

# Login to a specific cluster by API server URL
kharon oc-web-login https://api.c-12345.example.com:6443
`

var ocWebLoginCmd = &cobra.Command{
	Use:     "oc-web-login [c-cluster-id | https://api-server]",
	Short:   "Log in to OpenShift clusters with a web-based login.",
	Long:    ocWebLoginCmdLongDesc,
	Example: ocWebLoginCmdExample,
	RunE:    runOCWebLogin,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, true, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.ApiURL()
		return api != ""
	}),
}

func runOCWebLogin(cmd *cobra.Command, args []string) error {
	if !ocWebLoginExecCredential && !ocWebLoginForceRefreshToken {
		slog.Warn("Deprecated: Consider using 'kharon switch' which is distribution agnostic and supports automatic token refresh.")
	}

	if len(args) == 0 {
		if ocWebLoginExecCredential {
			return errors.New("--exec-credential needs cluster id or api server url")
		}
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
	apiURL, _, _ := cluster.ApiURL()
	if apiURL == "" {
		return fmt.Errorf("cluster %q does not have a known API URL", clusterID)
	}
	if dist, ok, err := cluster.Distribution(); err != nil {
		return fmt.Errorf("failed to get distribution for cluster: %w", err)
	} else if !ok {
		return fmt.Errorf("cluster has no distribution fact")
	} else if dist != lieutenant.DistributionOpenshift {
		return fmt.Errorf("expected openshift cluster, got: %s", dist)
	}
	if err := setProxyEnv(proxyAddrForShell(proxyAddr)); err != nil {
		return fmt.Errorf("failed to set proxy environment variables: %w", err)
	}
	token, expiry, err := ocptoken.Token(ctx, apiURL, ocWebLoginIDP, ocWebLoginForceRefreshToken)
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}
	if ocWebLoginExecCredential {
		if err := writeExecCredential(os.Stdout, token, expiry); err != nil {
			return fmt.Errorf("failed to write exec credentials: %w", err)
		}
	} else {
		if err := kubeconfig.InsertConnectionInfoIntoKubeconfig(clusterID, apiURL, proxyAddrForKubeconfig(proxyAddr), token, []byte("")); err != nil {
			return fmt.Errorf("failed to insert connection info into kubeconfig: %w", err)
		}
	}
	return nil
}

func loginWithURL(ctx context.Context, apiURL string) error {
	if err := setProxyEnv(proxyAddrForShell(proxyAddr)); err != nil {
		return fmt.Errorf("failed to set proxy environment variables: %w", err)
	}
	token, expiry, err := ocptoken.Token(ctx, apiURL, ocWebLoginIDP, ocWebLoginForceRefreshToken)
	if err != nil {
		return fmt.Errorf("failed to request token: %w", err)
	}

	if ocWebLoginExecCredential {
		if err := writeExecCredential(os.Stdout, token, expiry); err != nil {
			return fmt.Errorf("failed to write exec credentials: %w", err)
		}
	} else {
		if err := kubeconfig.InsertConnectionInfoIntoKubeconfig("", apiURL, proxyAddrForKubeconfig(proxyAddr), token, []byte("")); err != nil {
			return fmt.Errorf("failed to insert connection info into kubeconfig: %w", err)
		}
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
	existingToken := cfg.BearerToken
	if ocWebLoginForceRefreshToken {
		existingToken = ""
	}

	var tok string
	if ok, err := ocptoken.VerifyToken(ctx, existingToken, kc.Server); err != nil {
		return fmt.Errorf("failed to verify existing token: %w", err)
	} else if ok {
		tok = cfg.BearerToken
	} else {
		t, _, err := ocptoken.Token(ctx, kc.Server, ocWebLoginIDP, ocWebLoginForceRefreshToken)
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}
		tok = t
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

func writeExecCredential(w io.Writer, token string, expiry time.Time) error {
	var et *metav1.Time
	if !expiry.IsZero() {
		et = &metav1.Time{Time: expiry.Add(-5 * time.Minute)}
	}
	res := clientauthenticationv1.ExecCredential{
		APIVersion: "client.authentication.k8s.io/v1",
		Kind:       "ExecCredential",
		Status: &clientauthenticationv1.ExecCredentialStatus{
			// ExpirationTimestamp actually does not really matter, as tokens are not saved between executions.
			// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
			ExpirationTimestamp: et,
			Token:               token,
		},
	}
	if err := json.MarshalWrite(w, res); err != nil {
		return fmt.Errorf("failed to marshal exec credential: %w", err)
	}
	return nil
}
