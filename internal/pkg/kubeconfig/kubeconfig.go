package kubeconfig

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"k8s.io/client-go/tools/clientcmd"
	model "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

type Config = model.Config

// FromClusters creates a kubeconfig Config object from the given clusters. It uses the openshiftApiURL fact to set the server URL for each cluster.
// If currentContext is provided, it will be set as the current context in the resulting kubeconfig.
// The functions does not validate that the provided currentContext actually exists.
// If not provided, the first cluster with a valid API URL will be set as the current context.
func FromClusters(clusters []lieutenant.Cluster, proxyURL, currentContext string) *Config {

	kc := model.NewConfig()
	currentContextSet := false
	if currentContext != "" {
		kc.CurrentContext = currentContext
		currentContextSet = true
	}
	for _, c := range clusters {
		api, _, _ := c.GetApiURL()
		if api == "" {
			continue
		}
		clusterName := c.ID
		contextName := c.ID
		caData, _, _ := c.GetCAData()
		authInfo, _ := getAuthInfo(c)
		kc.Clusters[clusterName] = &model.Cluster{
			Server:                   api,
			ProxyURL:                 proxyURL,
			CertificateAuthorityData: caData,
		}
		kc.Contexts[contextName] = &model.Context{
			Cluster:  clusterName,
			AuthInfo: clusterName,
		}
		kc.AuthInfos[clusterName] = authInfo
		if !currentContextSet {
			kc.CurrentContext = contextName
			currentContextSet = true
		}
	}
	return kc
}

var osExecutable = sync.OnceValues(os.Executable)

func getAuthInfo(c lieutenant.Cluster) (*model.AuthInfo, error) {
	const authInfoName = "anonymous"
	if !c.UseOIDC() {
		return &model.AuthInfo{
			Username: authInfoName,
		}, nil
	}

	oidcIssuer, oidcClientPattern, _, err := c.GetOIDCInfo()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve OIDC parameters for cluster %s: %w", c.ID, err)
	}

	exe, err := osExecutable()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve executable path: %w", err)
	}

	return &model.AuthInfo{
		Exec: &model.ExecConfig{
			Command:            exe,
			APIVersion:         "client.authentication.k8s.io/v1beta1",
			InteractiveMode:    model.IfAvailableExecInteractiveMode,
			ProvideClusterInfo: false,
			Args: []string{
				"kubelogin",
				"get-token",
				fmt.Sprintf("--oidc-issuer-url=%s", oidcIssuer),
				fmt.Sprintf("--oidc-client-id=%s", fmt.Sprintf(oidcClientPattern, c.ID)),
				"--oidc-extra-scope=email offline_access profile openid",
			},
		},
	}, nil
}

// Encode encodes the given kubeconfig Config object to the provided writer in YAML format.
func Encode(kc *Config, w io.Writer) error {
	return clientcmdlatest.Codec.Encode(kc, w)
}

func InsertTokenIntoCurrentContext(token string) error {
	return updateKubeconfig(func(config *model.Config) error {
		if config.CurrentContext == "" || config.Contexts[config.CurrentContext] == nil {
			return fmt.Errorf("no current context set in kubeconfig or current context is invalid")
		}

		kubectx := config.Contexts[config.CurrentContext]
		if kubectx.AuthInfo == "" {
			config.Contexts[config.CurrentContext].AuthInfo = authInfoName(config.CurrentContext)
		}
		if authInfo, ok := config.AuthInfos[kubectx.AuthInfo]; ok {
			config.AuthInfos[kubectx.AuthInfo] = &model.AuthInfo{
				Token:                token,
				Impersonate:          authInfo.Impersonate,
				ImpersonateGroups:    authInfo.ImpersonateGroups,
				ImpersonateUserExtra: authInfo.ImpersonateUserExtra,
			}
		} else {
			config.AuthInfos[kubectx.AuthInfo] = &model.AuthInfo{
				Token: token,
			}
		}
		return nil
	})
}

var urlToContextReplacementRegex = regexp.MustCompile(`[^a-zA-Z0-9:]`)

// InsertConnectionInfoIntoKubeconfig inserts a new cluster, context, and auth info into the kubeconfig for the given context name, API URL, proxy URL, and token.
// If contextName is empty, a context name will be generated from the API URL by removing the protocol and replacing non-alphanumeric characters with dashes.
func InsertConnectionInfoIntoKubeconfig(contextName, apiURL, proxyURL, token string, caData []byte) error {
	if contextName == "" {
		contextName = urlToContextReplacementRegex.ReplaceAllString(strings.TrimPrefix(strings.TrimPrefix(apiURL, "http://"), "https://"), "-")
	}

	return updateKubeconfig(func(config *model.Config) error {
		authInfoName := authInfoName(contextName)
		config.Clusters[contextName] = &model.Cluster{
			Server:                   apiURL,
			ProxyURL:                 proxyURL,
			CertificateAuthorityData: caData,
		}
		config.Contexts[contextName] = &model.Context{
			Cluster:  contextName,
			AuthInfo: authInfoName,
		}
		config.AuthInfos[authInfoName] = &model.AuthInfo{
			Token: token,
		}
		config.CurrentContext = contextName
		return nil
	})
}

// SetCurrentContext sets the current context in the kubeconfig to the given context name.
// It returns an error if the context does not exist in the kubeconfig.
func SetCurrentContext(contextName string) error {
	return updateKubeconfig(func(config *model.Config) error {
		if _, ok := config.Contexts[contextName]; !ok {
			return fmt.Errorf("context %q not found in kubeconfig", contextName)
		}
		config.CurrentContext = contextName
		return nil
	})
}

// CurrentClusterConfig returns the cluster configuration of the current context in the kubeconfig.
// It returns an error if the current context is not set or invalid, or if the cluster referenced by the current context is not found.
func CurrentClusterConfig() (*model.Cluster, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	c, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).RawConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}
	if c.CurrentContext == "" || c.Contexts[c.CurrentContext] == nil {
		return nil, fmt.Errorf("no current context set in kubeconfig or current context is invalid")
	}
	cluster := c.Clusters[c.Contexts[c.CurrentContext].Cluster]
	if cluster == nil {
		return nil, fmt.Errorf("cluster referenced by current context not found in kubeconfig")
	}
	return cluster, nil
}

func updateKubeconfig(updateFunc func(*model.Config) error) error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	configOverrides := &clientcmd.ConfigOverrides{}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).RawConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig for editing: %w", err)
	}

	if err := updateFunc(&config); err != nil {
		return fmt.Errorf("update callback failed: %w", err)
	}

	return clientcmd.ModifyConfig(loadingRules, config, true)
}

func authInfoName(contextName string) string {
	return fmt.Sprintf("%s/kharon-login", contextName)
}
