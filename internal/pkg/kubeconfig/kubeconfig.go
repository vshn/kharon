package kubeconfig

import (
	"io"

	model "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

type Config = model.Config

// FromClusters creates a kubeconfig Config object from the given clusters. It uses the openshiftApiURL fact to set the server URL for each cluster.
// If currentContext is provided, it will be set as the current context in the resulting kubeconfig.
// The functions does not validate that the provided currentContext actually exists.
// If not provided, the first cluster with a valid API URL will be set as the current context.
func FromClusters(clusters []lieutenant.Cluster, currentContext string) *Config {
	kc := model.NewConfig()
	currentContextSet := false
	if currentContext != "" {
		kc.CurrentContext = currentContext
		currentContextSet = true
	}
	for _, c := range clusters {
		api, _, _ := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		if api == "" {
			continue
		}
		clusterName := c.ID
		contextName := c.ID
		kc.Clusters[clusterName] = &model.Cluster{
			Server: api,
		}
		kc.Contexts[contextName] = &model.Context{
			Cluster: clusterName,
		}
		if !currentContextSet {
			kc.CurrentContext = contextName
			currentContextSet = true
		}
	}
	return kc
}

// Encode encodes the given kubeconfig Config object to the provided writer in YAML format.
func Encode(kc *Config, w io.Writer) error {
	return clientcmdlatest.Codec.Encode(kc, w)
}
