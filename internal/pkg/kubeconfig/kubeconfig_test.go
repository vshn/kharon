package kubeconfig_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
	kcapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"

	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func Test_FromClusters_Encode(t *testing.T) {
	var res bytes.Buffer
	require.NoError(t, kubeconfig.Encode(kubeconfig.FromClusters([]lieutenant.Cluster{
		{
			ID: "c-other-1",
		},
		{
			ID: "c-test-1",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.c-test-1.vshnmanaged.net:6443",
			},
		},
		{
			ID: "c-example-2",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.c-example-2.vshnmanaged.net:6443",
			},
		},
	}, "socks5://localhost:12000", ""), &res))
	resultJSON, err := yaml.YAMLToJSONStrict(res.Bytes())
	require.NoError(t, err)

	expected := `{
	"apiVersion": "v1",
	"clusters": [
		{
			"cluster": {
				"server": "https://api.c-example-2.vshnmanaged.net:6443",
				"proxy-url": "socks5://localhost:12000"
			},
			"name": "c-example-2"
		},
		{
			"cluster": {
				"server": "https://api.c-test-1.vshnmanaged.net:6443",
				"proxy-url": "socks5://localhost:12000"
			},
			"name": "c-test-1"
		}
	],
	"contexts": [
		{
			"context": {
				"cluster": "c-example-2",
				"user": "c-example-2"
			},
			"name": "c-example-2"
		},
		{
			"context": {
				"cluster": "c-test-1",
				"user": "c-test-1"
			},
			"name": "c-test-1"
		}
	],
	"current-context": "c-test-1",
	"kind": "Config",
	"users": [
		{
			"name": "c-example-2",
			"user": {
				"username": "anonymous"
			}
		},
		{
			"name": "c-test-1",
			"user": {
				"username": "anonymous"
			}
		}
	]
}`

	require.JSONEq(t, expected, string(resultJSON))
}

func Test_FromClusters_CurrentContext(t *testing.T) {
	t.Run("context provided", func(t *testing.T) {
		kc := kubeconfig.FromClusters([]lieutenant.Cluster{}, "", "wanted-context")
		require.Equal(t, "wanted-context", kc.CurrentContext)
	})

	t.Run("context not provided", func(t *testing.T) {
		kc := kubeconfig.FromClusters([]lieutenant.Cluster{
			{
				ID: "c-test-1",
			},
			{
				ID: "c-example-2",
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.c-example-2.vshnmanaged.net:6443",
				},
			},
		}, "", "")
		require.Equal(t, "c-example-2", kc.CurrentContext)
	})
}

func Test_InsertConnectionInfoIntoKubeconfig(t *testing.T) {
	tcs := []struct {
		name               string
		contextName        string
		expectedKubeconfig *kubeconfig.Config
	}{
		{
			name:        "with context name",
			contextName: "test-context",
			expectedKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.Clusters["test-context"] = &kcapi.Cluster{
					Server:   "https://api.test-cluster.vshnmanaged.net:6443",
					ProxyURL: "socks5://localhost:12000",
				}
				kc.CurrentContext = "test-context"
				kc.AuthInfos["test-context/kharon-login"] = &kcapi.AuthInfo{
					Token: "test-token",
				}
				kc.Contexts["test-context"] = &kcapi.Context{
					Cluster:  "test-context",
					AuthInfo: "test-context/kharon-login",
				}
				return kc
			}(),
		}, {
			name:        "without context name",
			contextName: "",
			expectedKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.Clusters["api-test-cluster-vshnmanaged-net:6443"] = &kcapi.Cluster{
					Server:   "https://api.test-cluster.vshnmanaged.net:6443",
					ProxyURL: "socks5://localhost:12000",
				}
				kc.CurrentContext = "api-test-cluster-vshnmanaged-net:6443"
				kc.AuthInfos["api-test-cluster-vshnmanaged-net:6443/kharon-login"] = &kcapi.AuthInfo{
					Token: "test-token",
				}
				kc.Contexts["api-test-cluster-vshnmanaged-net:6443"] = &kcapi.Context{
					Cluster:  "api-test-cluster-vshnmanaged-net:6443",
					AuthInfo: "api-test-cluster-vshnmanaged-net:6443/kharon-login",
				}
				return kc
			}(),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			td := t.TempDir()
			kubeconfigPath := td + "/kubeconfig"
			t.Setenv("KUBECONFIG", kubeconfigPath)
			require.NoError(t, kubeconfig.InsertConnectionInfoIntoKubeconfig(tc.contextName, "https://api.test-cluster.vshnmanaged.net:6443", "socks5://localhost:12000", "test-token"))

			kubeConfig, err := new(clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}).Load()
			require.NoError(t, err)
			if diff := cmp.Diff(kubeConfig, tc.expectedKubeconfig, kubeconfigDiffOptions()); diff != "" {
				t.Errorf("kubeConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_InsertTokenIntoCurrentContext(t *testing.T) {
	tcs := []struct {
		name               string
		startingKubeconfig *kubeconfig.Config
		expectedKubeconfig *kubeconfig.Config
		wantErr            string
	}{
		{
			name:               "empty kubeconfig",
			startingKubeconfig: kcapi.NewConfig(),
			wantErr:            "no current context set in kubeconfig or current context is invalid",
		}, {
			name: "context not found in kubeconfig",
			startingKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.CurrentContext = "other-context"
				return kc
			}(),
			wantErr: "no current context set in kubeconfig or current context is invalid",
		}, {
			name: "context and auth info exist in kubeconfig, impersonate fields are preserved, other fields are pruned",
			startingKubeconfig: func() *kubeconfig.Config {
				clusterName := "cluster1"
				kc := kcapi.NewConfig()
				kc.Clusters[clusterName] = &kcapi.Cluster{
					Server: "https://api.test-cluster.vshnmanaged.net:6443",
				}
				kc.CurrentContext = clusterName
				kc.AuthInfos[clusterName] = &kcapi.AuthInfo{
					Token:       "old-token",
					Impersonate: "system:admin",
					ImpersonateGroups: []string{
						"system:admins",
					},
					ImpersonateUserExtra: map[string][]string{
						"extra-key": {"extra-value"},
					},
					Password: "should-be-removed",
				}
				kc.Contexts[clusterName] = &kcapi.Context{
					Cluster:  clusterName,
					AuthInfo: clusterName,
				}
				return kc
			}(),
			expectedKubeconfig: func() *kubeconfig.Config {
				clusterName := "cluster1"
				kc := kcapi.NewConfig()
				kc.Clusters[clusterName] = &kcapi.Cluster{
					Server: "https://api.test-cluster.vshnmanaged.net:6443",
				}
				kc.CurrentContext = clusterName
				kc.AuthInfos[clusterName] = &kcapi.AuthInfo{
					Token:       "test-token",
					Impersonate: "system:admin",
					ImpersonateGroups: []string{
						"system:admins",
					},
					ImpersonateUserExtra: map[string][]string{
						"extra-key": {"extra-value"},
					},
				}
				kc.Contexts[clusterName] = &kcapi.Context{
					Cluster:  clusterName,
					AuthInfo: clusterName,
				}
				return kc
			}(),
		}, {
			name: "context does not contain auth info reference, new auth info is created and referenced",
			startingKubeconfig: func() *kubeconfig.Config {
				clusterName := "cluster1"
				kc := kcapi.NewConfig()
				kc.Clusters[clusterName] = &kcapi.Cluster{
					Server: "https://api.test-cluster.vshnmanaged.net:6443",
				}
				kc.CurrentContext = clusterName
				kc.Contexts[clusterName] = &kcapi.Context{
					Cluster: clusterName,
				}
				return kc
			}(),
			expectedKubeconfig: func() *kubeconfig.Config {
				clusterName := "cluster1"
				kc := kcapi.NewConfig()
				kc.Clusters[clusterName] = &kcapi.Cluster{
					Server: "https://api.test-cluster.vshnmanaged.net:6443",
				}
				kc.CurrentContext = clusterName
				kc.AuthInfos[clusterName+"/kharon-login"] = &kcapi.AuthInfo{
					Token: "test-token",
				}
				kc.Contexts[clusterName] = &kcapi.Context{
					Cluster:  clusterName,
					AuthInfo: clusterName + "/kharon-login",
				}
				return kc
			}(),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			td := t.TempDir()
			kubeconfigPath := td + "/kubeconfig"
			require.NoError(t, clientcmd.WriteToFile(*tc.startingKubeconfig, kubeconfigPath))
			t.Setenv("KUBECONFIG", kubeconfigPath)

			err := kubeconfig.InsertTokenIntoCurrentContext("test-token")
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			kubeConfig, err := new(clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}).Load()
			require.NoError(t, err)
			if diff := cmp.Diff(kubeConfig, tc.expectedKubeconfig, kubeconfigDiffOptions()); diff != "" {
				t.Errorf("kubeConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_CurrentClusterConfig(t *testing.T) {
	tcs := []struct {
		name                  string
		startingKubeconfig    *kubeconfig.Config
		expectedClusterConfig *kcapi.Cluster
		wantErr               string
	}{
		{
			name:               "empty kubeconfig",
			startingKubeconfig: kcapi.NewConfig(),
			wantErr:            "no current context set in kubeconfig or current context is invalid",
		}, {
			name: "context not found in kubeconfig",
			startingKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.CurrentContext = "other-context"
				return kc
			}(),
			wantErr: "no current context set in kubeconfig or current context is invalid",
		}, {
			name: "referenced cluster not found in kubeconfig",
			startingKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.CurrentContext = "test-context"
				kc.Contexts["test-context"] = &kcapi.Context{
					Cluster: "other-cluster",
				}
				return kc
			}(),
			wantErr: "cluster referenced by current context not found in kubeconfig",
		}, {
			name: "cluster referenced and exists",
			startingKubeconfig: func() *kubeconfig.Config {
				clusterName := "cluster1"
				kc := kcapi.NewConfig()
				kc.Clusters[clusterName] = &kcapi.Cluster{
					Server: "https://api.test-cluster.vshnmanaged.net:6443",
				}
				kc.CurrentContext = clusterName
				kc.Contexts[clusterName] = &kcapi.Context{
					Cluster: clusterName,
				}
				return kc
			}(),
			expectedClusterConfig: func() *kcapi.Cluster {
				return &kcapi.Cluster{
					Server: "https://api.test-cluster.vshnmanaged.net:6443",
				}
			}(),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			td := t.TempDir()
			kubeconfigPath := td + "/kubeconfig"
			require.NoError(t, clientcmd.WriteToFile(*tc.startingKubeconfig, kubeconfigPath))
			t.Setenv("KUBECONFIG", kubeconfigPath)

			clusterConfig, err := kubeconfig.CurrentClusterConfig()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			if diff := cmp.Diff(clusterConfig, tc.expectedClusterConfig, kubeconfigDiffOptions()); diff != "" {
				t.Errorf("clusterConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_SetCurrentContext(t *testing.T) {
	tcs := []struct {
		name               string
		startingKubeconfig *kubeconfig.Config
		contextToSet       string
		expectedKubeconfig *kubeconfig.Config
		wantErr            string
	}{
		{
			name:               "empty kubeconfig",
			startingKubeconfig: kcapi.NewConfig(),
			contextToSet:       "test-context",
			wantErr:            "context \"test-context\" not found in kubeconfig",
		}, {
			name: "context not found in kubeconfig",
			startingKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.Contexts["other-context"] = &kcapi.Context{}
				return kc
			}(),
			contextToSet: "test-context",
			wantErr:      "context \"test-context\" not found in kubeconfig",
		}, {
			name: "context exists in kubeconfig",
			startingKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.Contexts["test-context"] = &kcapi.Context{}
				return kc
			}(),
			contextToSet: "test-context",
			expectedKubeconfig: func() *kubeconfig.Config {
				kc := kcapi.NewConfig()
				kc.Contexts["test-context"] = &kcapi.Context{}
				kc.CurrentContext = "test-context"
				return kc
			}(),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			td := t.TempDir()
			kubeconfigPath := td + "/kubeconfig"
			require.NoError(t, clientcmd.WriteToFile(*tc.startingKubeconfig, kubeconfigPath))
			t.Setenv("KUBECONFIG", kubeconfigPath)

			err := kubeconfig.SetCurrentContext(tc.contextToSet)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			kubeConfig, err := new(clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}).Load()
			require.NoError(t, err)
			if diff := cmp.Diff(kubeConfig, tc.expectedKubeconfig, kubeconfigDiffOptions()); diff != "" {
				t.Errorf("kubeConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func kubeconfigDiffOptions() cmp.Options {
	return cmp.Options{
		cmpopts.EquateEmpty(),
		cmpopts.IgnoreFields(kcapi.Cluster{}, "LocationOfOrigin"),
		cmpopts.IgnoreFields(kcapi.AuthInfo{}, "LocationOfOrigin"),
		cmpopts.IgnoreFields(kcapi.Context{}, "LocationOfOrigin"),
	}
}
