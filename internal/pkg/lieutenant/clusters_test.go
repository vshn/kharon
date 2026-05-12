package lieutenant

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/lieutenant/login"
)

func Test_Client_GetClusters(t *testing.T) {
	var errResponse atomic.Pointer[string]
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clusters" {
			http.NotFound(w, r)
			return
		}
		if r := errResponse.Load(); r != nil {
			http.Error(w, *r, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode([]Cluster{{ID: "cluster-1"}}); err != nil {
			t.Log("Failed to write response:", err)
		}
	}))
	defer s.Close()

	client := NewClient(s.URL, http.DefaultClient)
	c, err := client.GetClusters(t.Context())
	require.NoError(t, err)
	require.Len(t, c, 1)
	require.Equal(t, "cluster-1", c[0].ID)

	errResponse.Store(new("ran out of clusters"))
	_, err = client.GetClusters(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
	require.Contains(t, err.Error(), "ran out of clusters")
}

func Test_NewClient_defaultHTTPClient(t *testing.T) {
	client := NewClient("http://example.com", nil)
	require.NotNil(t, client.httpClient)
	require.IsType(t, &login.Transport{}, client.httpClient.Transport)
}

func Test_JumphostMappingFromClusters(t *testing.T) {
	tests := []struct {
		name    string
		cluster Cluster
		want    map[string]string
		wantErr string
	}{
		{
			name: "no jumphost",
			cluster: Cluster{
				ID: "cluster-1",
			},
			want: map[string]string{},
		}, {
			name: "no jumphost",
			cluster: Cluster{
				ID: "cluster-1",
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
				},
			},
			want: map[string]string{},
		}, {
			name: "jumphost with base domain",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
				},
			},
			want: map[string]string{"example.com": "jumphost-1"},
		}, {
			name: "jumphost with subdomains of base domain",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
					"openshiftAppsDomain": "apps.example.com",
					"openshiftApiURL":     "https://api.example.com:6443",
					"openshiftConsoleURL": "https://console.example.com",
				},
			},
			want: map[string]string{"example.com": "jumphost-1"},
		}, {
			name: "jumphost with subdomains different from base domain",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
					"openshiftAppsDomain": "apps.different.com",
					"openshiftApiURL":     "https://api.different.com:6443",
					"openshiftConsoleURL": "https://console.different.com",
				},
			},
			want: map[string]string{
				"example.com":           "jumphost-1",
				"apps.different.com":    "jumphost-1",
				"api.different.com":     "jumphost-1",
				"console.different.com": "jumphost-1",
			},
		}, {
			name: "jumphost with additional domains",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost":        "jumphost-1",
					"jumphostDomains": "additional.com, sub.example.com , blub.com ",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
				},
			},
			want: map[string]string{
				"example.com":    "jumphost-1",
				"additional.com": "jumphost-1",
				"blub.com":       "jumphost-1",
			},
		}, {
			name: "jumphost with invalid urls",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
					"openshiftApiURL":     "://invalid-url",
					"openshiftConsoleURL": "://invalid-url",
				},
			},
			want: map[string]string{
				"example.com": "jumphost-1",
			},
			wantErr: "missing protocol scheme",
		}, {
			name: "jumphost but no base domain",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftApiURL": "https://api.example.com:6443",
				},
			},
			want: map[string]string{
				"api.example.com": "jumphost-1",
			},
			wantErr: "no openshiftBaseDomain",
		}, {
			name: "invalid jumphost fact",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": 1,
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
				},
			},
			want:    map[string]string{},
			wantErr: "fact is not a string",
		}, {
			name: "invalid base domain fact",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": 1,
					"openshiftApiURL":     "https://api.example.com:6443",
				},
			},
			want: map[string]string{
				"api.example.com": "jumphost-1",
			},
			wantErr: "fact is not a string",
		}, {
			name: "invalid api url fact",
			cluster: Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					"jumphost": "jumphost-1",
				},
				DynamicFacts: map[string]any{
					"openshiftBaseDomain": "example.com",
					"openshiftApiURL":     1,
				},
			},
			want: map[string]string{
				"example.com": "jumphost-1",
			},
			wantErr: "fact is not a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JumphostMappingFromClusters([]Cluster{tt.cluster})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
