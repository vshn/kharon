package mapping_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
	"github.com/vshn/kharon/internal/pkg/proxy/mapping"
)

func Test_JumphostMappingFromClusters(t *testing.T) {
	tests := []struct {
		name    string
		cluster lieutenant.Cluster
		want    mapping.JumphostMapping
		wantErr string
	}{
		{
			name: "no jumphost",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{},
			},
		}, {
			name: "no jumphost",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{},
			},
		}, {
			name: "jumphost with base domain",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{"example.com": "jumphost-1"},
			},
		}, {
			name: "jumphost with subdomains of base domain",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
					lieutenant.KnownDynamicFactOpenshiftAppsDomain: "apps.example.com",
					lieutenant.KnownDynamicFactOpenshiftApiURL:     "https://api.example.com:6443",
					lieutenant.KnownDynamicFactOpenshiftConsoleURL: "https://console.example.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{"example.com": "jumphost-1"},
			},
		}, {
			name: "jumphost with subdomains different from base domain",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
					lieutenant.KnownDynamicFactOpenshiftAppsDomain: "apps.different.com",
					lieutenant.KnownDynamicFactOpenshiftApiURL:     "https://api.different.com:6443",
					lieutenant.KnownDynamicFactOpenshiftConsoleURL: "https://console.different.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"example.com":           "jumphost-1",
					"apps.different.com":    "jumphost-1",
					"api.different.com":     "jumphost-1",
					"console.different.com": "jumphost-1",
				},
			},
		}, {
			name: "jumphost with additional domains",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost:        "jumphost-1",
					lieutenant.KnownFactJumphostDomains: "additional.com, sub.example.com , blub.com ",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"example.com":    "jumphost-1",
					"additional.com": "jumphost-1",
					"blub.com":       "jumphost-1",
				},
			},
		}, {
			name: "jumphost with skipped domains domains",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost:            "jumphost-1",
					lieutenant.KnownFactJumphostSkipDomains: "additional.com, sub.example.com , blub.com ",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"example.com": "jumphost-1",
				},
				DirectAccessDomains: []string{
					"additional.com",
					"blub.com",
					"sub.example.com",
				},
			},
		}, {
			name: "jumphost with invalid urls",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
					lieutenant.KnownDynamicFactOpenshiftApiURL:     "://invalid-url",
					lieutenant.KnownDynamicFactOpenshiftConsoleURL: "://invalid-url",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"example.com": "jumphost-1",
				},
			},
			wantErr: "missing protocol scheme",
		}, {
			name: "jumphost but no base domain",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftApiURL: "https://api.example.com:6443",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"api.example.com": "jumphost-1",
				},
			},
			wantErr: "no openshiftBaseDomain",
		}, {
			name: "invalid jumphost fact",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: 1,
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{},
			},
			wantErr: "fact is not a string",
		}, {
			name: "invalid base domain fact",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: 1,
					lieutenant.KnownDynamicFactOpenshiftApiURL:     "https://api.example.com:6443",
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"api.example.com": "jumphost-1",
				},
			},
			wantErr: "fact is not a string",
		}, {
			name: "invalid api url fact",
			cluster: lieutenant.Cluster{
				ID: "cluster-1",
				Facts: map[string]any{
					lieutenant.KnownFactJumphost: "jumphost-1",
				},
				DynamicFacts: map[string]any{
					lieutenant.KnownDynamicFactOpenshiftBaseDomain: "example.com",
					lieutenant.KnownDynamicFactOpenshiftApiURL:     1,
				},
			},
			want: mapping.JumphostMapping{
				DomainToJumphost: map[string]string{
					"example.com": "jumphost-1",
				},
			},
			wantErr: "fact is not a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mapping.JumphostMappingFromClusters([]lieutenant.Cluster{tt.cluster})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
