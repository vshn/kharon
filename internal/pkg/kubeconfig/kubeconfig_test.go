package kubeconfig_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
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
				"openshiftApiURL": "https://api.c-test-1.vshnmanaged.net:6443",
			},
		},
		{
			ID: "c-example-2",
			DynamicFacts: map[string]any{
				"openshiftApiURL": "https://api.c-example-2.vshnmanaged.net:6443",
			},
		},
	}), &res))
	resultJSON, err := yaml.YAMLToJSONStrict(res.Bytes())
	require.NoError(t, err)

	expected := `{
	"apiVersion": "v1",
	"clusters": [
		{
			"cluster": {
				"server": "https://api.c-example-2.vshnmanaged.net:6443"
			},
			"name": "c-example-2"
		},
		{
			"cluster": {
				"server": "https://api.c-test-1.vshnmanaged.net:6443"
			},
			"name": "c-test-1"
		}
	],
	"contexts": [
		{
			"context": {
				"cluster": "c-example-2",
				"user": ""
			},
			"name": "c-example-2"
		},
		{
			"context": {
				"cluster": "c-test-1",
				"user": ""
			},
			"name": "c-test-1"
		}
	],
	"current-context": "c-test-1",
	"kind": "Config",
	"users": null
}`

	require.JSONEq(t, expected, string(resultJSON))
}
