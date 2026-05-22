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

func Test_FindByID(t *testing.T) {
	clusters := []Cluster{
		{ID: "cluster-1"},
		{ID: "cluster-2"},
	}
	c, found := FindByID(clusters, "cluster-1")
	require.True(t, found)
	require.Equal(t, "cluster-1", c.ID)

	_, found = FindByID(clusters, "cluster-3")
	require.False(t, found)
}

func Test_FindByAPIURL(t *testing.T) {
	clusters := []Cluster{
		{ID: "invalid-fact", DynamicFacts: map[string]any{KnownDynamicFactOpenshiftApiURL: 12345}},
		{ID: "cluster-1", DynamicFacts: map[string]any{KnownDynamicFactOpenshiftApiURL: "https://api.cluster-1.example.com"}},
		{ID: "cluster-2", DynamicFacts: map[string]any{KnownDynamicFactOpenshiftApiURL: "https://api.cluster-2.example.com"}},
	}
	c, found := FindByAPIURL(clusters, "https://api.cluster-1.example.com")
	require.True(t, found)
	require.Equal(t, "cluster-1", c.ID)

	_, found = FindByAPIURL(clusters, "https://api.cluster-3.example.com")
	require.False(t, found)
}
