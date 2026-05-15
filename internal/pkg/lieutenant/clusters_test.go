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
