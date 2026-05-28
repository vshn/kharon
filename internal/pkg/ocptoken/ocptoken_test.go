package ocptoken

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	"github.com/vshn/kharon/internal/pkg/cache"
)

func Test_EnsureToken(t *testing.T) {
	t.Run("returns existing token when oauth token has enough validity", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "", errors.New("must not be called")
		})

		token := "sha256~valid-token"
		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "system:admin", r.Header.Get("Impersonate-User"))
				writeTokenResponse(t, w, time.Now().Add(-10*time.Minute), 3*60*60)
			},
			nil,
		)

		got, err := EnsureToken(context.Background(), token, srv.URL, "")
		require.NoError(t, err)
		require.Equal(t, token, got)
	})

	t.Run("requests a new token and caches it when oauth token is expired", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "new-token", nil
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-2*time.Hour), 3600)
			},
			nil,
		)

		got, err := EnsureToken(context.Background(), "sha256~expired-token", srv.URL, "")
		require.NoError(t, err)
		require.Equal(t, "new-token", got)
		cached, err := cache.GetToken(srv.URL)
		require.NoError(t, err)
		require.Equal(t, "new-token", cached)
	})

	t.Run("returns existing token when token lookup is forbidden but SSR succeeds", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "", errors.New("must not be called")
		})

		token := "sha256~forbidden-token"
		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
		)

		got, err := EnsureToken(context.Background(), token, srv.URL, "")
		require.NoError(t, err)
		require.Equal(t, token, got)
	})

	t.Run("requests new token when token lookup is forbidden and SSR is unauthorized", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "new-token-after-ssr", nil
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
		)

		got, err := EnsureToken(context.Background(), "sha256~forbidden-token", srv.URL, "")
		require.NoError(t, err)
		require.Equal(t, "new-token-after-ssr", got)
	})

	t.Run("requests new token when token lookup fails with unauthorized SSR", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "new-token", nil
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			nil,
		)

		got, err := EnsureToken(context.Background(), "sha256~unauthorized-token", srv.URL, "")
		require.NoError(t, err)
		require.Equal(t, "new-token", got)
	})

	t.Run("uses cached token when it is valid", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "", errors.New("must not be called")
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "system:admin", r.Header.Get("Impersonate-User"))
				writeTokenResponse(t, w, time.Now().Add(-10*time.Minute), 3*60*60)
			},
			nil,
		)

		token := "sha256~cached-token"
		require.NoError(t, cache.WriteToken(srv.URL, token))

		got, err := EnsureToken(context.Background(), "", srv.URL, "")
		require.NoError(t, err)
		require.Equal(t, token, got)
	})
}

func newMockAPIServer(t *testing.T, tokenHandler http.HandlerFunc, ssrHandler http.HandlerFunc) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /apis/oauth.openshift.io/v1/oauthaccesstokens/{token}", func(w http.ResponseWriter, r *http.Request) {
		tokenHandler(w, r)
	})
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/selfsubjectreviews", func(w http.ResponseWriter, r *http.Request) {
		if ssrHandler == nil {
			t.Fatalf("unexpected SSR call")
		}
		ssrHandler(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func mockUserHomeDir(t *testing.T) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
}

func writeTokenResponse(t *testing.T, w http.ResponseWriter, creationTimestamp time.Time, expiresIn int) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
		"metadata": map[string]any{
			"creationTimestamp": creationTimestamp.UTC().Format(time.RFC3339),
		},
		"expiresIn": expiresIn,
	}))
}

func mockTokenRequestFunc(t *testing.T, fn func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error)) {
	t.Helper()

	original := tokenRequestFunc
	tokenRequestFunc = fn
	t.Cleanup(func() {
		tokenRequestFunc = original
	})
}
