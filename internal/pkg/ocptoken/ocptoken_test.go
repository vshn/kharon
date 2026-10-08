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

func Test_VerifyToken(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		mockUserHomeDir(t)

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-10*time.Minute), 3*60*60)
			},
		)

		ok, err := VerifyToken(context.Background(), "valid", srv.URL)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("valid token, not enough expiry left", func(t *testing.T) {
		mockUserHomeDir(t)

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-10*time.Minute), 60*60)
			},
		)

		ok, err := VerifyToken(context.Background(), "valid", srv.URL)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("expired token", func(t *testing.T) {
		mockUserHomeDir(t)

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-12*time.Hour), 60*60)
			},
		)

		ok, err := VerifyToken(context.Background(), "expired", srv.URL)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockUserHomeDir(t)

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			},
		)

		ok, err := VerifyToken(context.Background(), "expired", srv.URL)
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func Test_Token(t *testing.T) {
	t.Run("uses cached token when it is valid", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "", errors.New("must not be called")
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Must not be called - token expiry lookup is local", http.StatusInternalServerError)
			},
		)

		token := "sha256~cached-token"
		require.NoError(t, cache.WriteToken(srv.URL, cache.Entry{
			Expiry: time.Now().Add(12 * time.Hour),
			Token:  token,
		}))

		got, expiry, err := Token(context.Background(), srv.URL, "", false)
		require.NoError(t, err)
		require.Equal(t, token, got)
		require.True(t, expiry.After(time.Now()), "expected cached token expiry to be in the future")
	})

	t.Run("requests new token when cached token is expired", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "new-token", nil
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-2*time.Hour), 3600*12)
			},
		)

		token := "sha256~cached-token"
		require.NoError(t, cache.WriteToken(srv.URL, cache.Entry{
			Expiry: time.Now().Add(15 * time.Minute),
			Token:  token,
		}))

		got, expiry, err := Token(context.Background(), srv.URL, "", false)
		require.NoError(t, err)
		require.Equal(t, "new-token", got)
		require.True(t, expiry.After(time.Now()), "expected token expiry to be in the future")
	})

	t.Run("requests new token when no cached token is available", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "new-token", nil
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-2*time.Hour), 3600*12)
			},
		)

		got, expiry, err := Token(context.Background(), srv.URL, "", false)
		require.NoError(t, err)
		require.Equal(t, "new-token", got)
		require.True(t, expiry.After(time.Now()), "expected token expiry to be in the future")
	})

	t.Run("requests new token when refresh is true", func(t *testing.T) {
		mockUserHomeDir(t)

		mockTokenRequestFunc(t, func(clientCfg *rest.Config, authzURLHandler tokenrequest.AuthorizationURLHandlerFunc, callbackPort int) (string, error) {
			return "new-token", nil
		})

		srv := newMockAPIServer(t,
			func(w http.ResponseWriter, r *http.Request) {
				writeTokenResponse(t, w, time.Now().Add(-2*time.Hour), 3600*12)
			},
		)

		require.NoError(t, cache.WriteToken(srv.URL, cache.Entry{
			Expiry: time.Now().Add(12 * time.Hour),
			Token:  "refreshed",
		}))

		got, expiry, err := Token(context.Background(), srv.URL, "", true)
		require.NoError(t, err)
		require.Equal(t, "new-token", got)
		require.True(t, expiry.After(time.Now()), "expected token expiry to be in the future")
	})
}

func newMockAPIServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /apis/oauth.openshift.io/v1/useroauthaccesstokens/{token}", func(w http.ResponseWriter, r *http.Request) {
		tokenHandler(w, r)
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

func writeTokenResponse(t *testing.T, w http.ResponseWriter, creationTimestamp time.Time, expiresInSeconds int) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
		"metadata": map[string]any{
			"creationTimestamp": creationTimestamp.UTC().Format(time.RFC3339),
		},
		"expiresIn": expiresInSeconds,
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
