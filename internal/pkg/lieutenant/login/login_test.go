package login

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/require"
)

func TestLogin(t *testing.T) {
	t.Setenv("KHARON_BROWSER", "go run ./testdata/browser")
	m, err := mockoidc.NewServer(nil)
	require.NoError(t, err)

	require.NoError(t, m.AddMiddleware(clientSecretInjector(m)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, m.Start(ln, nil))
	defer m.Shutdown()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer io.Copy(io.Discard, r.Body)

		json.NewEncoder(w).Encode(lieutenantConfig{
			OIDC: lieutenantConfigOIDC{
				ClientID:     m.ClientID,
				DiscoveryURL: m.DiscoveryEndpoint(),
			},
		})
	})
	mux.HandleFunc("/clusters", func(w http.ResponseWriter, r *http.Request) {
		defer io.Copy(io.Discard, r.Body)

		kp, err := mockoidc.DefaultKeypair()
		if err != nil {
			http.Error(w, "failed to get keypair", http.StatusInternalServerError)
			return
		}

		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			http.Error(w, "missing Bearer token", http.StatusUnauthorized)
			return
		}
		if _, err := kp.VerifyJWT(strings.TrimPrefix(h, "Bearer "), m.Now); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		json.NewEncoder(w).Encode([]map[string]any{{"id": "cluster-1"}})
	})
	s := httptest.NewServer(mux)
	defer s.Close()

	t.Run("success", func(t *testing.T) {
		lts := &LieutenantTokenSource{APIURL: s.URL}
		for range 2 {
			tok, err := lts.Token()
			require.NoError(t, err)
			require.NotEmpty(t, tok.AccessToken)
		}
	})
	t.Run("local server port occupied", func(t *testing.T) {
		l, err := net.Listen("tcp", "localhost:18000")
		require.NoError(t, err)
		defer l.Close()

		lts := &LieutenantTokenSource{APIURL: s.URL}
		_, err = lts.Token()
		require.ErrorContains(t, err, "address already in use")
	})
}

// clientSecretInjector is a hackus biggus middleware that injects the client secret into token requests.
// We use secret-less login with PKCE which the mock OIDC server doesn't support.
func clientSecretInjector(m *mockoidc.MockOIDC) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == mockoidc.TokenEndpoint {
				if err := r.ParseForm(); err != nil {
					io.Copy(io.Discard, r.Body)
					http.Error(w, "failed to parse form", http.StatusBadRequest)
					return
				}
				r.Form.Set("client_secret", m.ClientSecret)
			}
			next.ServeHTTP(w, r)
		})
	}
}
