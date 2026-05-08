package login

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/vshn/kharon/internal/pkg/browser"
	"golang.org/x/oauth2"
)

//go:embed success.html
var successPage string

type lieutenantConfigOIDC struct {
	ClientID     string `json:"clientId"`
	DiscoveryURL string `json:"discoveryUrl"`
}

type lieutenantConfig struct {
	APIVersion string               `json:"apiVersion"`
	OIDC       lieutenantConfigOIDC `json:"oidc"`
}

var _ oauth2.TokenSource = new(LieutenantTokenSource)

type LieutenantTokenSource struct {
	APIURL string

	cMux sync.Mutex
	c    oauth2.TokenSource
}

func (lts *LieutenantTokenSource) Token() (tok *oauth2.Token, err error) {
	lts.cMux.Lock()
	defer lts.cMux.Unlock()

	if lts.c != nil {
		return lts.c.Token()
	}

	cfg, err := lts.config()
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC config: %w", err)
	}
	provider, err := oidc.NewProvider(context.Background(), strings.TrimSuffix(cfg.OIDC.DiscoveryURL, "/.well-known/openid-configuration"))
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	conf := &oauth2.Config{
		ClientID:    cfg.OIDC.ClientID,
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint:    provider.Endpoint(),
		RedirectURL: "http://localhost:18000",
	}

	type codeResponse struct {
		code string
		err  error
	}

	code := make(chan codeResponse, 2)
	serv := &http.Server{
		Addr: "localhost:18000",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				_, _ = io.Copy(io.Discard, r.Body)
			}()
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}

			c := r.URL.Query().Get("code")
			if c == "" {
				http.Error(w, "code query parameter is required", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, successPage)
			code <- codeResponse{code: c}
		}),
	}
	go func() {
		code <- codeResponse{err: fmt.Errorf("failed to start local server for redirect: %w", serv.ListenAndServe())}
	}()
	defer func() { _ = serv.Close() }()

	verifier := oauth2.GenerateVerifier()
	authURL := conf.AuthCodeURL("kharon-login",
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)
	fmt.Fprintln(os.Stderr, authURL)

	bCtx, bCtxCancel := context.WithCancel(context.Background())
	defer bCtxCancel()
	go func() {
		if err := browser.OpenURL(bCtx, authURL); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open browser automatically: %v\nPlease open the URL above manually.\n", err)
		}
	}()

	cr := <-code
	if cr.err != nil {
		return nil, cr.err
	}
	tok, err = conf.Exchange(context.Background(), cr.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	lts.c = conf.TokenSource(context.Background(), tok)
	return lts.c.Token()
}

func (lts *LieutenantTokenSource) config() (lieutenantConfig, error) {
	if lts.APIURL == "" {
		return lieutenantConfig{}, fmt.Errorf("API URL is required")
	}

	r, err := http.Get(lts.APIURL)
	if err != nil {
		return lieutenantConfig{}, fmt.Errorf("failed to fetch OIDC config from the API: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return lieutenantConfig{}, fmt.Errorf("API URL returned non-200 status code: %d", r.StatusCode)
	}

	var cfg lieutenantConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		return lieutenantConfig{}, fmt.Errorf("failed to decode API response: %w", err)
	}

	slog.Debug("Successfully fetched OIDC config from the API", "client_id", cfg.OIDC.ClientID, "discovery_url", cfg.OIDC.DiscoveryURL)

	return cfg, nil
}
