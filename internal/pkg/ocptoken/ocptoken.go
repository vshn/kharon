package ocptoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/oauth/tokenrequest"
	"k8s.io/client-go/rest"

	"github.com/vshn/kharon/internal/pkg/browser"
	"github.com/vshn/kharon/internal/pkg/cache"
)

var (
	tokenRequestFunc = tokenrequest.RequestTokenWithLocalCallback
)

// VerifyToken checks if the provided token is valid and not expiring soon.
// The check runs against the API Server.
func VerifyToken(ctx context.Context, token, apiURL string) (ok bool, err error) {
	if token == "" {
		return false, err
	}
	cfg := &rest.Config{
		Host:        apiURL,
		BearerToken: token,
	}
	expiry, err := getTokenExpiry(ctx, cfg, token)
	if err != nil {
		return false, fmt.Errorf("failed to get token expiry: %w", err)
	} else if expiresSoon(expiry) {
		return false, nil
	}
	return true, nil
}

// Token returns a non-expired token from cache or the API Server.
func Token(ctx context.Context, apiURL, idp string) (string, time.Time, error) {
	cachedToken, err := cache.GetToken(apiURL)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get cached token: %w", err)
	}
	if cachedToken != (cache.Entry{}) && !expiresSoon(cachedToken.Expiry) {
		slog.Debug("Found valid cached token", "api_url", apiURL, "expiry", cachedToken.Expiry)
		return cachedToken.Token, cachedToken.Expiry, nil
	}

	return requestToken(ctx, apiURL, idp)
}

func getTokenExpiry(ctx context.Context, cfg *rest.Config, token string) (time.Time, error) {
	const sha256Prefix = "sha256~"

	type response struct {
		Metadata struct {
			CreationTimestamp time.Time `json:"creationTimestamp"`
		} `json:"metadata"`
		ExpiresIn int `json:"expiresIn"`
	}

	withoutPrefix := strings.TrimPrefix(token, sha256Prefix)
	h := sha256.Sum256([]byte(withoutPrefix))
	tokenName := sha256Prefix + base64.RawURLEncoding.EncodeToString(h[:])

	c, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create HTTP client for kubeconfig: %w", err)
	}
	url, _, err := rest.DefaultServerUrlFor(cfg)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to determine API server URL from kubeconfig: %w", err)
	}
	url.Path = "/apis/oauth.openshift.io/v1/useroauthaccesstokens/" + tokenName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			slog.Warn("token not authorized")
			return time.Time{}, nil
		}
		body, _ := io.ReadAll(resp.Body)
		return time.Time{}, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return time.Time{}, fmt.Errorf("failed to decode response body: %w", err)
	}

	return r.Metadata.CreationTimestamp.Add(time.Duration(r.ExpiresIn) * time.Second), nil
}

func requestToken(ctx context.Context, apiURL, idp string) (string, time.Time, error) {
	tok, err := tokenRequestFunc(&rest.Config{
		Host: apiURL,
	}, func(url *url.URL) error {
		if idp != "" {
			q := url.Query()
			q.Set("idp", idp)
			url.RawQuery = q.Encode()
		}
		// TODO(bastjan) All output on Stderr to not interfere with token output.
		// Branch `integrate-kubelogin` already has preparation for that.
		return browser.OpenURL(ctx, url.String())
	}, 0)
	if err != nil {
		return "", time.Time{}, err
	}
	expiry, err := getTokenExpiry(ctx, &rest.Config{
		Host:        apiURL,
		BearerToken: tok,
	}, tok)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get expiry for newly created token: %w", err)
	}
	if expiresSoon(expiry) {
		return "", time.Time{}, fmt.Errorf("newly created token expires too soon at %s", expiry.Format(time.RFC3339))
	}
	if err := cache.WriteToken(apiURL, cache.Entry{
		Expiry: expiry,
		Token:  tok,
	}); err != nil {
		slog.Warn("Failed to cache token", "error", err)
	}
	return tok, expiry, nil
}

func expiresSoon(expiry time.Time) bool {
	return time.Until(expiry) <= time.Hour
}
