package ocptoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	errForbidden     = fmt.Errorf("access forbidden")
	tokenRequestFunc = tokenrequest.RequestTokenWithLocalCallback
)

// EnsureToken checks if the provided token is valid and not expiring soon.
// If the token is valid, it returns the token.
// If the token is invalid or expiring soon, it requests a new token using the provided API URL and Identity Provider (IDP) name.
// If the token is empty, it will attempt to retrieve a cached token for the given API URL before checking its validity.
func EnsureToken(ctx context.Context, token, apiURL, idp string) (string, error) {
	if token == "" {
		cachedToken, err := cache.GetToken(apiURL)
		if err != nil {
			return "", fmt.Errorf("failed to get cached token: %w", err)
		}
		if cachedToken != "" {
			slog.Debug("Found cached token, checking validity", "api_url", apiURL)
		}
		token = cachedToken
	}
	if token != "" {
		cfg := &rest.Config{
			Host:        apiURL,
			BearerToken: token,
		}
		expiry, err := getTokenExpiry(ctx, cfg, token)
		if err != nil && errors.Is(err, errForbidden) {
			slog.Debug("Can't determine token expiry because access is forbidden. Falling back to SSR.", "error", err)
			ok, ssrErr := lightSSR(ctx, cfg)
			if ssrErr != nil {
				return "", fmt.Errorf("failed to perform SelfSubjectReview: %w", ssrErr)
			}
			if ok {
				return token, nil
			}
		} else if err != nil {
			return "", fmt.Errorf("failed to get token expiry: %w", err)
		} else if expiry > time.Hour {
			return token, nil
		}
	}
	return requestToken(ctx, apiURL, idp)
}

func getTokenExpiry(ctx context.Context, cfg *rest.Config, token string) (time.Duration, error) {
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
		return 0, fmt.Errorf("failed to create HTTP client for kubeconfig: %w", err)
	}
	url, _, err := rest.DefaultServerUrlFor(cfg)
	if err != nil {
		return 0, fmt.Errorf("failed to determine API server URL from kubeconfig: %w", err)
	}
	url.Path = "/apis/oauth.openshift.io/v1/oauthaccesstokens/" + tokenName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Impersonate-User", "system:admin")
	resp, err := c.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return 0, errForbidden
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
			return 0, nil
		}
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, fmt.Errorf("failed to decode response body: %w", err)
	}

	expiry := time.Until(r.Metadata.CreationTimestamp.Add(time.Duration(r.ExpiresIn) * time.Second))
	return expiry, nil
}

// Including the openshift or kubenetes client more than doubles the size of the binary, so we implement a very minimal version of the SelfSubjectReview API call.
func lightSSR(ctx context.Context, cfg *rest.Config) (ok bool, err error) {
	c, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP client for kubeconfig: %w", err)
	}
	url, _, err := rest.DefaultServerUrlFor(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to determine API server URL from kubeconfig: %w", err)
	}
	url.Path = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), strings.NewReader(`{"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1"}`))
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusCreated {
		return true, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return false, nil
	}
	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
}

func requestToken(ctx context.Context, apiURL, idp string) (string, error) {
	tok, err := tokenRequestFunc(&rest.Config{
		Host: apiURL,
	}, func(url *url.URL) error {
		if idp != "" {
			q := url.Query()
			q.Set("idp", idp)
			url.RawQuery = q.Encode()
		}
		return browser.OpenURL(ctx, url.String())
	}, 0)
	if err != nil {
		return "", err
	}
	if err := cache.WriteToken(apiURL, tok); err != nil {
		slog.Warn("Failed to cache token", "error", err)
	}
	return tok, nil
}
