package lieutenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/vshn/kharon/internal/pkg/lieutenant/login"
)

const (
	KnownDynamicFactOpenshiftApiURL     = "openshiftApiURL"
	KnownDynamicFactOpenshiftConsoleURL = "openshiftConsoleURL"
	KnownDynamicFactOpenshiftBaseDomain = "openshiftBaseDomain"
	KnownDynamicFactOpenshiftAppsDomain = "openshiftAppsDomain"

	KnownFactJumphost            = "jumphost"
	KnownFactJumphostDomains     = "jumphostDomains"
	KnownFactJumphostSkipDomains = "jumphostSkipDomains"
)

type Cluster struct {
	ID           string         `json:"id"`
	DisplayName  string         `json:"displayName"`
	TenantID     string         `json:"tenant"`
	Facts        map[string]any `json:"facts"`
	DynamicFacts map[string]any `json:"dynamicFacts"`
}

func (c Cluster) StringFact(factName string) (string, bool, error) {
	return stringFactFrom(c.Facts, factName)
}

func (c Cluster) DynamicStringFact(factName string) (string, bool, error) {
	return stringFactFrom(c.DynamicFacts, factName)
}

func stringFactFrom(m map[string]any, factName string) (string, bool, error) {
	if value, ok := m[factName]; ok {
		if str, ok := value.(string); ok {
			return str, true, nil
		}
		return "", false, errors.New("fact is not a string")
	}
	return "", false, nil
}

type Client struct {
	apiURL     string
	httpClient *http.Client
}

// NewClient creates a new Client for the Lieutenant API.
// If httpClient is nil, a default client with OIDC authentication will be used.
func NewClient(apiURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &login.Transport{
				Source: &login.LieutenantTokenSource{
					APIURL: apiURL,
				},
			},
		}
	}
	return &Client{
		apiURL:     apiURL,
		httpClient: httpClient,
	}
}

func (c *Client) GetClusters(ctx context.Context) ([]Cluster, error) {
	res, err := c.httpClient.Get(c.apiURL + "/clusters")
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, string(body))
	}

	var clusters []Cluster
	if err := json.NewDecoder(res.Body).Decode(&clusters); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}
	return clusters, nil
}
