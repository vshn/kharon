package lieutenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/minio/pkg/v3/wildcard"
	"k8s.io/apimachinery/pkg/labels"

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

// FindByID searches for a cluster with the given ID in the provided slice of clusters.
func FindByID(clusters []Cluster, id string) (Cluster, bool) {
	for _, cluster := range clusters {
		if cluster.ID == id {
			return cluster, true
		}
	}
	return Cluster{}, false
}

// FindByAPIURL searches for a cluster with the given OpenShift API URL in the provided slice of clusters.
func FindByAPIURL(clusters []Cluster, apiURL string) (Cluster, bool) {
	for _, cluster := range clusters {
		if url, ok, _ := cluster.DynamicStringFact(KnownDynamicFactOpenshiftApiURL); ok && url == apiURL {
			return cluster, true
		}
	}
	return Cluster{}, false
}

// Filter filters the given slice of clusters based on the provided include and exclude patterns, as well as fact selectors.
// An empty includePatterns slice matches everything.
func Filter(clusters []Cluster, includePatterns, excludePatterns []string, factSelector, dynamicFactSelector labels.Selector, predicate func(Cluster) bool) []Cluster {
	filtered := make([]Cluster, 0, len(clusters))
	for _, cluster := range clusters {
		if predicate != nil && !predicate(cluster) {
			continue
		}
		if len(includePatterns) > 0 && !matchesPatterns(cluster.ID, includePatterns) {
			continue
		}
		if matchesPatterns(cluster.ID, excludePatterns) {
			continue
		}
		if matchesSelector(cluster.Facts, factSelector) && matchesSelector(cluster.DynamicFacts, dynamicFactSelector) {
			filtered = append(filtered, cluster)
		}
	}

	return filtered
}

func matchesPatterns(s string, patterns []string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool {
		return wildcard.Match(p, s)
	})
}

func matchesSelector(facts map[string]any, selector labels.Selector) bool {
	labelsSet := make(labels.Set, len(facts))
	for k, v := range facts {
		if str, ok := v.(string); ok {
			labelsSet[k] = str
		}
	}
	return selector.Matches(labelsSet)
}
