package lieutenant

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/minio/pkg/v3/wildcard"
	"go.uber.org/multierr"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/vshn/kharon/internal/pkg/lieutenant/login"
)

const (
	knownDynamicFactOpenshiftApiURL     = "openshiftApiURL"
	knownDynamicFactOpenshiftConsoleURL = "openshiftConsoleURL"
	knownDynamicFactOpenshiftBaseDomain = "openshiftBaseDomain"
	knownDynamicFactOpenshiftAppsDomain = "openshiftAppsDomain"

	knownDynamicFactTalosApiURL     = "talosApiURL"
	knownDynamicFactTalosBaseDomain = "talosBaseDomain"
	knownDynamicFactTalosAppsDomain = "talosAppsDomain"
	knownDynamicFactTalosCAData     = "talosAPICertificateAuthorityData"

	knownDynamicFactOidcClientId = "oidcClientId"
	knownDynamicFactOidcIssuer   = "oidcIssuer"

	knownFactDistribution = "distribution"

	KnownFactJumphost            = "jumphost"
	KnownFactJumphostDomains     = "jumphostDomains"
	KnownFactJumphostSkipDomains = "jumphostSkipDomains"

	DistributionOpenshift = "openshift"
	DistributionTalos     = "talos"
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

func (c Cluster) Distribution() (string, bool, error) {
	dist, ok, err := c.StringFact(knownFactDistribution)
	if err != nil {
		return dist, ok, err
	}
	if dist == "oke" || dist == "openshift4" {
		return DistributionOpenshift, ok, err
	}
	return dist, ok, err
}

func (c Cluster) GetApiURL() (string, bool, error) {
	val, ok, err := c.DynamicStringFact(knownDynamicFactOpenshiftApiURL)
	if ok || err != nil {
		return val, ok, err
	}
	return c.DynamicStringFact(knownDynamicFactTalosApiURL)
}

func (c Cluster) ConsoleURL() (string, bool, error) {
	return c.DynamicStringFact(knownDynamicFactOpenshiftConsoleURL)
}

func (c Cluster) CAData() ([]byte, bool, error) {
	data, ok, err := c.DynamicStringFact(knownDynamicFactTalosCAData)
	if err != nil {
		return nil, ok, err
	}
	decoded, err := base64.StdEncoding.DecodeString(data)
	return decoded, ok, err
}

func (c Cluster) OIDCClientId() (string, bool, error) {
	dist, ok, err := c.Distribution()
	switch dist {
	case DistributionTalos:
		client, ok, err := c.DynamicStringFact(knownDynamicFactOidcClientId)
		if err != nil {
			return "", false, fmt.Errorf("unable to determine OIDC client ID from fact for cluster %s: %w", c.ID, err)
		}
		if !ok {
			return "", false, fmt.Errorf("cluster %s does not contain dynamic fact %s.", c.ID, knownDynamicFactOidcClientId)
		}
		return client, ok, err
	default:
		return "", ok, err
	}
}

func (c Cluster) OIDCIssuer() (string, bool, error) {
	dist, ok, err := c.Distribution()
	switch dist {
	case DistributionTalos:
		issuer, ok, err := c.DynamicStringFact(knownDynamicFactOidcIssuer)
		if err != nil {
			return "", false, fmt.Errorf("unable to determine OIDC issuer from fact for cluster %s: %w", c.ID, err)
		}
		if !ok {
			return "", false, fmt.Errorf("cluster %s does not contain dynamic fact %s.", c.ID, knownDynamicFactOidcIssuer)
		}
		return issuer, ok, err
	default:
		return "", ok, err
	}
}

func (c Cluster) ClusterDomains() (string, []string, error) {
	var domains []string
	var errs []error
	var baseDomainFact string
	var extraDomainFacts []string
	var extraUrlFacts []string

	dist, _, _ := c.Distribution()
	switch dist {
	case DistributionOpenshift:
		baseDomainFact = knownDynamicFactOpenshiftBaseDomain
		extraDomainFacts = []string{
			knownDynamicFactOpenshiftAppsDomain,
		}
		extraUrlFacts = []string{
			knownDynamicFactOpenshiftApiURL,
			knownDynamicFactOpenshiftConsoleURL,
		}
	case DistributionTalos:
		baseDomainFact = knownDynamicFactTalosBaseDomain
		extraDomainFacts = []string{
			knownDynamicFactTalosAppsDomain,
		}
		extraUrlFacts = []string{
			knownDynamicFactTalosApiURL,
		}
	default:
		return "", []string{}, nil
	}
	baseDomain, _, err := c.DynamicStringFact(baseDomainFact)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to get base domain dynamic fact for cluster %s: %w", c.ID, err))
	}

	for _, extraDomainFact := range extraDomainFacts {
		if extraDomain, _, err := c.DynamicStringFact(extraDomainFact); err != nil {
			errs = append(errs, fmt.Errorf("failed to get %s dynamic fact for cluster %s: %w", extraDomainFact, c.ID, err))
		} else if extraDomain != "" && !hasBaseDomain(extraDomain, baseDomain) {
			domains = append(domains, extraDomain)
		}
	}
	for _, extraUrlFact := range extraUrlFacts {
		if extraUrl, _, err := c.DynamicStringFact(extraUrlFact); err != nil {
			errs = append(errs, fmt.Errorf("failed to get %s dynamic fact for cluster %s: %w", extraUrlFact, c.ID, err))
		} else if extraUrl != "" {
			u, err := url.Parse(extraUrl)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse %s dynamic fact for cluster %s: %w", extraUrlFact, c.ID, err))
			} else if domain := u.Hostname(); domain != "" && !hasBaseDomain(domain, baseDomain) {
				domains = append(domains, domain)
			}
		}
	}
	return baseDomain, domains, multierr.Combine(errs...)

}

func (c Cluster) UseOIDC() bool {
	dist, _, _ := c.Distribution()
	return dist == DistributionTalos
}

func hasBaseDomain(domain, base string) bool {
	if base == "" {
		return false
	}
	return domain == base || strings.HasSuffix(domain, "."+base)
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

func (c *Client) Clusters(ctx context.Context) ([]Cluster, error) {
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
		if url, ok, _ := cluster.GetApiURL(); ok && url == apiURL {
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
