package lieutenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/vshn/kharon/internal/pkg/lieutenant/login"
	"go.uber.org/multierr"
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

func GetClusters(ctx context.Context, apiURL string) ([]Cluster, error) {
	tok := &login.LieutenantTokenSource{
		APIURL: apiURL,
	}
	c := &http.Client{
		Transport: &login.Transport{
			Source: tok,
		},
	}

	res, err := c.Get(apiURL + "/clusters")
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

// JumphostMappingFromClusters creates a mapping from domains to jumphosts based on the provided clusters.
// If an error is returned, the mapping may be incomplete.
func JumphostMappingFromClusters(clusters []Cluster) (map[string]string, error) {
	mapping := make(map[string]string)
	var errs []error
	for _, c := range clusters {
		jumphost, _, err := c.StringFact("jumphost")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get jumphost fact for cluster %s: %w", c.ID, err))
			continue
		}
		if jumphost == "" {
			continue
		}

		baseDomain, _, err := c.DynamicStringFact("openshiftBaseDomain")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftBaseDomain dynamic fact for cluster %s: %w", c.ID, err))
		} else if baseDomain == "" {
			errs = append(errs, fmt.Errorf("cluster %s has jumphost fact but no openshiftBaseDomain dynamic fact", c.ID))
		} else {
			mapping[baseDomain] = jumphost
		}
		if appsDomain, _, err := c.DynamicStringFact("openshiftAppsDomain"); err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftAppsDomain dynamic fact for cluster %s: %w", c.ID, err))
		} else if appsDomain != "" && !hasBaseDomain(appsDomain, baseDomain) {
			mapping[appsDomain] = jumphost
		}
		if apiUrl, _, err := c.DynamicStringFact("openshiftApiURL"); err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftApiURL dynamic fact for cluster %s: %w", c.ID, err))
		} else if apiUrl != "" {
			u, err := url.Parse(apiUrl)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse openshiftApiURL dynamic fact for cluster %s: %w", c.ID, err))
			} else if domain := u.Hostname(); domain != "" && !hasBaseDomain(domain, baseDomain) {
				mapping[domain] = jumphost
			}
		}
		if consoleUrl, _, err := c.DynamicStringFact("openshiftConsoleURL"); err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftConsoleURL dynamic fact for cluster %s: %w", c.ID, err))
		} else if consoleUrl != "" {
			u, err := url.Parse(consoleUrl)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse openshiftConsoleURL dynamic fact for cluster %s: %w", c.ID, err))
			} else if domain := u.Hostname(); domain != "" && !hasBaseDomain(domain, baseDomain) {
				mapping[domain] = jumphost
			}
		}
		if additionalDomains, _, err := c.StringFact("jumphostDomains"); err != nil {
			errs = append(errs, fmt.Errorf("failed to get jumphostDomains fact for cluster %s: %w", c.ID, err))
		} else if additionalDomains != "" {
			for _, domain := range strings.Split(additionalDomains, ",") {
				domain = strings.TrimSpace(domain)
				if domain != "" && !hasBaseDomain(domain, baseDomain) {
					mapping[domain] = jumphost
				}
			}
		}
	}

	return mapping, multierr.Combine(errs...)
}

func hasBaseDomain(domain, base string) bool {
	if base == "" {
		return false
	}
	return domain == base || strings.HasSuffix(domain, "."+base)
}
