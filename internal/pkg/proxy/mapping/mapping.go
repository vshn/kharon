package mapping

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"go.uber.org/multierr"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

type JumphostMapping struct {
	DomainToJumphost    map[string]string
	DirectAccessDomains []string
}

// JumphostMappingFromClusters creates a mapping from domains to jumphosts based on the provided clusters.
// If an error is returned, the mapping may be incomplete.
func JumphostMappingFromClusters(clusters []lieutenant.Cluster) (JumphostMapping, error) {
	mapping := make(map[string]string)
	directDomains := make(map[string]struct{})
	var errs []error
	for _, c := range clusters {
		jumphost, _, err := c.StringFact(lieutenant.KnownFactJumphost)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get jumphost fact for cluster %s: %w", c.ID, err))
			continue
		}
		if jumphost == "" {
			continue
		}

		direct, _, err := c.StringFact(lieutenant.KnownFactJumphostSkipDomains)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get jumphostSkipDomains fact for cluster %s: %w", c.ID, err))
		} else if direct != "" {
			for domain := range strings.SplitSeq(direct, ",") {
				domain = strings.TrimSpace(domain)
				if domain != "" {
					directDomains[domain] = struct{}{}
				}
			}
		}

		baseDomain, _, err := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftBaseDomain)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftBaseDomain dynamic fact for cluster %s: %w", c.ID, err))
		} else if baseDomain == "" {
			errs = append(errs, fmt.Errorf("cluster %s has jumphost fact but no openshiftBaseDomain dynamic fact", c.ID))
		} else {
			mapping[baseDomain] = jumphost
		}
		if appsDomain, _, err := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftAppsDomain); err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftAppsDomain dynamic fact for cluster %s: %w", c.ID, err))
		} else if appsDomain != "" && !hasBaseDomain(appsDomain, baseDomain) {
			mapping[appsDomain] = jumphost
		}
		if apiUrl, _, err := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL); err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftApiURL dynamic fact for cluster %s: %w", c.ID, err))
		} else if apiUrl != "" {
			u, err := url.Parse(apiUrl)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse openshiftApiURL dynamic fact for cluster %s: %w", c.ID, err))
			} else if domain := u.Hostname(); domain != "" && !hasBaseDomain(domain, baseDomain) {
				mapping[domain] = jumphost
			}
		}
		if consoleUrl, _, err := c.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL); err != nil {
			errs = append(errs, fmt.Errorf("failed to get openshiftConsoleURL dynamic fact for cluster %s: %w", c.ID, err))
		} else if consoleUrl != "" {
			u, err := url.Parse(consoleUrl)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to parse openshiftConsoleURL dynamic fact for cluster %s: %w", c.ID, err))
			} else if domain := u.Hostname(); domain != "" && !hasBaseDomain(domain, baseDomain) {
				mapping[domain] = jumphost
			}
		}
		if additionalDomains, _, err := c.StringFact(lieutenant.KnownFactJumphostDomains); err != nil {
			errs = append(errs, fmt.Errorf("failed to get jumphostDomains fact for cluster %s: %w", c.ID, err))
		} else if additionalDomains != "" {
			for domain := range strings.SplitSeq(additionalDomains, ",") {
				domain = strings.TrimSpace(domain)
				if domain != "" && !hasBaseDomain(domain, baseDomain) {
					mapping[domain] = jumphost
				}
			}
		}
	}

	dm := slices.Collect(maps.Keys(directDomains))
	slices.Sort(dm)
	return JumphostMapping{
		DomainToJumphost:    mapping,
		DirectAccessDomains: dm,
	}, multierr.Combine(errs...)
}

func hasBaseDomain(domain, base string) bool {
	if base == "" {
		return false
	}
	return domain == base || strings.HasSuffix(domain, "."+base)
}
