package mapping

import (
	"fmt"
	"maps"
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

		baseDomain, clusterDomains, err := c.GetClusterDomains()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get all cluster domains for cluster %s: %w", c.ID, err))
		}
		if baseDomain == "" {
			errs = append(errs, fmt.Errorf("cluster %s has jumphost fact but no base domain dynamic fact", c.ID))
		} else {
			mapping[baseDomain] = jumphost
		}
		// Note(aa): c.getClusterDomains() can return a partial result even if it encounters an error, so we add all returned domains to the mapping.
		for _, domain := range clusterDomains {
			mapping[domain] = jumphost
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
