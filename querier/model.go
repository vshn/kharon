package main

import "errors"

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
