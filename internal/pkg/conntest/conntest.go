package conntest

import (
	"io"
	"iter"
	"net/http"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

type Report struct {
	ClusterName string

	ConsoleURL             string
	ConsoleConnectionErr   error
	APIServerURL           string
	APIServerConnectionErr error
	OAuthURL               string
	OAuthConnectionErr     error
}

func (r Report) HasErrors() bool {
	return r.ConsoleConnectionErr != nil || r.APIServerConnectionErr != nil || r.OAuthConnectionErr != nil
}

// TestClusters tests the connectivity to the API server, console and OAuth endpoint of the given clusters using the provided HTTP client.
// It returns a channel of reports for each cluster.
func TestClusters(client *http.Client, clusters []lieutenant.Cluster) iter.Seq[Report] {
	return func(yield func(Report) bool) {
		for _, cluster := range clusters {
			var report Report
			report.ClusterName = cluster.ID
			if apiURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL); apiURL != "" {
				report.APIServerURL = apiURL
				report.APIServerConnectionErr = get(client, apiURL)
			} else {
				// If there's no API URL there's no point in testing the cluster further
				continue
			}
			if consoleURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftConsoleURL); consoleURL != "" {
				report.ConsoleURL = consoleURL
				report.ConsoleConnectionErr = get(client, consoleURL)
			}
			if oauthRoute, _, _ := cluster.DynamicStringFact("openshiftOAuthRoute"); oauthRoute != "" {
				report.OAuthURL = "https://" + oauthRoute
				report.OAuthConnectionErr = get(client, report.OAuthURL)
			}
			if !yield(report) {
				return
			}
		}
	}
}

func get(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}
