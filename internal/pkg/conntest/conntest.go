package conntest

import (
	"context"
	"io"
	"iter"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

type Report struct {
	ClusterName string

	Jumphost string

	ConsoleURL             string
	ConsoleConnectionErr   error
	APIServerURL           string
	APIServerConnectionErr error
	OAuthURL               string
	OAuthConnectionErr     error

	Warnings []string
}

type RoutingDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	JumphostForHost(host string) string
}

func (r Report) HasErrors() bool {
	return r.ConsoleConnectionErr != nil || r.APIServerConnectionErr != nil || r.OAuthConnectionErr != nil
}

// TestClusters tests the connectivity to the API server, console and OAuth endpoint of the given clusters using the provided HTTP client.
// It returns a channel of reports for each cluster.
func TestClusters(r RoutingDialer, clusters []lieutenant.Cluster) iter.Seq[Report] {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = r.DialContext

	client := &http.Client{
		Transport: t,
		Timeout:   5 * time.Second,
	}
	return func(yield func(Report) bool) {
		for _, cluster := range clusters {
			var report Report
			report.ClusterName = cluster.ID
			if apiURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL); apiURL != "" {
				report.APIServerURL = apiURL
				report.APIServerConnectionErr = get(client, apiURL)
				u, err := url.Parse(apiURL)
				if err == nil {
					report.Jumphost = r.JumphostForHost(u.Hostname())
				} else {
					report.Warnings = append(report.Warnings, "Failed to parse API server URL to extract jumphost: "+err.Error())
				}
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
