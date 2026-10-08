package conntest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	SkippedReason string

	Jumphost string

	ConsoleURL             string
	ConsoleConnectionErr   error
	APIServerURL           string
	APIServerConnectionErr error
	OAuthURL               string
	OAuthConnectionErr     error

	Warnings []string
}

func (r Report) HasErrors() bool {
	return r.ConsoleConnectionErr != nil || r.APIServerConnectionErr != nil || r.OAuthConnectionErr != nil
}

func (r Report) Skipped() bool {
	return r.SkippedReason != ""
}

type RoutingDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	JumphostForHost(host string) string
}

// TestClusters tests the connectivity to the API server, console and OAuth endpoint of the given clusters using the provided HTTP client.
// It returns a channel of reports for each cluster.
func TestClusters(r RoutingDialer, clusters []lieutenant.Cluster) iter.Seq[Report] {
	client := httpClient(r.DialContext)

	return func(yield func(Report) bool) {
		for _, cluster := range clusters {
			var report Report
			report.ClusterName = cluster.ID
			if apiURL, _, _ := cluster.ApiURL(); apiURL != "" {
				cadata, _, _ := cluster.ApiCAData()
				report.APIServerURL = apiURL
				report.APIServerConnectionErr = getWithCustomCA(r.DialContext, cadata, apiURL)
				u, err := url.Parse(apiURL)
				if err == nil {
					report.Jumphost = r.JumphostForHost(u.Hostname())
				} else {
					report.Warnings = append(report.Warnings, "Failed to parse API server URL to extract jumphost: "+err.Error())
				}
			} else {
				report.SkippedReason = "No API server URL found in inventory"
				if !yield(report) {
					return
				}
				continue
			}
			if consoleURL, _, _ := cluster.ConsoleURL(); consoleURL != "" {
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

type dialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

// Warning: The [http.Client.Transport] has internal state and should be reused or [http.Client.CloseIdleConnections] should be called.
func httpClient(dc dialContext) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = dc

	return &http.Client{
		Transport: t,
		Timeout:   5 * time.Second,
	}
}

// getWithCustomCA allows an HTTP GET connection test with custom CA.
// Creates a temporary [http.Client] but closes all connections on exit.
func getWithCustomCA(dc dialContext, cadata []byte, apiURL string) error {
	c := httpClient(dc)
	defer c.CloseIdleConnections()

	if len(cadata) != 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(cadata) {
			return fmt.Errorf("Unable to use custom CA, possibly malformed")
		}
		t := c.Transport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
		c.Transport = t
	}

	return get(c, apiURL)
}

func get(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}
