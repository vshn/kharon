package conntest_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vshn/kharon/internal/pkg/conntest"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func Test_TestClusters(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer serv.Close()

	dialer := mockDialer{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, net.UnknownNetworkError(network)
			}
			return net.Dial(network, serv.Listener.Addr().String())
		},
	}

	reports := slices.Collect(conntest.TestClusters(dialer, []lieutenant.Cluster{
		{
			ID: "no-api-url",
		},
		{
			ID: "invalid",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "http://foo.com/?foo\nbar",
			},
		},
		{
			ID: "cluster1",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL:     "http://api.cluster1.example.com",
				lieutenant.KnownDynamicFactOpenshiftConsoleURL: "http://console.cluster1.example.com",
				"openshiftOAuthRoute":                          "oauth.cluster1.example.com",
			},
		},
		{
			ID: "cluster2",
			DynamicFacts: map[string]any{
				lieutenant.KnownDynamicFactOpenshiftApiURL: "http://api.cluster2.example.com",
			},
		},
	}))

	assert.Equal(t, []conntest.Report{
		{
			ClusterName:   "no-api-url",
			SkippedReason: "No API server URL found in inventory",
		},
		{
			ClusterName:  "invalid",
			APIServerURL: "http://foo.com/?foo\nbar",
			APIServerConnectionErr: &url.Error{
				Op:  "parse",
				URL: "http://foo.com/?foo\nbar",
				Err: errors.New("net/url: invalid control character in URL"),
			},
			Warnings: []string{"Failed to parse API server URL to extract jumphost: parse \"http://foo.com/?foo\\nbar\": net/url: invalid control character in URL"},
		},
		{
			ClusterName:            "cluster1",
			Jumphost:               "jumphost-for-api.cluster1.example.com",
			ConsoleURL:             "http://console.cluster1.example.com",
			ConsoleConnectionErr:   nil,
			APIServerURL:           "http://api.cluster1.example.com",
			APIServerConnectionErr: nil,
			OAuthURL:               "https://oauth.cluster1.example.com",
			OAuthConnectionErr:     &url.Error{Op: "Get", URL: "https://oauth.cluster1.example.com", Err: errors.New("http: server gave HTTP response to HTTPS client")},
		},
		{
			ClusterName:            "cluster2",
			Jumphost:               "jumphost-for-api.cluster2.example.com",
			APIServerURL:           "http://api.cluster2.example.com",
			APIServerConnectionErr: nil,
		},
	}, reports)
}

func Test_Report_HasErrors(t *testing.T) {
	assert.True(t, conntest.Report{
		APIServerConnectionErr: errors.New("error"),
		ConsoleConnectionErr:   nil,
		OAuthConnectionErr:     nil,
	}.HasErrors())
	assert.True(t, conntest.Report{
		APIServerConnectionErr: nil,
		ConsoleConnectionErr:   errors.New("error"),
		OAuthConnectionErr:     nil,
	}.HasErrors())
	assert.True(t, conntest.Report{
		APIServerConnectionErr: nil,
		ConsoleConnectionErr:   nil,
		OAuthConnectionErr:     errors.New("error"),
	}.HasErrors())
	assert.False(t, conntest.Report{
		APIServerConnectionErr: nil,
		ConsoleConnectionErr:   nil,
		OAuthConnectionErr:     nil,
	}.HasErrors())
}

func Test_Report_Skipped(t *testing.T) {
	assert.True(t, conntest.Report{
		SkippedReason: "reason",
	}.Skipped())
	assert.False(t, conntest.Report{
		SkippedReason: "",
	}.Skipped())
}

type mockDialer struct {
	dialer func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.dialer != nil {
		return d.dialer(ctx, network, address)
	}
	return nil, nil
}

func (d mockDialer) JumphostForHost(host string) string {
	return "jumphost-for-" + host
}
