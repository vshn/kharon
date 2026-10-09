package conntest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vshn/kharon/v2/internal/pkg/conntest"
	"github.com/vshn/kharon/v2/internal/pkg/lieutenant"
)

func Test_TestClusters(t *testing.T) {
	var customCAServCalled atomic.Int32
	defer func() {
		require.Greater(t, customCAServCalled.Load(), int32(0))
	}()

	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer serv.Close()

	customCAServ := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customCAServCalled.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer customCAServ.Close()

	var customCA bytes.Buffer
	pem.Encode(base64.NewEncoder(base64.StdEncoding, &customCA), &pem.Block{Type: "CERTIFICATE", Bytes: customCAServ.TLS.Certificates[0].Certificate[0]})

	dialer := mockDialer{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, net.UnknownNetworkError(network)
			}
			if address == "api-talos-custom-ca.example.com:443" {
				return net.Dial(network, customCAServ.Listener.Addr().String())
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
				"openshiftApiURL": "http://foo.com/?foo\nbar",
			},
		},
		{
			ID: "cluster1",
			DynamicFacts: map[string]any{
				"openshiftApiURL":     "http://api.cluster1.example.com",
				"openshiftConsoleURL": "http://console.cluster1.example.com",
				"openshiftOAuthRoute": "oauth.cluster1.example.com",
			},
		},
		{
			ID: "cluster2",
			DynamicFacts: map[string]any{
				"openshiftApiURL": "http://api.cluster2.example.com",
			},
		},
		{
			ID: "talos-1",
			DynamicFacts: map[string]any{
				"talosApiURL": "http://api.talos1.example.com",
			},
		},
		{
			ID: "talos-invalid-custom-ca",
			DynamicFacts: map[string]any{
				"talosApiURL":                      "http://api.talos-invalid-custom-ca.example.com",
				"talosAPICertificateAuthorityData": "Rk9PQkFSCg==",
			},
		},
		{
			ID: "talos-custom-ca",
			DynamicFacts: map[string]any{
				"talosApiURL":                      "https://api-talos-custom-ca.example.com",
				"talosAPICertificateAuthorityData": customCA.String(),
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
		{
			ClusterName:            "talos-1",
			Jumphost:               "jumphost-for-api.talos1.example.com",
			APIServerURL:           "http://api.talos1.example.com",
			APIServerConnectionErr: nil,
		},
		{
			ClusterName:            "talos-invalid-custom-ca",
			Jumphost:               "jumphost-for-api.talos-invalid-custom-ca.example.com",
			APIServerURL:           "http://api.talos-invalid-custom-ca.example.com",
			APIServerConnectionErr: errors.New("Unable to use custom CA, possibly malformed"),
		},
		{
			ClusterName:  "talos-custom-ca",
			Jumphost:     "jumphost-for-api-talos-custom-ca.example.com",
			APIServerURL: "https://api-talos-custom-ca.example.com",
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
