package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sync/errgroup"
)

func Test_jumphostChainForTarget(t *testing.T) {
	u := ssh_config.UserSettings{}
	u.ConfigFinder(func() string {
		return filepath.Join("testdata", "jumphosts_config")
	})

	tests := []struct {
		name            string
		host            string
		want            []string
		wantErrMatching string
	}{
		{
			name: "No jumphosts",
			host: "no-jumphosts",
			want: []string{"no-jumphosts"},
		},
		{
			name: "chain using ProxyJump",
			host: "chain.1.target",
			want: []string{"chain1.3", "chain1.2", "chain.1.target"},
		},
		{
			name: "chain using ProxyJump",
			host: "chain.2.target",
			want: []string{"chain2.2", "chain.2.target"},
		},
		{
			name: "chain using ProxyCommand",
			host: "chain.proxycommand.target",
			want: []string{"chain.proxycommand.4", "chain.proxycommand.3", "chain.proxycommand.2", "chain.proxycommand.target"},
		},
		{
			name:            "circular jumps",
			host:            "circular.target",
			wantErrMatching: "circular ProxyJump detected",
		},
		{
			name:            "unknown proxycommand",
			host:            "unknown.proxycommand",
			wantErrMatching: "error parsing ProxyCommand for host unknown.proxycommand: unexpected ProxyCommand format",
		},
		{
			name:            "multiple ProxyJump entries",
			host:            "multiple.proxyjump",
			wantErrMatching: "multiple ProxyJump entries for host multiple.proxyjump are not supported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jumphostChainForTarget(&u, tt.host)
			if tt.wantErrMatching != "" {
				assert.ErrorContains(t, err, tt.wantErrMatching)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_loadHostnameMapping(t *testing.T) {
	loaded, err := loadHostnameMapping(filepath.Join("testdata", "mapping.json"))
	require.NoError(t, err)
	assert.Equal(t, []hostSuffixJumphostMapping{
		{HostSuffix: "api.c-bettersmarter-prod01.vshnmanaged.net", Jumphost: "jumphost2"},
		{HostSuffix: "c-bettersmarter-prod01.vshnmanaged.net", Jumphost: "jumphost1"},
		{HostSuffix: "a.storage.bettersmarter.ch", Jumphost: "jumphost4"},
		{HostSuffix: "b.storage.bettersmarter.ch", Jumphost: "jumphost5"},
		{HostSuffix: "c.storage.bettersmarter.ch", Jumphost: "jumphost6"},
		{HostSuffix: "vcenter.bettersmarter.ch", Jumphost: "jumphost3"},
	}, loaded)
}

func Test_Start(t *testing.T) {
	u := &ssh_config.UserSettings{}
	u.ConfigFinder(func() string {
		return filepath.Join("testdata", "jumphosts_config")
	})
	userPubKey, agentSocket := spawnSSHAgent(t)
	t.Logf("Spawned SSH agent with public key %x at socket %s", userPubKey, agentSocket)
	t.Setenv("SSH_AUTH_SOCK", agentSocket)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("X-Request-Host", r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer httpServer.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	proxyPort, err := freePort()
	require.NoError(t, err, "failed to find free port for proxy")
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	wg, wgCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return Start(wgCtx, proxyAddr, "testdata/mapping.json", u)
	})

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return url.Parse("socks5://" + proxyAddr)
	}
	client := &http.Client{
		Transport: transport,
	}
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		resp, err := client.Get(httpServer.URL)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}, 5*time.Second, 100*time.Millisecond, "proxy did not start in time")

	cancel()

	require.NoError(t, wg.Wait())
}

// freePort returns a free port on the host.
func freePort() (int, error) {
	a, err := net.ResolveTCPAddr("tcp", ":0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", a)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// spawnSSHAgent generates an ed25519 key pair, adds it to an in-memory SSH
// agent, and serves the agent on a temporary Unix socket.
// It returns the public key and the path to the socket.
// The agent is shut down and the socket removed when the test ends.
func spawnSSHAgent(t *testing.T) (pub ed25519.PublicKey, socketPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	ag := agent.NewKeyring()

	require.NoError(t, ag.Add(agent.AddedKey{PrivateKey: priv}))

	tmp := t.TempDir()
	socketPath = tmp + "/agent.sock"
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err, "spawnSSHAgent: listen on unix socket")

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(ag, conn)
		}
	}()

	t.Cleanup(func() {
		require.NoError(t, ln.Close())
		require.NoError(t, os.RemoveAll(tmp))
	})

	return pub, socketPath
}
