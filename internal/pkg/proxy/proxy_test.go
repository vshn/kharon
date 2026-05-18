package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/foxcpp/go-mockdns"
	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/errgroup"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/proxy/mapping"
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
	path := filepath.Join(t.TempDir(), "mapping.json")
	require.NoError(t, cache.WriteProxyMappingFile(path, mapping.JumphostMapping{
		DomainToJumphost: map[string]string{
			"c-bettersmarter-prod01.vshnmanaged.net":     "jumphost1",
			"a.storage.bettersmarter.ch":                 "jumphost4",
			"api.c-bettersmarter-prod01.vshnmanaged.net": "jumphost2",
			"vcenter.bettersmarter.ch":                   "jumphost3",
			"b.storage.bettersmarter.ch":                 "jumphost5",
			"c.storage.bettersmarter.ch":                 "jumphost6",
		},
	}))

	loaded, err := loadHostnameMapping(path)
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
	ev := eventuallyDefaults{waitFor: 5 * time.Second, interval: 100 * time.Millisecond}

	userPubKey, agentSocket := spawnSSHAgent(t)
	t.Logf("Spawned SSH agent with public key %x at socket %s", userPubKey, agentSocket)

	localDNSResolver := localhostResolverFor(t, "no.hop", "one.hop", "sub.always.direct", "sub.sub.always.direct")
	dmz2DNSResolver := localhostResolverFor(t, "two.hops", "jumphost3")
	dmz3DNSResolver := localhostResolverFor(t, "three.hops")
	dmz4DNSResolver := localhostResolverFor(t, "after.reload")

	allowedPubKey, err := ssh.NewPublicKey(userPubKey)
	require.NoError(t, err)
	jumpHost1 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: localDNSResolver})
	jumpHost2 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: dmz2DNSResolver})
	jumpHost3 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: dmz3DNSResolver})
	jumpHost4 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: dmz4DNSResolver})
	knownHostsPath := writeKnownHostsFile(t, knownHostEntry{
		hostname: "127.0.0.1",
		port:     jumpHost1.Port(),
		hostKey:  jumpHost1.HostKey(),
	}, knownHostEntry{
		hostname: "jumphost2",
		port:     jumpHost2.Port(),
		hostKey:  jumpHost2.HostKey(),
	}, knownHostEntry{
		hostname: "jumphost3",
		port:     jumpHost3.Port(),
		hostKey:  jumpHost3.HostKey(),
	}, knownHostEntry{
		hostname: "jumphost4",
		port:     jumpHost4.Port(),
		hostKey:  jumpHost4.HostKey(),
	})

	mappingPath := filepath.Join(t.TempDir(), "mapping.json")
	require.NoError(t, cache.WriteProxyMappingFile(mappingPath, mapping.JumphostMapping{
		DirectAccessDomains: []string{"sub.always.direct"},
		DomainToJumphost: map[string]string{
			"one.hop":       "jumphost1",
			"two.hops":      "jumphost2",
			"three.hops":    "jumphost3",
			"error.hop":     "nonexistent.jumphost",
			"always.direct": "jumphost3",
		},
	}), "failed to update hostname mapping")

	sshConfigPath := filepath.Join(t.TempDir(), "ssh_config")
	b := sshConfigBuilder{
		{
			Block: "Host *",
			Options: map[string]string{
				"IdentityAgent":      agentSocket,
				"UserKnownHostsFile": knownHostsPath,
				"User":               "test",
			},
		},
		{
			Block: "Host jumphost1",
			Options: map[string]string{
				"HostName": "127.0.0.1",
				"Port":     fmt.Sprintf("%d", jumpHost1.Port()),
			},
		},
		{
			Block: "Host jumphost2",
			Options: map[string]string{
				"HostName":     "127.0.0.1",
				"HostKeyAlias": "jumphost2",
				"ProxyJump":    "jumphost1",
				"Port":         strconv.Itoa(jumpHost2.Port()),
			},
		},
		{
			Block: "Host jumphost3",
			Options: map[string]string{
				"ProxyJump": "jumphost2",
				"Port":      strconv.Itoa(jumpHost3.Port()),
			},
		},
	}
	require.NoError(t, os.WriteFile(sshConfigPath, []byte(b.String()), 0o600))

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("X-Request-Host", r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer httpServer.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p := Proxy{
		SSHConfig: func() *ssh_config.UserSettings {
			u := &ssh_config.UserSettings{}
			u.ConfigFinder(func() string {
				return sshConfigPath
			})
			return u
		},
		DirectDialer: net.Dialer{
			Resolver: localDNSResolver,
		},
		KeepAliveInterval: 100 * time.Millisecond,
	}
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := pl.Addr().String()
	require.NoError(t, err, "failed to listen for proxy")
	wg, wgCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return p.Start(wgCtx, func() (net.Listener, error) { return pl, nil }, mappingPath)
	})

	httpClient := newHTTPClient(proxyAddr, httpServer.Listener.Addr().(*net.TCPAddr).Port)
	ev.requireEventuallyWithT(t, func(t *assert.CollectT) {
		httpClient.RequireSuccessfulGet(t, "http://no.hop")
	}, "proxy did not start in time")

	for _, domain := range []string{"sub.always.direct", "sub.sub.always.direct", "no.hop", "one.hop", "two.hops", "three.hops"} {
		httpClient.RequireSuccessfulGet(t, fmt.Sprintf("http://%s", domain))
	}

	ev.requireEventuallyWithT(t, func(t *assert.CollectT) {
		assert.GreaterOrEqual(t, jumpHost1.KeepAliveCount(), uint64(1), "expected at least 1 keep-alive request to jumpHost1")
		assert.GreaterOrEqual(t, jumpHost2.KeepAliveCount(), uint64(1), "expected at least 1 keep-alive request to jumpHost2")
		assert.GreaterOrEqual(t, jumpHost3.KeepAliveCount(), uint64(1), "expected at least 1 keep-alive request to jumpHost3")
	}, "keep-alive requests were not received in time")

	require.GreaterOrEqual(t, jumpHost3.AuthenticatedConnections(), int64(1), "precondition failed: expected at least 1 authenticated connection to jumpHost3")
	jumpHost3.BlockKeepAlives()

	ev.requireEventuallyWithT(t, func(t *assert.CollectT) {
		assert.Equal(t, int64(0), jumpHost3.AuthenticatedConnections())
	}, "expected no authenticated connections to jumpHost3 after blocking keep-alives")

	jumpHost3.UnblockKeepAlives()
	ev.requireEventuallyWithT(t, func(t *assert.CollectT) {
		httpClient.RequireSuccessfulGet(t, "http://three.hops")
	}, "expected to be able to connect to three.hops again after unblocking keep-alives")

	{
		fr := httpClient.RequireNewRequest(t, http.MethodGet, "http://error.hop", nil)
		_, err := httpClient.client.Do(fr)
		require.Error(t, err, "expected request to error.hop to fail before adding jumphost4 and reloading proxy")
	}

	{
		fr := httpClient.RequireNewRequest(t, http.MethodGet, "http://after.reload", nil)
		_, err := httpClient.client.Do(fr)
		require.Error(t, err, "expected request to after.reload to fail before adding jumphost4 and reloading proxy")
	}

	b[3] = sshConfigBlock{
		Block: "Host jumphost4",
		Options: map[string]string{
			"Port":         strconv.Itoa(jumpHost4.Port()),
			"HostKeyAlias": "jumphost4",
			"ProxyCommand": fmt.Sprintf("ssh -W 127.0.0.1:%d -- %s", jumpHost4.Port(), "jumphost1"),
		},
	}
	require.NoError(t, os.WriteFile(sshConfigPath, []byte(b.String()), 0o600))

	require.NoError(t, cache.WriteProxyMappingFile(mappingPath, mapping.JumphostMapping{
		DomainToJumphost: map[string]string{
			"one.hop":      "jumphost1",
			"two.hops":     "jumphost2",
			"three.hops":   "jumphost3",
			"after.reload": "jumphost4",
		},
		DirectAccessDomains: []string{"sub.always.direct", "sub.sub.always.direct"},
	}), "failed to update hostname mapping")

	require.NoError(t, p.Reload(mappingPath), "failed to reload proxy with updated SSH config and hostname mapping")

	ev.requireEventuallyWithT(t, func(t *assert.CollectT) {
		httpClient.RequireSuccessfulGet(t, "http://after.reload")
	}, "expected to be able to connect to after.reload after reloading SSH config with new jumphost")

	proxyRes, err := http.Get(fmt.Sprintf("http://%s/proxy.pac", proxyAddr))
	require.NoError(t, err, "failed to fetch proxy PAC file")
	defer proxyRes.Body.Close()
	proxyPAC, err := io.ReadAll(proxyRes.Body)
	require.NoError(t, err, "failed to read proxy PAC response body")
	require.Equal(t, strings.ReplaceAll(`function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.vshn.net")) {
    return "DIRECT";
  }
  if (shExpMatch(host, "*sub.always.direct")) {
    return "DIRECT";
  }
  if (shExpMatch(host, "*sub.sub.always.direct")) {
    return "DIRECT";
  }
  if (shExpMatch(host, "*after.reload")) {
    return "SOCKS5 {{ADDR}}";
  }
  if (shExpMatch(host, "*three.hops")) {
    return "SOCKS5 {{ADDR}}";
  }
  if (shExpMatch(host, "*two.hops")) {
    return "SOCKS5 {{ADDR}}";
  }
  if (shExpMatch(host, "*one.hop")) {
    return "SOCKS5 {{ADDR}}";
  }
  return "DIRECT";
}`, "{{ADDR}}", proxyAddr), string(proxyPAC))

	cancel()
	require.NoError(t, wg.Wait())

	require.ErrorContains(t, p.Reload(mappingPath), "proxy is not running")
}

func Test_Start_AutomaticShutdown(t *testing.T) {
	ev := eventuallyDefaults{waitFor: 5 * time.Second, interval: 100 * time.Millisecond}

	userPubKey, agentSocket := spawnSSHAgent(t)
	t.Logf("Spawned SSH agent with public key %x at socket %s", userPubKey, agentSocket)

	localDNSResolver := localhostResolverFor(t, "no.hop")

	mappingPath := filepath.Join(t.TempDir(), "mapping.json")
	require.NoError(t, cache.WriteProxyMappingFile(mappingPath, mapping.JumphostMapping{
		DomainToJumphost: map[string]string{},
	}), "failed to write initial empty mapping file")

	sshConfigPath := filepath.Join(t.TempDir(), "ssh_config")
	b := sshConfigBuilder{
		{
			Block: "Host *",
			Options: map[string]string{
				"IdentityAgent": agentSocket,
			},
		},
	}
	require.NoError(t, os.WriteFile(sshConfigPath, []byte(b.String()), 0o600))

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("X-Request-Host", r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer httpServer.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	p := Proxy{
		SSHConfig: func() *ssh_config.UserSettings {
			u := &ssh_config.UserSettings{}
			u.ConfigFinder(func() string {
				return sshConfigPath
			})
			return u
		},
		DirectDialer: net.Dialer{
			Resolver: localDNSResolver,
		},
		ShutdownTimeout: 500 * time.Millisecond,
	}
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := pl.Addr().String()
	require.NoError(t, err, "failed to listen for proxy")
	wg, wgCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		return p.Start(wgCtx, func() (net.Listener, error) { return pl, nil }, mappingPath)
	})

	httpClient := newHTTPClient(proxyAddr, httpServer.Listener.Addr().(*net.TCPAddr).Port)
	ev.requireEventuallyWithT(t, func(t *assert.CollectT) {
		httpClient.RequireSuccessfulGet(t, "http://no.hop")
	}, "proxy did not start in time")

	httpClient.client.CloseIdleConnections()

	var shutdownWait errgroup.Group
	shutdownWait.Go(func() error {
		timeout := 2 * time.Second
		done := make(chan error, 1)
		go func() {
			done <- wg.Wait()
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(timeout):
			return fmt.Errorf("proxy did not shut down within %s after idle connections were closed", timeout)
		}
	})
	require.NoError(t, shutdownWait.Wait())
}

type eventuallyDefaults struct {
	waitFor  time.Duration
	interval time.Duration
}

func (e eventuallyDefaults) requireEventuallyWithT(t *testing.T, condition func(collect *assert.CollectT), msgAndArgs ...any) {
	t.Helper()
	require.EventuallyWithT(t, condition, e.waitFor, e.interval, msgAndArgs...)
}

type httpClient struct {
	client         *http.Client
	httpServerPort int
}

func newHTTPClient(proxyAddr string, httpServerPort int) *httpClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return url.Parse("socks5://" + proxyAddr)
	}
	return &httpClient{
		client: &http.Client{
			Transport: transport,
		},
		httpServerPort: httpServerPort,
	}
}

func (c *httpClient) RequireNewRequest(t require.TestingT, method, urlStr string, body io.Reader) *http.Request {
	u, err := url.Parse(urlStr)
	require.NoError(t, err)
	u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(c.httpServerPort))

	httpReq, err := http.NewRequestWithContext(context.TODO(), method, u.String(), body)
	require.NoError(t, err)
	return httpReq
}

// RequireSuccessfulGet performs a GET request to the given URL and requires that it succeeds with a 2xx status code.
// It auto-injects the port of the test HTTP server into the URL and uses the client's SOCKS5 proxy configuration to perform the request.
func (c *httpClient) RequireSuccessfulGet(t require.TestingT, urlStr string) {
	httpReq := c.RequireNewRequest(t, http.MethodGet, urlStr, nil)

	resp, err := c.client.Do(httpReq)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	require.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300, "expected successful response, got %d", resp.StatusCode)
}

type knownHostEntry struct {
	hostname string
	port     int
	hostKey  ssh.PublicKey
}

func writeKnownHostsFile(t *testing.T, entries ...knownHostEntry) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "known_hosts")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	require.NoError(t, err)
	defer f.Close()

	for _, entry := range entries {
		line := knownhosts.Line([]string{net.JoinHostPort(entry.hostname, strconv.Itoa(entry.port))}, entry.hostKey)
		_, err := f.WriteString(line + "\n")
		require.NoError(t, err)
	}

	return p
}

type mockSSHServer struct {
	hostKey ssh.PublicKey
	addr    *net.TCPAddr

	blockKeepAlives               atomic.Bool
	keepAliveCounter              atomic.Uint64
	authenticatedConnectionsGauge atomic.Int64
}

func (s *mockSSHServer) Port() int {
	return s.addr.Port
}

func (s *mockSSHServer) HostKey() ssh.PublicKey {
	return s.hostKey
}

func (s *mockSSHServer) BlockKeepAlives() {
	s.blockKeepAlives.Store(true)
}

func (s *mockSSHServer) UnblockKeepAlives() {
	s.blockKeepAlives.Store(false)
}

func (s *mockSSHServer) KeepAliveCount() uint64 {
	return s.keepAliveCounter.Load()
}

func (s *mockSSHServer) AuthenticatedConnections() int64 {
	return s.authenticatedConnectionsGauge.Load()
}

// spawnForwardingSSHServer starts an SSH server that accepts connections using the allowedClientPubKey.
// It supports only "direct-tcpip" channels and forwards them to the requested destination using the provided dialer.
// The server responds to keep-alive requests (of type `keepAliveRequestType`) and increments the keepAliveCounter, unless keep-alives are blocked.
// All other unsupported SSH features (like exec or shell channels) are rejected.
// The server listens on a random free port on localhost and uses a randomly generated host key.
// The server is shut down when the test ends.
func spawnForwardingSSHServer(t *testing.T, allowedClientPubKey ssh.PublicKey, dialer net.Dialer) *mockSSHServer {
	t.Helper()

	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	require.NoError(t, err)

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowedClientPubKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized client key")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &mockSSHServer{
		hostKey: hostSigner.PublicKey(),
		addr:    ln.Addr().(*net.TCPAddr),
	}

	var wg errgroup.Group
	wg.Go(func() error {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("accepting SSH connection: %w", err)
			}
			go s.handleSSHForwardingConnection(conn, serverConfig, dialer)
		}
	})

	t.Cleanup(func() {
		require.NoError(t, ln.Close())
		require.NoError(t, wg.Wait(), "waiting for SSH server goroutine to finish")
	})

	return s
}

func (s *mockSSHServer) handleSSHForwardingConnection(rawConn net.Conn, conf *ssh.ServerConfig, dialer net.Dialer) {
	defer rawConn.Close()

	_, chans, reqs, err := ssh.NewServerConn(rawConn, conf)
	if err != nil {
		slog.Error("SSH handshake failed", slog.Any("error", err))
		return
	}

	s.authenticatedConnectionsGauge.Add(1)
	defer s.authenticatedConnectionsGauge.Add(-1)

	go func() {
		for req := range reqs {
			if req.Type == keepAliveRequestType {
				if s.blockKeepAlives.Load() {
					continue
				}

				s.keepAliveCounter.Add(1)
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		}
	}()

	for newChannel := range chans {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}

		var req struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
			_ = newChannel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
			continue
		}

		targetConn, err := dialer.Dial("tcp", net.JoinHostPort(req.DestAddr, strconv.Itoa(int(req.DestPort))))
		if err != nil {
			_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}

		sshChannel, channelRequests, err := newChannel.Accept()
		if err != nil {
			targetConn.Close()
			continue
		}
		go ssh.DiscardRequests(channelRequests)

		go func() {
			defer sshChannel.Close()
			defer targetConn.Close()

			errCh := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(sshChannel, targetConn)
				errCh <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(targetConn, sshChannel)
				errCh <- struct{}{}
			}()
			<-errCh
		}()
	}
}

// localhostResolverFor returns a net.Resolver that resolves the given hosts to localhost.
// It starts a mock DNS server that serves the necessary records and sets the resolver to use that server.
// The server is shut down when the test ends.
func localhostResolverFor(t *testing.T, hosts ...string) *net.Resolver {
	t.Helper()

	zones := make(map[string]mockdns.Zone, len(hosts))
	localhostZone := mockdns.Zone{A: []string{"127.0.0.1"}, AAAA: []string{"::1"}}
	for _, host := range hosts {
		zones[strings.TrimSuffix(host, ".")+"."] = localhostZone
	}

	mockDNSServer, err := mockdns.NewServerWithLogger(zones, new(nopLogger), true)
	require.NoError(t, err, "failed to start mock DNS server")
	t.Cleanup(func() {
		require.NoError(t, mockDNSServer.Close(), "failed to stop mock DNS server")
	})

	mockDNSResolver := &net.Resolver{}
	mockDNSServer.PatchNet(mockDNSResolver)
	return mockDNSResolver
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

	socketPath = t.TempDir() + "/agent.sock"
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
	})

	return pub, socketPath
}

type nopLogger struct{}

func (l *nopLogger) Printf(format string, args ...any) {}

type sshConfigBuilder []sshConfigBlock

type sshConfigBlock struct {
	Block   string
	Options map[string]string
}

func (b sshConfigBuilder) String() string {
	var sb strings.Builder
	for _, block := range b {
		sb.WriteString(block.Block)
		sb.WriteString("\n")
		for _, k := range slices.Sorted(maps.Keys(block.Options)) {
			v := block.Options[k]
			fmt.Fprintf(&sb, "\t%s %s\n", k, v)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
