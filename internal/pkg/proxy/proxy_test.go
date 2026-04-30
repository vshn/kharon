package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	userPubKey, agentSocket := spawnSSHAgent(t)
	t.Logf("Spawned SSH agent with public key %x at socket %s", userPubKey, agentSocket)

	localDNSResolver := localhostResolverFor(t, "no.hop", "one.hop")
	dmz2DNSResolver := localhostResolverFor(t, "two.hops", "jumphost3")
	dmz3DNSResolver := localhostResolverFor(t, "three.hops")

	allowedPubKey, err := ssh.NewPublicKey(userPubKey)
	require.NoError(t, err)
	jumpHost1 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: localDNSResolver})
	jumpHost2 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: dmz2DNSResolver})
	jumpHost3 := spawnForwardingSSHServer(t, allowedPubKey, net.Dialer{Resolver: dmz3DNSResolver})
	knownHostsPath := writeKnownHostsFile(t, knownHostEntry{
		hostname: "127.0.0.1",
		port:     jumpHost1.Port(),
		hostKey:  jumpHost1.HostKey(),
	}, knownHostEntry{
		hostname: "127.0.0.1",
		port:     jumpHost2.Port(),
		hostKey:  jumpHost2.HostKey(),
	}, knownHostEntry{
		hostname: "jumphost3",
		port:     jumpHost3.Port(),
		hostKey:  jumpHost3.HostKey(),
	})

	mappingPath := filepath.Join(t.TempDir(), "mapping.json")
	require.NoError(t, os.WriteFile(mappingPath, requireJSONMarshal(t, map[string]string{
		"one.hop":    "jumphost1",
		"two.hops":   "jumphost2",
		"three.hops": "jumphost3",
	}), 0o600))

	sshConfigPath := filepath.Join(t.TempDir(), "ssh_config")
	require.NoError(t, os.WriteFile(sshConfigPath, []byte(fmt.Sprintf(`
Host *
	IdentityAgent %s
	UserKnownHostsFile %s
	User test

Host jumphost1
	HostName 127.0.0.1
	Port %d

Host jumphost2
	HostName 127.0.0.1
	ProxyJump jumphost1
	Port %d

Host jumphost3
	ProxyJump jumphost2
	Port %d
`, agentSocket, knownHostsPath, jumpHost1.Port(), jumpHost2.Port(), jumpHost3.Port())), 0o600))

	u := &ssh_config.UserSettings{}
	u.ConfigFinder(func() string {
		return sshConfigPath
	})

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.Header().Set("X-Request-Host", r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer httpServer.Close()
	httpServerPort := httpServer.Listener.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	proxyPort, err := freePort()
	require.NoError(t, err, "failed to find free port for proxy")
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	wg, wgCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		p := Proxy{
			SSHConfig: u,
			DirectDialer: net.Dialer{
				Resolver: localDNSResolver,
			},
		}
		return p.Start(wgCtx, proxyAddr, mappingPath)
	})

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return url.Parse("socks5://" + proxyAddr)
	}
	client := &http.Client{
		Transport: transport,
	}
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		httpReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://no.hop:%d", httpServerPort), nil)
		require.NoError(t, err)
		resp, err := client.Do(httpReq)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}, 5*time.Second, 100*time.Millisecond, "proxy did not start in time")

	for _, domain := range []string{"no.hop", "one.hop", "two.hops", "three.hops"} {
		httpReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://%s:%d", domain, httpServerPort), nil)
		require.NoError(t, err)
		resp, err := client.Do(httpReq)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	cancel()
	require.NoError(t, wg.Wait())
}

func requireJSONMarshal(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
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

type forwardingSSHServer struct {
	hostKey ssh.PublicKey
	addr    *net.TCPAddr
}

// spawnForwardingSSHServer starts an SSH server that accepts connections using the allowedClientPubKey.
// It supports only "direct-tcpip" channels and forwards them to the requested destination using the provided dialer.
// All other unsupported SSH features (like exec or shell channels) are rejected.
// The server listens on a random free port on localhost and uses a randomly generated host key.
// The server is shut down when the test ends.
func spawnForwardingSSHServer(t *testing.T, allowedClientPubKey ssh.PublicKey, dialer net.Dialer) *forwardingSSHServer {
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

	s := &forwardingSSHServer{
		hostKey: hostSigner.PublicKey(),
		addr:    ln.Addr().(*net.TCPAddr),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSSHForwardingConnection(conn, serverConfig, dialer)
		}
	}()

	t.Cleanup(func() {
		require.NoError(t, ln.Close())
	})

	return s
}

func (s *forwardingSSHServer) Port() int {
	return s.addr.Port
}

func (s *forwardingSSHServer) HostKey() ssh.PublicKey {
	return s.hostKey
}

func handleSSHForwardingConnection(rawConn net.Conn, conf *ssh.ServerConfig, dialer net.Dialer) {
	defer rawConn.Close()

	_, chans, reqs, err := ssh.NewServerConn(rawConn, conf)
	if err != nil {
		return
	}

	go ssh.DiscardRequests(reqs)

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

func (l *nopLogger) Printf(format string, args ...interface{}) {}
