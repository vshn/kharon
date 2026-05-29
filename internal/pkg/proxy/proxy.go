package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/multierr"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/errgroup"
	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/sshconfig"
)

const keepAliveRequestType = "keepalive@kharon"

type Proxy struct {
	// SSHConfigFile is the path to the SSH config file to use for determining jumphosts and SSH connection settings.
	// If not set, the proxy uses the default SSH config files.
	SSHConfigFile string

	// DirectDialer is the dialer to use for direct connections.
	DirectDialer net.Dialer

	// KeepAliveInterval is the interval for sending keep-alive messages to the jumphosts.
	// Defaults to 3 seconds if not set.
	KeepAliveInterval time.Duration

	// ShutdownTimeout is the timeout for shutting down the proxy when no active connections are present.
	// A zero value means that the proxy will not shut down automatically.
	ShutdownTimeout time.Duration

	// dialer is the current dialer to use for incoming connections. It is stored atomically so that it can be replaced on the fly when reloading the configuration.
	dialer atomic.Pointer[RoutingDialer]

	// addr is the current address the proxy is listening on, used for generating the PAC file.
	addr string
}

func (p *Proxy) Start(ctx context.Context, lp func() (net.Listener, error), mappingFile string) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sshDialer, err := NewRoutingDialer(sshconfig.NewSSHConfigWithCache(p.SSHConfigFile), p.DirectDialer, p.keepAliveInterval(), mappingFile)
	if err != nil {
		return fmt.Errorf("failed to build SSH dialer: %w", err)
	}
	p.dialer.Store(sshDialer)
	defer func() {
		if oldDialer := p.dialer.Swap(nil); oldDialer != nil {
			multierr.AppendInto(&err, oldDialer.Close())
		}
	}()

	socks5Server := &socks5.Server{
		Logf: func(format string, args ...any) {
			slog.Error(fmt.Sprintf(format, args...))
		},
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			slog.Debug("New SOCKS5 connection", slog.String("network", network), slog.String("addr", addr))
			return p.dialer.Load().DialContext(ctx, network, addr)
		},
	}
	listener, err := lp()
	if err != nil {
		return fmt.Errorf("failed to get listener: %w", err)
	}
	p.addr = listener.Addr().String()
	slog.Info("starting SOCKS5 server", slog.String("addr", p.addr))
	listener = &ConnCountingListener{Listener: listener}

	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(listener)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request", slog.String("method", r.Method), slog.String("url", r.URL.String()), slog.String("remote_addr", r.RemoteAddr))
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		if err := p.dialer.Load().writeProxyPAC(w, p.addr); err != nil {
			slog.Error("failed to write proxy PAC", slog.Any("error", err))
		}
	})
	httpServ := &http.Server{
		Handler: mux,
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		<-egCtx.Done()
		slog.Info("shutting down SOCKS5 server")
		return listener.Close()
	})
	eg.Go(func() error {
		if err := socks5Server.Serve(socksListener); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("SOCKS5 server error: %w", err)
		}
		return nil
	})
	eg.Go(func() error {
		defer func() {
			if err := httpServ.Close(); err != nil {
				slog.Error("HTTP server close error", slog.Any("error", err))
			}
		}()
		if err := httpServ.Serve(httpListener); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	if p.ShutdownTimeout > 0 {
		const probes = 10
		ticker := time.NewTicker(p.ShutdownTimeout / probes)
		var counter int
		eg.Go(func() error {
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					c := listener.(*ConnCountingListener).connCount.Load()
					if c == 0 {
						counter++
					} else {
						counter = 0
					}
					slog.Debug("Active connections", slog.Int64("count", c), slog.Int("shutdown_counter", counter), slog.Int("shutdown_at", probes))
					if counter >= probes {
						slog.Info("no active connections within shutdown timeout, shutting down", slog.Duration("shutdown_timeout", p.ShutdownTimeout))
						cancel()
					}
				case <-egCtx.Done():
					return nil
				}
			}
		})
	}

	return eg.Wait()
}

func (p *Proxy) Reload(mappingFile string) error {
	current := p.dialer.Load()
	if current == nil {
		return fmt.Errorf("proxy is not running")
	}

	newDialer, err := NewRoutingDialer(sshconfig.NewSSHConfigWithCache(p.SSHConfigFile), p.DirectDialer, p.keepAliveInterval(), mappingFile)
	if err != nil {
		return fmt.Errorf("failed to build new SSH dialer: %w", err)
	}

	if p.dialer.CompareAndSwap(current, newDialer) {
		return current.Close()
	} else {
		// Another reload happened in the meantime, or the proxy was stopped.
		// Just close the new dialer and keep the current one running.
		return newDialer.Close()
	}
}

// keepAliveInterval returns the keep-alive interval to use for SSH connections, defaulting to 3 seconds if not set.
func (p *Proxy) keepAliveInterval() time.Duration {
	if p.KeepAliveInterval == 0 {
		return 3 * time.Second
	}
	return p.KeepAliveInterval
}

func loadHostnameMapping(mappingFile string) ([]hostSuffixJumphostMapping, error) {
	l := slog.With(slog.String("mapping_file", mappingFile))
	l.Info("Loading hostname mapping")
	hmp, err := cache.ReadProxyMappingFile(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy mapping file. You might need to run the `update` command first.: %w", err)
	}
	hostnameMapping := make([]hostSuffixJumphostMapping, 0, len(hmp.DomainToJumphost))
	for h, jh := range hmp.DomainToJumphost {
		hostnameMapping = append(hostnameMapping, hostSuffixJumphostMapping{
			HostSuffix: h,
			Jumphost:   jh,
		})
	}
	// Longest suffix first, so that more specific mappings are preferred over less specific ones.
	slices.SortFunc(hostnameMapping, func(a, b hostSuffixJumphostMapping) int {
		return 10*(len(b.HostSuffix)-len(a.HostSuffix)) + strings.Compare(a.HostSuffix, b.HostSuffix)
	})

	// Add direct access domain at the front of the list with empty jumphost, so that they are preferred over any domain mappings.
	direct := make([]hostSuffixJumphostMapping, len(hmp.DirectAccessDomains))
	for i, d := range hmp.DirectAccessDomains {
		direct[i] = hostSuffixJumphostMapping{
			HostSuffix: d,
			Jumphost:   "",
		}
	}
	hostnameMapping = append(direct, hostnameMapping...)

	l.Info("Loaded hostname mappings", slog.Int("mappings", len(hostnameMapping)))
	return hostnameMapping, nil
}

type hostSuffixJumphostMapping struct {
	HostSuffix string
	Jumphost   string
}

// RoutingDialer is a custom dialer that routes connections through SSH jumphosts based on the destination hostname and the provided SSH configuration.
type RoutingDialer struct {
	sshManagersMux sync.Mutex
	sshManagers    map[string]*clientMgr

	routes sync.Map

	agentConn       net.Conn
	agent           agent.ExtendedAgent
	hostnameMapping []hostSuffixJumphostMapping

	sshSettings *sshconfig.SSHConfigWithCache

	directDialer      net.Dialer
	keepAliveInterval time.Duration
}

// NewRoutingDialer creates a new RoutingDialer with the given SSH configuration, direct dialer, keep-alive interval, and hostname mapping file.
func NewRoutingDialer(sshConfig *sshconfig.SSHConfigWithCache, direct net.Dialer, tunnelKeepAliveInterval time.Duration, mappingFile string) (*RoutingDialer, error) {
	hostnameMapping, err := loadHostnameMapping(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load hostname mapping: %w", err)
	}

	// TODO(bastjan) This can in theory be different for different jumphosts, but let's assume it's the same for all of them for now.
	// We can always add support for per-jumphost agent sockets later if needed.
	// It's just a random hostname that is very unlikely to be used in the SSH config,
	// we should get the default value for IdentityAgent without accidentally picking up a real host's config.
	agentConf, err := sshConfig.ConfigForHost("6372ffc2-9466-4e89-b60d-14307aa583a5.internal.kharon.vshn.io")
	if err != nil {
		return nil, fmt.Errorf("SSH_AUTH_SOCK is not a valid socket: %w", err)
	}
	agentSock := agentConf.Get("IdentityAgent")
	if agentSock != "" {
		rs, err := replaceTildeWithHome(agentSock)
		if err != nil {
			return nil, fmt.Errorf("failed to replace `~/` with home directory in agent socket path: %w", err)
		}
		agentSock = rs
	} else {
		// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			return nil, fmt.Errorf("SSH_AUTH_SOCK is not set")
		}
		agentSock = socket
	}
	slog.Info("Using SSH agent socket", slog.String("path", agentSock))
	sshAgentConn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH_AUTH_SOCK: %w", err)
	}

	agentClient := agent.NewClient(sshAgentConn)
	return &RoutingDialer{
		agentConn:       sshAgentConn,
		agent:           agentClient,
		hostnameMapping: hostnameMapping,

		sshManagers: make(map[string]*clientMgr),

		sshSettings:       sshConfig,
		directDialer:      direct,
		keepAliveInterval: tunnelKeepAliveInterval,
	}, nil
}

func (d *RoutingDialer) Close() error {
	d.sshManagersMux.Lock()
	defer d.sshManagersMux.Unlock()

	errs := make([]error, 0, len(d.sshManagers)+1)
	errs = append(errs, d.agentConn.Close())

	for _, mgr := range d.sshManagers {
		errs = append(errs, mgr.Close())
	}
	return multierr.Combine(errs...)
}

type clientMgr struct {
	Jumphost          string
	Agent             agent.ExtendedAgent
	SSHSettings       *sshconfig.SSHConfigWithCache
	KeepAliveInterval time.Duration

	// clientMux protects access to client and clientCleanup.
	// Both are set together when a new client is created, and both are set to nil when the client is closed.
	clientMux sync.Mutex
	client    *ssh.Client
	// clientCleanup also closes client, client.Close should not be called directly called.
	clientCleanup func() error
}

func (m *clientMgr) Close() error {
	m.clientMux.Lock()
	defer m.clientMux.Unlock()

	if m.clientCleanup != nil {
		return m.clientCleanup()
	}
	return nil
}

func (m *clientMgr) GetClient(ctx context.Context) (*ssh.Client, error) {
	m.clientMux.Lock()
	defer m.clientMux.Unlock()

	if m.client != nil {
		return m.client, nil
	}

	jumphosts, err := jumphostChainForTarget(m.SSHSettings, m.Jumphost)
	if err != nil {
		return nil, fmt.Errorf("error getting jumphost chain for %s: %w", m.Jumphost, err)
	}

	slog.Debug("New connection", slog.String("chain", strings.Join(jumphosts, "->")))
	configs := make([]sshJump, 0, len(jumphosts))
	for _, jh := range jumphosts {
		jhAddr, jhConfig, err := configForHost(m.SSHSettings, jh, m.Agent)
		if err != nil {
			return nil, fmt.Errorf("error getting SSH config for jumphost %s: %w", jh, err)
		}
		configs = append(configs, sshJump{
			Addr:   jhAddr,
			Config: jhConfig,
		})
	}

	sshc, cleanupSSHC, err := dialThroughJumps(configs)
	if err != nil {
		return nil, fmt.Errorf("error dialing jumphost chain %s: %w", strings.Join(jumphosts, "->"), err)
	}

	stopKeepAlive := func() {}
	if m.KeepAliveInterval > 0 {
		keepAliveStopper, ska := context.WithCancel(context.Background())
		stopKeepAlive = ska
		kat := time.NewTicker(m.KeepAliveInterval)
		go func() {
			defer kat.Stop()
			for {
				select {
				case <-kat.C:
					if err := sendKeepAlive(sshc, m.KeepAliveInterval); err != nil {
						slog.Debug("SSH keepalive failed", slog.String("jumphost", m.Jumphost), slog.Any("error", err))
						kat.Stop()

						m.clientMux.Lock()
						if keepAliveStopper.Err() != nil || m.client != sshc {
							// Keep-alive loop already stopped or client was replaced, just unlock and return.
							m.clientMux.Unlock()
							return
						}
						if err := m.clientCleanup(); err != nil {
							slog.Error("Error during SSH client cleanup", slog.String("jumphost", m.Jumphost), slog.Any("error", err))
						}
						m.client = nil
						m.clientCleanup = nil
						m.clientMux.Unlock()
						return
					}
				case <-keepAliveStopper.Done():
					return
				}
			}
		}()
	}

	m.client = sshc
	m.clientCleanup = func() error {
		stopKeepAlive()
		if err := cleanupSSHC(); err != nil {
			return fmt.Errorf("error cleaning up SSH client for jumphost %s: %w", m.Jumphost, err)
		}
		return nil
	}

	return sshc, nil
}

// sendKeepAlive sends a keep-alive request to the SSH server and waits for a response or timeout.
// Note that it leaks goroutines on timeout, but since we tear down the whole client on timeout, it shouldn't be a problem in practice.
func sendKeepAlive(sshc *ssh.Client, timeout time.Duration) error {
	keepAliveCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		if _, _, err := sshc.SendRequest(keepAliveRequestType, true, nil); err != nil {
			errCh <- fmt.Errorf("SSH keepalive failed: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-keepAliveCtx.Done():
		return keepAliveCtx.Err()
	case err := <-errCh:
		return err
	}
}

// JumphostForHost determines the appropriate jumphost for the given hostname based
// on the loaded hostname mappings and caches the result for future lookups.
func (d *RoutingDialer) JumphostForHost(hostname string) string {
	if jh, ok := d.routes.Load(hostname); ok {
		return jh.(string)
	}

	var jumphost string
	for _, mapping := range d.hostnameMapping {
		if strings.HasSuffix(hostname, mapping.HostSuffix) {
			jumphost = mapping.Jumphost
			break
		}
	}
	d.routes.Store(hostname, jumphost)

	if jumphost == "" {
		slog.Debug("Direct connection", slog.String("hostname", hostname))
	} else {
		slog.Debug("Domain mapped to jumphost", slog.String("hostname", hostname), slog.String("jumphost", jumphost))
	}

	return jumphost
}

// DialContext connects to the address on the named network using the provided context.
// It determines the appropriate SSH jumphost based on the destination hostname and routes the connection through it if necessary.
func (d *RoutingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("error splitting host and port for %s: %w", addr, err)
	}

	jumphost := d.JumphostForHost(hostname)

	if jumphost == "" {
		return d.directDialer.DialContext(ctx, network, addr)
	}

	d.sshManagersMux.Lock()
	mgr, ok := d.sshManagers[jumphost]
	if !ok {
		mgr = &clientMgr{
			Jumphost:          jumphost,
			Agent:             d.agent,
			SSHSettings:       d.sshSettings,
			KeepAliveInterval: d.keepAliveInterval,
		}
		d.sshManagers[jumphost] = mgr
	}
	d.sshManagersMux.Unlock()

	sshc, err := mgr.GetClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting SSH client for %s: %w", addr, err)
	}

	return sshc.DialContext(ctx, network, addr)
}

type sshJump struct {
	Addr   string
	Config *ssh.ClientConfig
}

// dialThroughJumps establishes an SSH client connection through a chain of jumphost proxies.
// It connects sequentially through each jump in the chain, then to the target.
// Returns the target SSH client, a cleanup function, and any error.
func dialThroughJumps(jumps []sshJump) (*ssh.Client, func() error, error) {
	if len(jumps) == 0 {
		return nil, nil, fmt.Errorf("no jumphosts provided")
	}
	if len(jumps) == 1 {
		return dialDirectTarget(jumps[0].Addr, jumps[0].Config)
	}
	target := jumps[len(jumps)-1]
	jumps = jumps[:len(jumps)-1]

	// Connect through the jumphost chain
	chain := &clientChain{}
	for _, jump := range jumps {
		if err := chain.connectJump(jump.Addr, jump.Config); err != nil {
			return nil, nil, multierr.Append(err, chain.closeAll())
		}
	}

	// Connect to final target
	targetClient, err := chain.dialTargetThroughChain(target.Addr, target.Config)
	if err != nil {
		return nil, nil, multierr.Append(err, chain.closeAll())
	}

	return targetClient, chain.closeAll, nil
}

// clientChain manages a chain of SSH clients for establishing connections through jumphost proxies.
type clientChain struct {
	clients []*ssh.Client
}

// connectJump establishes an SSH connection to the next jump in the chain, either directly or through the last client in the chain.
func (c *clientChain) connectJump(addr string, config *ssh.ClientConfig) error {
	if len(c.clients) == 0 {
		return c.dialInitialJump(addr, config)
	}
	lastClient := c.clients[len(c.clients)-1]
	return c.dialThroughJump(lastClient, addr, config)
}

// dialInitialJump establishes the initial SSH connection to the first jump in the chain.
func (c *clientChain) dialInitialJump(addr string, config *ssh.ClientConfig) error {
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("error connecting first jump %q: %w", addr, err)
	}
	c.clients = append(c.clients, client)
	return nil
}

// dialThroughJump establishes an SSH connection through the current client in the chain to the next jump.
func (c *clientChain) dialThroughJump(jump *ssh.Client, addr string, config *ssh.ClientConfig) error {
	conn, err := jump.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("error dialing jump %q through %q: %w", addr, jump.RemoteAddr().String(), err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return multierr.Combine(
			fmt.Errorf("error creating client for jump %q through %q: %w", addr, jump.RemoteAddr().String(), err),
			conn.Close(),
		)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	c.clients = append(c.clients, client)
	return nil
}

// dialTargetThroughChain establishes an SSH connection to the final target through the chain.
func (c *clientChain) dialTargetThroughChain(targetAddr string, targetConfig *ssh.ClientConfig) (*ssh.Client, error) {
	lastClient := c.clients[len(c.clients)-1]

	conn, err := lastClient.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("error dialing target %q through %q: %w", targetAddr, lastClient.RemoteAddr().String(), err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, targetConfig)
	if err != nil {
		return nil, multierr.Combine(
			fmt.Errorf("error creating ssh client for target %q through %q: %w", targetAddr, lastClient.RemoteAddr().String(), err),
			conn.Close(),
		)
	}

	targetClient := ssh.NewClient(sshConn, chans, reqs)
	c.clients = append(c.clients, targetClient)
	return targetClient, nil
}

// closeAll closes all clients in the chain in reverse order.
func (c *clientChain) closeAll() error {
	errs := make([]error, 0, len(c.clients))
	for _, client := range slices.Backward(c.clients) {
		errs = append(errs, client.Close())
	}
	return multierr.Combine(errs...)
}

// dialDirectTarget establishes a direct SSH connection without proxy jumps.
func dialDirectTarget(addr string, config *ssh.ClientConfig) (*ssh.Client, func() error, error) {
	c, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting target %q: %w", addr, err)
	}
	return c, c.Close, nil
}

func configForHost(sshConfig *sshconfig.SSHConfigWithCache, host string, agent agent.ExtendedAgent) (string, *ssh.ClientConfig, error) {
	conf, err := sshConfig.ConfigForHost(host)
	if err != nil {
		return "", nil, fmt.Errorf("error getting SSH config for host %s: %w", host, err)
	}

	khfs := conf.Get("UserKnownHostsFile")
	akhfs := make([]string, 0)
	for khf := range strings.FieldsSeq(khfs) {
		khf, err := replaceTildeWithHome(khf)
		if err != nil {
			return "", nil, fmt.Errorf("error replacing `~/` with home directory for UserKnownHostsFile %s: %w", khf, err)
		}

		akhf, err := filepath.Abs(khf)
		if err != nil {
			return "", nil, fmt.Errorf("error getting absolute path for UserKnownHostsFile %s: %w", khf, err)
		}
		if _, err := os.Stat(akhf); err != nil {
			if os.IsNotExist(err) {
				slog.Debug("UserKnownHostsFile does not exist, skipping", slog.String("path", akhf))
				continue
			}
			return "", nil, fmt.Errorf("error statting UserKnownHostsFile %s: %w", akhf, err)
		}
		akhfs = append(akhfs, akhf)
	}
	slog.Debug("Using known hosts files for host", slog.String("host", host), slog.String("files", strings.Join(akhfs, ", ")))
	knownHosts, err := knownhosts.New(akhfs...)
	if err != nil {
		return "", nil, fmt.Errorf("error creating knownhosts callback for host %s: %w", host, err)
	}
	username := conf.Get("User")
	port := conf.Get("Port")
	hostName := conf.Get("HostName")
	proxyCommand := conf.Get("ProxyCommand")
	if proxyCommand != "" {
		slog.Debug("Fallback to ProxyCommand for HostName", slog.String("host", host), slog.String("proxy_command", proxyCommand))
		extractedHostName, _, _, err := parseProxyCommand(proxyCommand)
		if err != nil {
			return "", nil, fmt.Errorf("error parsing ProxyCommand for host %s: %w", host, err)
		}
		slog.Debug("Extracted HostName from ProxyCommand", slog.String("host", host), slog.String("host_name", extractedHostName))
		hostName = extractedHostName
	}
	hostKeyAlias := conf.Get("HostKeyAlias")
	if hostKeyAlias != "" {
		knownHostsWithoutMapping := knownHosts
		knownHosts = func(hn string, remote net.Addr, key ssh.PublicKey) error {
			h, p, err := net.SplitHostPort(hn)
			if err != nil {
				return fmt.Errorf("error splitting host and port for %s: %w", hn, err)
			}
			if h == host || h == hostName {
				hn = net.JoinHostPort(hostKeyAlias, p)
			}
			return knownHostsWithoutMapping(hn, remote, key)
		}
	}
	return net.JoinHostPort(hostName, port), &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: knownHosts,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agent.Signers),
		},
	}, nil
}

func jumphostChainForTarget(conf *sshconfig.SSHConfigWithCache, host string) ([]string, error) {
	chain := []string{host}

	for {
		c, err := conf.ConfigForHost(host)
		if err != nil {
			return nil, fmt.Errorf("error getting SSH config for host %s: %w", host, err)
		}
		jump := c.Get("ProxyJump")
		if jump == "" {
			pc := c.Get("ProxyCommand")
			if pc == "" {
				break
			}
			slog.Debug("Fallback to ProxyCommand for ProxyJump", slog.String("host", host), slog.String("proxy_command", pc))
			_, _, extracted, err := parseProxyCommand(pc)
			if err != nil {
				return nil, fmt.Errorf("error parsing ProxyCommand for host %s: %w", host, err)
			}
			slog.Debug("Extracted jumphost from ProxyCommand", slog.String("host", host), slog.String("jumphost", extracted))
			jump = extracted
		}
		if strings.Contains(jump, ",") {
			return nil, fmt.Errorf("multiple ProxyJump entries for host %s are not supported", host)
		}
		if slices.Contains(chain, jump) {
			return nil, fmt.Errorf("circular ProxyJump detected for host %s: %s is already in the chain", host, jump)
		}
		chain = append(chain, jump)
		host = jump
	}

	slices.Reverse(chain)
	return chain, nil
}

func parseProxyCommand(cmd string) (hostName, hostPort, proxyName string, err error) {
	const expectedFormat = "ssh -W <host>:<port> -- <proxy>"
	parts := strings.Fields(cmd)
	if len(parts) != 5 || parts[0] != "ssh" || parts[1] != "-W" || parts[3] != "--" {
		return "", "", "", fmt.Errorf("unexpected ProxyCommand format, expected: %s", expectedFormat)
	}

	hostName, hostPort, err = net.SplitHostPort(parts[2])
	if err != nil {
		return "", "", "", fmt.Errorf("error parsing host and port from ProxyCommand: %w", err)
	}

	return hostName, hostPort, parts[4], nil
}

func replaceTildeWithHome(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("error getting user home directory: %w", err)
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func (d *RoutingDialer) writeProxyPAC(w io.Writer, addr string) error {
	// Allow direct access to the vshn.net sign-in page and the Lieutenant API
	// Fallback in case the proxy is not available due to incompatible or corrupted jumphost
	// mapping rules.
	staticDirectDomains := []hostSuffixJumphostMapping{
		{HostSuffix: ".vshn.net"},
	}

	if _, err := fmt.Fprint(w, "function FindProxyForURL(url, host) {\n"); err != nil {
		return err
	}
	for _, mapping := range append(staticDirectDomains, d.hostnameMapping...) {
		// Turns out JSON is a subset of JavaScript...
		s, err := json.Marshal(fmt.Sprintf("*%s", mapping.HostSuffix))
		if err != nil {
			return fmt.Errorf("error marshalling host suffix to JSON: %w", err)
		}
		ret := "DIRECT"
		if mapping.Jumphost != "" {
			ret = fmt.Sprintf("SOCKS5 %s", addr)
		}
		if _, err := fmt.Fprintf(w, "  if (shExpMatch(host, %s)) {\n    return \"%s\";\n  }\n", s, ret); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "  return \"DIRECT\";\n}"); err != nil {
		return err
	}
	return nil
}
