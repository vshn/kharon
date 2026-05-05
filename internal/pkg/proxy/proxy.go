package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kevinburke/ssh_config"
	"go.uber.org/multierr"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/errgroup"
	"tailscale.com/net/socks5"
)

const keepAliveRequestType = "keepalive@kharon"

type Proxy struct {
	// SSHConfig is the SSH config to use for determining jumphosts and SSH connection settings.
	// If not set, the proxy uses ssh_config.DefaultUserSettings.
	// The function is called on every Reload() and it should return a new instance of ssh_config.UserSettings each time.
	// ssh_config.UserSettings has an internal cache and never reloads the config file after the first load.
	SSHConfig func() *ssh_config.UserSettings

	// DirectDialer is the dialer to use for direct connections.
	DirectDialer net.Dialer

	// KeepAliveInterval is the interval for sending keep-alive messages to the jumphosts.
	// Defaults to 3 seconds if not set.
	KeepAliveInterval time.Duration

	// dialer is the current dialer to use for incoming connections. It is stored atomically so that it can be replaced on the fly when reloading the configuration.
	dialer atomic.Pointer[sshDialer]
}

func (p *Proxy) Start(ctx context.Context, addr, mappingFile string) (err error) {
	sshDialer, err := buildSSHDialer(p, mappingFile)
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
		Logf: log.Printf,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("New SOCKS5 connection %s://%s", network, addr)
			return p.dialer.Load().dial(ctx, network, addr)
		},
	}
	log.Printf("starting SOCKS5 server on %s", addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		<-egCtx.Done()
		log.Print("shutting down SOCKS5 server")
		return listener.Close()
	})
	eg.Go(func() error {
		if err := socks5Server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("SOCKS5 server error: %w", err)
		}
		return nil
	})

	return eg.Wait()
}

func (p *Proxy) Reload(mappingFile string) error {
	current := p.dialer.Load()
	if current == nil {
		return fmt.Errorf("proxy is not running")
	}

	newDialer, err := buildSSHDialer(p, mappingFile)
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
	mf, err := os.Open(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file: %w", err)
	}
	defer func() { _ = mf.Close() }()
	var hmp map[string]string
	if err := json.NewDecoder(mf).Decode(&hmp); err != nil {
		return nil, fmt.Errorf("failed to parse mapping file: %w", err)
	}
	hostnameMapping := make([]hostSuffixJumphostMapping, 0, len(hmp))
	for h, jh := range hmp {
		hostnameMapping = append(hostnameMapping, hostSuffixJumphostMapping{
			HostSuffix: h,
			Jumphost:   jh,
		})
	}
	// Longest suffix first, so that more specific mappings are preferred over less specific ones.
	slices.SortFunc(hostnameMapping, func(a, b hostSuffixJumphostMapping) int {
		return 10*(len(b.HostSuffix)-len(a.HostSuffix)) + strings.Compare(a.HostSuffix, b.HostSuffix)
	})
	log.Printf("Loaded %v hostname mappings", len(hostnameMapping))
	return hostnameMapping, nil
}

type hostSuffixJumphostMapping struct {
	HostSuffix string
	Jumphost   string
}

type sshDialer struct {
	sshManagersMux sync.Mutex
	sshManagers    map[string]*clientMgr

	routes sync.Map

	agentConn       net.Conn
	agent           agent.ExtendedAgent
	hostnameMapping []hostSuffixJumphostMapping

	sshSettings *ssh_config.UserSettings

	directDialer      net.Dialer
	keepAliveInterval time.Duration
}

func buildSSHDialer(p *Proxy, mappingFile string) (*sshDialer, error) {
	hostnameMapping, err := loadHostnameMapping(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load hostname mapping: %w", err)
	}

	var sshConfig *ssh_config.UserSettings
	if p.SSHConfig != nil {
		sshConfig = p.SSHConfig()
	}
	if sshConfig == nil {
		sshConfig = &ssh_config.UserSettings{}
	}

	// TODO(bastjan) This can in theory be different for different jumphosts, but let's assume it's the same for all of them for now.
	// We can always add support for per-jumphost agent sockets later if needed.
	// It's just a random hostname that is very unlikely to be used in the SSH config,
	// we should get the default value for IdentityAgent without accidentally picking up a real host's config.
	agentSock, err := sshConfig.GetStrict("6372ffc2-9466-4e89-b60d-14307aa583a5.internal.kharon.vshn.io", "IdentityAgent")
	if err != nil {
		return nil, fmt.Errorf("SSH_AUTH_SOCK is not a valid socket: %w", err)
	}
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
	log.Printf("Using SSH agent socket: %s", agentSock)
	sshAgentConn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH_AUTH_SOCK: %w", err)
	}

	agentClient := agent.NewClient(sshAgentConn)
	return &sshDialer{
		agentConn:       sshAgentConn,
		agent:           agentClient,
		hostnameMapping: hostnameMapping,

		sshManagers: make(map[string]*clientMgr),

		sshSettings:       sshConfig,
		directDialer:      p.DirectDialer,
		keepAliveInterval: p.keepAliveInterval(),
	}, nil
}

func (d *sshDialer) Close() error {
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
	SSHSettings       *ssh_config.UserSettings
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

	log.Printf("New connection to %s", strings.Join(jumphosts, "->"))
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

	target := configs[len(configs)-1]
	sshc, cleanupSSHC, err := dialViaProxyJump(target.Addr, target.Config, configs[:len(configs)-1])
	if err != nil {
		return nil, fmt.Errorf("error dialing jumphost chain %s: %w", strings.Join(jumphosts, "->"), err)
	}

	keepAliveStopper, stopKeepAlive := context.WithCancel(context.Background())
	kat := time.NewTicker(m.KeepAliveInterval)
	go func() {
		defer kat.Stop()
		for {
			select {
			case <-kat.C:
				if err := sendKeepAlive(sshc, m.KeepAliveInterval); err != nil {
					log.Printf("SSH keepalive failed for jumphost %s: %v", m.Jumphost, err)
					kat.Stop()

					m.clientMux.Lock()
					if keepAliveStopper.Err() != nil || m.client != sshc {
						// Keep-alive loop already stopped or client was replaced, just unlock and return.
						m.clientMux.Unlock()
						return
					}
					if err := m.clientCleanup(); err != nil {
						log.Printf("Error during SSH client cleanup for jumphost %s: %v", m.Jumphost, err)
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

func (d *sshDialer) jumphostForHost(hostname string) string {
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
		log.Printf("⌥ %s is a direct connection", hostname)
	} else {
		log.Printf("⌥ %s mapped to jumphost %s", hostname, jumphost)
	}

	return jumphost
}

func (d *sshDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("error splitting host and port for %s: %w", addr, err)
	}

	jumphost := d.jumphostForHost(hostname)

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

// TODO(bastjan) This is horrible AI code. Refactor to be more readable.
func dialViaProxyJump(targetAddr string, targetConfig *ssh.ClientConfig, jumps []sshJump) (*ssh.Client, func() error, error) {
	if len(jumps) == 0 {
		c, err := ssh.Dial("tcp", targetAddr, targetConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("error connecting target %s: %w", targetAddr, err)
		}
		return c, c.Close, nil
	}

	clients := make([]*ssh.Client, 0, len(jumps)+1)

	closeAll := func() error {
		errs := make([]error, len(clients))
		for i := len(clients) - 1; i >= 0; i-- {
			errs[i] = clients[i].Close()
		}
		return multierr.Combine(errs...)
	}

	currentClient, err := ssh.Dial("tcp", jumps[0].Addr, jumps[0].Config)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting jump 0 (%s): %w", jumps[0].Addr, err)
	}
	clients = append(clients, currentClient)

	for i := 1; i < len(jumps); i++ {
		nextConn, err := currentClient.Dial("tcp", jumps[i].Addr)
		if err != nil {
			return nil, nil, multierr.Combine(
				closeAll(),
				fmt.Errorf("error dialing jump %d (%s): %w", i, jumps[i].Addr, err),
			)
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(nextConn, jumps[i].Addr, jumps[i].Config)
		if err != nil {
			return nil, nil, multierr.Combine(
				nextConn.Close(),
				closeAll(),
				fmt.Errorf("error creating client for jump %d (%s): %w", i, jumps[i].Addr, err),
			)
		}

		currentClient = ssh.NewClient(sshConn, chans, reqs)
		clients = append(clients, currentClient)
	}

	targetConn, err := currentClient.Dial("tcp", targetAddr)
	if err != nil {
		return nil, nil, multierr.Combine(
			closeAll(),
			fmt.Errorf("error dialing target %s through jumps: %w", targetAddr, err),
		)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(targetConn, targetAddr, targetConfig)
	if err != nil {
		return nil, nil, multierr.Combine(
			targetConn.Close(),
			closeAll(),
			fmt.Errorf("error creating ssh client for target %s: %w", targetAddr, err),
		)
	}

	targetClient := ssh.NewClient(sshConn, chans, reqs)
	clients = append(clients, targetClient)

	return targetClient, closeAll, nil
}

func configForHost(sshConfig *ssh_config.UserSettings, host string, agent agent.ExtendedAgent) (string, *ssh.ClientConfig, error) {
	khfs, err := sshConfig.GetStrict(host, "UserKnownHostsFile")
	if err != nil {
		return "", nil, fmt.Errorf("error getting UserKnownHostsFile for host %s: %w", host, err)
	}
	akhfs := make([]string, 0)
	for _, khf := range strings.Fields(khfs) {
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
				log.Printf("Warning: UserKnownHostsFile %s does not exist, skipping", akhf)
				continue
			}
			return "", nil, fmt.Errorf("error statting UserKnownHostsFile %s: %w", akhf, err)
		}
		akhfs = append(akhfs, akhf)
	}
	log.Printf("Using known hosts files for host %s: %s", host, strings.Join(akhfs, ", "))
	knownHosts, err := knownhosts.New(akhfs...)
	if err != nil {
		return "", nil, fmt.Errorf("error creating knownhosts callback for host %s: %w", host, err)
	}
	username, err := sshConfig.GetStrict(host, "User")
	if err != nil {
		return "", nil, fmt.Errorf("error getting User for host %s: %w", host, err)
	}
	port, err := sshConfig.GetStrict(host, "Port")
	if err != nil {
		return "", nil, fmt.Errorf("error getting Port for host %s: %w", host, err)
	}
	hostName, err := sshConfig.GetStrict(host, "HostName")
	if err != nil {
		return "", nil, fmt.Errorf("error getting HostName for host %s: %w", host, err)
	}
	if hostName == "" {
		proxyCommand, err := sshConfig.GetStrict(host, "ProxyCommand")
		if err != nil {
			return "", nil, fmt.Errorf("error getting ProxyCommand for host %s: %w", host, err)
		}
		if proxyCommand != "" {
			log.Printf("Fallback to ProxyCommand for HostName %s: %s", host, proxyCommand)
			extractedHostName, _, _, err := parseProxyCommand(proxyCommand)
			if err != nil {
				return "", nil, fmt.Errorf("error parsing ProxyCommand for host %s: %w", host, err)
			}
			log.Printf("Extracted HostName from ProxyCommand for host %s: %s", host, extractedHostName)
			hostName = extractedHostName
		} else {
			hostName = host
		}
	}
	hostKeyAlias, err := sshConfig.GetStrict(host, "HostKeyAlias")
	if err != nil {
		return "", nil, fmt.Errorf("error getting HostKeyAlias for host %s: %w", host, err)
	}
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

func jumphostChainForTarget(conf *ssh_config.UserSettings, host string) ([]string, error) {
	chain := []string{host}

	for {
		jump, err := conf.GetStrict(host, "ProxyJump")
		if err != nil {
			return nil, fmt.Errorf("error getting ProxyJump for host %s: %w", host, err)
		}
		if jump == "" {
			pc, err := conf.GetStrict(host, "ProxyCommand")
			if err != nil {
				return nil, fmt.Errorf("error getting ProxyCommand for host %s: %w", host, err)
			}
			if pc == "" {
				break
			}
			log.Printf("Fallback to ProxyCommand for host %s: %s", host, pc)
			_, _, extracted, err := parseProxyCommand(pc)
			if err != nil {
				return nil, fmt.Errorf("error parsing ProxyCommand for host %s: %w", host, err)
			}
			log.Printf("Extracted jumphost from ProxyCommand for host %s: %s", host, extracted)
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
