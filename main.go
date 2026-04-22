package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"tailscale.com/net/socks5"
)

func main() {
	log.Print("What part of trying to connect to Kubernetes clusters is a fucking living?")

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s mapping_file.json", os.Args[0])
	}
	mappingFile := os.Args[1]
	hostnameMapping, err := loadHostnameMapping(mappingFile)
	if err != nil {
		log.Fatalf("Failed to load hostname mapping: %v", err)
	}

	// TODO(sebastian.widmer) This can in theory be different for different jumphosts, but let's assume it's the same for all of them for now.
	// We can always add support for per-jumphost agent sockets later if needed.
	agentSock, err := ssh_config.GetStrict("6372ffc2-9466-4e89-b60d-14307aa583a5.internal.smart-connect.io", "IdentityAgent")
	if err != nil {
		log.Fatalf("SSH_AUTH_SOCK is not a valid socket: %v", err)
	}
	if agentSock != "" {
		rs, err := replaceTildeWithHome(agentSock)
		if err != nil {
			log.Fatalf("Failed to replace `~/` with home directory in agent socket path: %v", err)
		}
		agentSock = rs
	} else {
		// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			log.Fatal("SSH_AUTH_SOCK is not set")
		}
		agentSock = socket
	}
	log.Printf("Using SSH agent socket: %s", agentSock)
	sshAgentConn, err := net.Dial("unix", agentSock)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	defer sshAgentConn.Close()

	agentClient := agent.NewClient(sshAgentConn)

	d := &sshDialer{
		agent:           agentClient,
		hostnameMapping: hostnameMapping,

		sshManagers: make(map[string]*clientMgr),
	}

	socks5Server := &socks5.Server{
		Logf: log.Printf,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("New SOCKS5 connection %s://%s", network, addr)
			return d.dial(ctx, network, addr)
		},
	}
	log.Print("starting SOCKS5 server on 127.0.0.1:12000")
	listener, err := net.Listen("tcp", "127.0.0.1:12000")
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()
	if err := socks5Server.Serve(listener); err != nil {
		log.Fatalf("SOCKS5 server error: %v", err)
	}
}

func loadHostnameMapping(mappingFile string) ([]hostSuffixJumphostMapping, error) {
	mf, err := os.Open(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file: %w", err)
	}
	defer mf.Close()
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
		return len(b.HostSuffix) - len(a.HostSuffix)
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

	agent           agent.ExtendedAgent
	hostnameMapping []hostSuffixJumphostMapping

	directDialer net.Dialer
}

type clientMgr struct {
	Jumphost string
	Agent    agent.ExtendedAgent

	clientMux sync.Mutex
	client    *ssh.Client
	cleanup   func()
}

func (m *clientMgr) GetClient(ctx context.Context) (*ssh.Client, error) {
	m.clientMux.Lock()
	defer m.clientMux.Unlock()

	if m.client != nil {
		return m.client, nil
	}

	// TODO(sebastian.widmer) Supervision, reconnection, teardown, younameit
	jumphosts, err := jumphostChainForTarget(ssh_config.DefaultUserSettings, m.Jumphost)
	if err != nil {
		return nil, fmt.Errorf("error getting jumphost chain for %s: %w", m.Jumphost, err)
	}

	log.Printf("New connection to %s", strings.Join(jumphosts, "->"))
	configs := make([]sshJump, 0, len(jumphosts))
	for _, jh := range jumphosts {
		jhAddr, jhConfig, err := configForHost(jh, m.Agent)
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
	kat := time.NewTicker(5 * time.Second)
	go func() {
		defer kat.Stop()
		for {
			select {
			case <-kat.C:
				if err := sendKeepAlive(sshc, 3*time.Second); err != nil {
					log.Printf("SSH keepalive failed for jumphost %s: %v", m.Jumphost, err)
					kat.Stop()

					m.clientMux.Lock()
					if m.client != nil && m.client == sshc {
						client := m.client
						cleanup := m.cleanup

						m.client = nil
						m.cleanup = nil
						m.clientMux.Unlock()

						client.Close()
						cleanup()
					} else {
						// Client was already replaced, just unlock and continue with the new one.
						m.clientMux.Unlock()
					}
					return
				}
			case <-keepAliveStopper.Done():
				return
			}
		}
	}()

	m.client = sshc
	m.cleanup = func() {
		stopKeepAlive()
		cleanupSSHC()
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
		if _, _, err := sshc.SendRequest("keepalive@smart-access", true, nil); err != nil {
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
		log.Printf("⌥ %s is direct connection", hostname)
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
			Jumphost: jumphost,
			Agent:    d.agent,
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

// TODO(sebastian.widmer) This is horrible AI code. Refactor to be more readable.
func dialViaProxyJump(targetAddr string, targetConfig *ssh.ClientConfig, jumps []sshJump) (*ssh.Client, func(), error) {
	if len(jumps) == 0 {
		c, err := ssh.Dial("tcp", targetAddr, targetConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("error connecting target %s: %w", targetAddr, err)
		}
		return c, func() {
			_ = c.Close()
		}, nil
	}

	clients := make([]*ssh.Client, 0, len(jumps)+1)

	closeAll := func() {
		for i := len(clients) - 1; i >= 0; i-- {
			_ = clients[i].Close()
		}
	}

	currentClient, err := ssh.Dial("tcp", jumps[0].Addr, jumps[0].Config)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting jump 0 (%s): %w", jumps[0].Addr, err)
	}
	clients = append(clients, currentClient)

	for i := 1; i < len(jumps); i++ {
		nextConn, err := currentClient.Dial("tcp", jumps[i].Addr)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("error dialing jump %d (%s): %w", i, jumps[i].Addr, err)
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(nextConn, jumps[i].Addr, jumps[i].Config)
		if err != nil {
			_ = nextConn.Close()
			closeAll()
			return nil, nil, fmt.Errorf("error creating client for jump %d (%s): %w", i, jumps[i].Addr, err)
		}

		currentClient = ssh.NewClient(sshConn, chans, reqs)
		clients = append(clients, currentClient)
	}

	targetConn, err := currentClient.Dial("tcp", targetAddr)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("error dialing target %s through jumps: %w", targetAddr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(targetConn, targetAddr, targetConfig)
	if err != nil {
		_ = targetConn.Close()
		closeAll()
		return nil, nil, fmt.Errorf("error creating ssh client for target %s: %w", targetAddr, err)
	}

	targetClient := ssh.NewClient(sshConn, chans, reqs)
	clients = append(clients, targetClient)

	var once sync.Once
	cleanup := func() {
		once.Do(closeAll)
	}

	return targetClient, cleanup, nil
}

func configForHost(host string, agent agent.ExtendedAgent) (string, *ssh.ClientConfig, error) {
	khfs, err := ssh_config.GetStrict(host, "UserKnownHostsFile")
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
	username, err := ssh_config.GetStrict(host, "User")
	if err != nil {
		return "", nil, fmt.Errorf("error getting User for host %s: %w", host, err)
	}
	port, err := ssh_config.GetStrict(host, "Port")
	if err != nil {
		return "", nil, fmt.Errorf("error getting Port for host %s: %w", host, err)
	}
	hostName, err := ssh_config.GetStrict(host, "HostName")
	if err != nil {
		return "", nil, fmt.Errorf("error getting HostName for host %s: %w", host, err)
	}
	if hostName == "" {
		proxyCommand, err := ssh_config.GetStrict(host, "ProxyCommand")
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
	hostKeyAlias, err := ssh_config.GetStrict(host, "HostKeyAlias")
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
