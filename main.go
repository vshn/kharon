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

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"tailscale.com/net/socks5"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s mapping_file.json", os.Args[0])
	}
	mappingFile := os.Args[1]
	mappingRaw, err := os.ReadFile(mappingFile)
	if err != nil {
		log.Fatalf("Failed to read mapping file: %v", err)
	}
	var hostnameMapping map[string]string
	if err := json.Unmarshal(mappingRaw, &hostnameMapping); err != nil {
		log.Fatalf("Failed to parse mapping file: %v", err)
	}

	// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		log.Fatal("SSH_AUTH_SOCK is not set")
	}
	log.Printf("Using SSH agent socket: %s", socket)

	sshAgentConn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	defer sshAgentConn.Close()

	agentClient := agent.NewClient(sshAgentConn)

	d := &sshDialer{
		agent:           agentClient,
		hostnameMapping: hostnameMapping,

		openSSHConnections: make(map[string]*ssh.Client),
	}

	socks5Server := &socks5.Server{
		Logf: log.Printf,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("Dialing %s://%s through proxy", network, addr)
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

type sshDialer struct {
	openSSHConnectionsMux sync.Mutex
	openSSHConnections    map[string]*ssh.Client

	agent           agent.ExtendedAgent
	hostnameMapping map[string]string
}

func (d *sshDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("error splitting host and port for %s: %w", addr, err)
	}

	var jumphost string
	for h, jh := range d.hostnameMapping {
		if strings.HasSuffix(hostname, h) {
			jumphost = jh
			break
		}
	}

	if jumphost == "" {
		log.Printf("No jumphosts configured for %s, dialing directly", addr)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	// TODO(sebastian.widmer) Per jumphost connection pooling to not block multiple connections on SSH connection setup.
	getClient := func() (*ssh.Client, error) {
		d.openSSHConnectionsMux.Lock()
		defer d.openSSHConnectionsMux.Unlock()

		existingSSH, ok := d.openSSHConnections[addr]
		if ok {
			log.Printf("Reusing existing SSH connection for %s", addr)
			return existingSSH, nil
		}

		jumphosts, err := jumphostChainForTarget(jumphost)
		if err != nil {
			return nil, fmt.Errorf("error getting jumphost chain for %s: %w", jumphost, err)
		}

		log.Printf("New connection for %s through jumphosts: %v", addr, strings.Join(jumphosts, "->"))
		configs := make([]sshJump, 0, len(jumphosts))
		for _, jh := range jumphosts {
			jhAddr, jhConfig, err := configForHost(jh, d.agent)
			if err != nil {
				return nil, fmt.Errorf("error getting SSH config for jumphost %s: %w", jh, err)
			}
			configs = append(configs, sshJump{
				Addr:   jhAddr,
				Config: jhConfig,
			})
		}

		target := configs[len(configs)-1]
		sshc, _, err := dialViaProxyJump(target.Addr, target.Config, configs[:len(configs)-1])
		if err != nil {
			return nil, fmt.Errorf("error dialing target %s through jumphosts: %w", addr, err)
		}

		d.openSSHConnections[addr] = sshc

		return sshc, nil
	}

	sshc, err := getClient()
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
		for i := range clients {
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
		if strings.HasPrefix(khf, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", nil, fmt.Errorf("error getting user home directory: %w", err)
			}
			khf = filepath.Join(home, khf[2:])
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

func jumphostChainForTarget(host string) ([]string, error) {
	chain := []string{host}

	for {
		jump, err := ssh_config.GetStrict(host, "ProxyJump")
		if err != nil {
			return nil, fmt.Errorf("error getting ProxyJump for host %s: %w", host, err)
		}
		if jump == "" {
			pc, err := ssh_config.GetStrict(host, "ProxyCommand")
			if err != nil {
				return nil, fmt.Errorf("error getting ProxyCommand for host %s: %w", host, err)
			}
			if pc != "" {
				log.Printf("Fallback to ProxyCommand for host %s: %s", host, pc)
				_, _, extracted, err := parseProxyCommand(pc)
				if err != nil {
					return nil, fmt.Errorf("error parsing ProxyCommand for host %s: %w", host, err)
				}
				log.Printf("Extracted jumphost from ProxyCommand for host %s: %s", host, extracted)
				chain = append(chain, extracted)
				break
			}
			break
		}
		if strings.Contains(jump, ",") {
			return nil, fmt.Errorf("multiple ProxyJump entries for host %s are not supported", host)
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
