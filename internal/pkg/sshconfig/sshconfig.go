package sshconfig

import (
	"bufio"
	"bytes"
	"io"
	"os/exec"
	"strings"
	"sync"
)

type SSHConfigWithCache struct {
	c     SSHConfig
	cache sync.Map
}

// NewSSHConfigWithCache creates a new SSHConfigWithCache with the given SSH configuration file.
// The SSH configuration for each host will be cached after the first retrieval to improve performance on subsequent requests.
// If configFile is empty, the default SSH configuration will be used.
func NewSSHConfigWithCache(configFile string) *SSHConfigWithCache {
	return &SSHConfigWithCache{
		c: SSHConfig{ConfigFile: configFile},
	}
}

// ConfigForHost returns the SSH configuration for the given host, using a cache to avoid redundant calls to "ssh -G" for the same host.
func (s *SSHConfigWithCache) ConfigForHost(h string) (Config, error) {
	value, _ := s.cache.LoadOrStore(h, sync.OnceValues(func() (Config, error) {
		return s.c.ConfigForHost(h)
	}))
	return value.(func() (Config, error))()
}

// SSHConfig represents the SSH configuration and provides a method to retrieve the configuration for a specific host.
// It uses the "ssh -G" command to get the effective SSH configuration for a host, which takes into account all SSH configuration files and rules.
type SSHConfig struct {
	// ConfigFile is the path to the SSH configuration file to use. If empty, the default SSH configuration will be used.
	ConfigFile string
}

// ConfigForHost returns the SSH configuration for the given host by invoking "ssh -G" and parsing its output.
func (s SSHConfig) ConfigForHost(h string) (Config, error) {
	args := []string{"-G", h}
	if s.ConfigFile != "" {
		args = append([]string{"-F", s.ConfigFile}, args...)
	}
	c := exec.Command("ssh", args...)
	out, err := c.StdoutPipe()
	if err != nil {
		return Config{}, err
	}
	if err := c.Start(); err != nil {
		return Config{}, err
	}
	cm := make(map[string][]string)
	if err := newDecoder(out).Decode(&cm); err != nil {
		return Config{}, err
	}
	return Config{config: cm}, c.Wait()
}

// Config represents the SSH configuration for a specific host, allowing retrieval of configuration values.
type Config struct {
	config map[string][]string
}

// Get returns the first value for the given SSH configuration key, or an empty string if the key is not set.
func (c *Config) Get(key string) string {
	values := c.config[strings.ToLower(key)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// GetAll returns all values for the given SSH configuration key, or an empty slice if the key is not set.
func (c *Config) GetAll(key string) []string {
	return c.config[strings.ToLower(key)]
}

type decoder struct {
	scanner *bufio.Scanner
}

func newDecoder(r io.Reader) *decoder {
	return &decoder{
		scanner: bufio.NewScanner(r),
	}
}

func (p *decoder) Decode(out *map[string][]string) error {
	for p.scanner.Scan() {
		line := p.scanner.Bytes()
		before, after, found := bytes.Cut(line, []byte(" "))
		if !found {
			continue
		}
		key := string(bytes.ToLower(bytes.TrimSpace(before)))
		value := string(bytes.TrimSpace(after))
		(*out)[key] = append((*out)[key], value)
	}
	return p.scanner.Err()
}
