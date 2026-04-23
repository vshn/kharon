package main

import (
	"path/filepath"
	"testing"

	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/assert"
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
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_loadHostnameMapping(t *testing.T) {
	loaded, err := loadHostnameMapping(filepath.Join("testdata", "mapping.json"))
	assert.NoError(t, err)
	assert.Equal(t, []hostSuffixJumphostMapping{
		{HostSuffix: "api.c-bettersmarter-prod01.vshnmanaged.net", Jumphost: "jumphost2"},
		{HostSuffix: "c-bettersmarter-prod01.vshnmanaged.net", Jumphost: "jumphost1"},
		{HostSuffix: "a.storage.bettersmarter.ch", Jumphost: "jumphost4"},
		{HostSuffix: "b.storage.bettersmarter.ch", Jumphost: "jumphost5"},
		{HostSuffix: "c.storage.bettersmarter.ch", Jumphost: "jumphost6"},
		{HostSuffix: "vcenter.bettersmarter.ch", Jumphost: "jumphost3"},
	}, loaded)
}
