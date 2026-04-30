# smart-access

Smart cluster access solution tailored to VSHNs management of Kubernetes clusters over SSH jumphosts.

Starts a socks5 proxy that automatically routes cluster domains of configured jumphosts.

## Usage

### Requirements

The tool has only been tested on Linux and macOS, but should work on any platform supported by Go and OpenSSH.

Currently the tool relies on a SSH agent running. Either the `SSH_AUTH_SOCK` environment variable must be set, or a globally set `IdentityAgent` in the SSH config must be present.

### Setup

Setup [SSH Jumphost (sshop)](https://vshnwiki.atlassian.net/wiki/spaces/VT/pages/8291275/SSH+Jumphost+sshop).

Download a copy of https://git.vshn.net/vshn/openshift4-clusters/-/raw/main/domain_jumphost_mapping.json?ref_type=heads.

```sh
go run . domain_jumphost_mapping.json
```

Point your browser or `kubectl`/`oc` to `socks5h://localhost:12000`.

There are sample `systemd`/`launchd` unit files in the `os/` directory.
