# kharon

<p align="center">
  <img width=256px src="./assets/Gustave_Doré_-_Dante_Alighieri_-_Inferno_-_Plate_9_(Canto_III_-_Charon)_medium.jpeg" alt="Gustave Doré's engravings illustrated the Divine Comedy (1861–1868); here Charon comes to ferry souls across the river Acheron to Hell" /><br />
<i>Kharon ferries your connections safely across <del>the river Styx</del> SSH jumphosts into <del>the underworld</del> private networks.</i>
</p>

Kharon is a smart cluster access solution tailored to VSHNs management of Kubernetes clusters over SSH jumphosts.

Starts a socks5 proxy that automatically routes cluster domains of configured jumphosts.

## Usage

### Requirements

The tool has only been tested on Linux and macOS, but should work on any platform supported by Go and OpenSSH.

Currently the tool relies on a SSH agent running. Either the `SSH_AUTH_SOCK` environment variable must be set, or a globally set `IdentityAgent` in the SSH config must be present.

### Setup

Setup [SSH Jumphost (sshop)](https://vshnwiki.atlassian.net/wiki/spaces/VT/pages/8291275/SSH+Jumphost+sshop).

Pull jumphost configuration and cluster inventory from Lieutenant:

```sh
go run . update
```

Start the proxy:

```sh
go run . proxy
```

Point your browser to `socks5h://localhost:12000` or get a shell with environment and kube configs set up:

```sh
go run . shell
```

There are sample `systemd`/`launchd` unit files in the `os/` directory.
