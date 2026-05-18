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

Install `kharon` in your `PATH` by either downloading the [latest release](https://github.com/vshn/kharon/releases/latest) or building from source:

```sh
make build
mv kharon ~/.local/bin
# Ensure kharon can be executed from your PATH
kharon help
```

Pull the latest cluster and jumphost information from the API:

```sh
kharon update
```

Install the proxy with the interactive installer:

```sh
# This will install a systemd/launchd unit interactively.
# The proxy will be set up in "on-demand" mode, which means it will only start when
# a connection is made to the proxy port and will stop after a period of inactivity.
# Don't forget to setup auto-complete for your shell of choice, the installer will remind you to do so!
kharon install
```

[Point your browser](./docs/setup) to `socks5h://localhost:12000` or get a shell with environment and kube configs set up:

```sh
kharon shell
```

or login to your cluster of choice directly (the APPUiO lab cluster is a good candidate for testing):

```sh
kharon oc-web-login c-appuio-lab-cloudscale-rma-0
```
