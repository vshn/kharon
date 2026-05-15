package cmd

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/activation"
	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/proxy"
)

const defaultProxyAddr = "localhost:12000"

var addr, onDemand, proxyMappingFile string
var onDemandShutdownTimeout time.Duration

func init() {
	RootCmd.AddCommand(proxyCmd)

	flag := proxyCmd.Flags()
	flag.StringVar(&addr, "addr", defaultProxyAddr, "Address to bind the proxy to in the format <host>:<port>. If port is set to 0, a random free port will be used.")
	flag.StringVar(&onDemand, "on-demand", "", "On-demand allows the proxy to start from launchd or systemd when a connection is attempted. Value can be '-on-demand=launchd=<SocketName>' or '-on-demand=systemd=<my-socket.socket>'. The proxy will shut down after the specified timeout when no active connections are present.")
	flag.StringVar(&proxyMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file. This file can be generated with the `update` subcommand and should be kept up to date. The proxy will watch for SIGHUP to reload the mapping without restarting.")
	flag.DurationVar(&onDemandShutdownTimeout, "on-demand-shutdown-timeout", 3*time.Minute, "Timeout for shutting down the proxy when no active connections are present in on-demand mode. Zero disables automatic shutdown.")
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a SOCKS5 proxy server for accessing Kubernetes clusters.",
	Long:  "Start a SOCKS5 proxy server that listens for incoming connections and forwards them to the appropriate Kubernetes cluster based on the provided domain to jumphost mapping file. The proxy supports on-demand activation via launchd or systemd and can automatically shut down after a specified timeout when no active connections are present.",
	Run:   runProxy,
}

func runProxy(cmd *cobra.Command, _ []string) {
	slog.Info("What part of trying to connect to Kubernetes clusters is a fucking living?")

	if proxyMappingFile == "" {
		slog.Error("Mapping file path is required", "error", "mapping-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	proxy := proxy.Proxy{}

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go func() {
		for range sighup {
			slog.Info("Received SIGHUP, reloading configuration...")
			if err := proxy.Reload(proxyMappingFile); err != nil {
				slog.Error("Failed to reload configuration", slog.Any("error", err))
			}
		}
	}()

	lp := func() (net.Listener, error) {
		return net.Listen("tcp", addr)
	}
	if onDemand != "" {
		proxy.ShutdownTimeout = onDemandShutdownTimeout

		init, opt, hasOpt := strings.Cut(onDemand, "=")
		switch init {
		case "launchd":
			if !hasOpt {
				slog.Error("launchd on-demand requires a socket name, e.g. '-on-demand=launchd=MySocket'")
				os.Exit(1)
			}
			lp = activation.LaunchdListener(opt)
		case "systemd":
			if !hasOpt {
				slog.Error("systemd on-demand requires a systemd socket unit name, e.g. '-on-demand=systemd=<my-socket.socket>'")
				os.Exit(1)
			}
			lp = activation.SystemdListener(opt)
		default:
			slog.Error("Invalid on-demand initializer, must be 'launchd' or 'systemd'", slog.String("value", init))
			os.Exit(1)
		}
	}

	if err := proxy.Start(ctx, lp, proxyMappingFile); err != nil {
		slog.Error("Failed to start proxy", slog.Any("error", err))
		os.Exit(1)
	}
}

func proxyMappingFilePath() string {
	cd, err := cache.ProxyMappingFilePath()
	if err != nil {
		slog.Warn("Failed to get proxy mapping file path", slog.Any("error", err))
		return ""
	}
	return cd
}
