package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/vshn/kharon/internal/pkg/proxy"
)

func main() {
	slog.Info("What part of trying to connect to Kubernetes clusters is a fucking living?")

	var addr string
	var verbosity int
	flag.StringVar(&addr, "addr", "127.0.0.1:12000", "Address to bind the proxy to in the format <host>:<port>. If port is set to 0, a random free port will be used.")
	flag.IntVar(&verbosity, "v", 0, "Verbosity level for logging. Lower values produce more detailed logs. Default is 0 (info). See https://pkg.go.dev/log/slog#Level for thresholds.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] mapping_file.json\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	slog.SetLogLoggerLevel(slog.Level(verbosity))

	mappingFile := flag.Arg(0)
	if mappingFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var proxy proxy.Proxy

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go func() {
		for range sighup {
			slog.Info("Received SIGHUP, reloading configuration...")
			if err := proxy.Reload(mappingFile); err != nil {
				slog.Error("Failed to reload configuration", slog.Any("error", err))
			}
		}
	}()

	if err := proxy.Start(ctx, addr, mappingFile); err != nil {
		slog.Error("Failed to start proxy", slog.Any("error", err))
		os.Exit(1)
	}
}
