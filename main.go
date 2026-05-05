package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vshn/kharon/internal/pkg/proxy"
)

func main() {
	log.Print("What part of trying to connect to Kubernetes clusters is a fucking living?")

	var addr string
	flag.StringVar(&addr, "addr", "127.0.0.1:12000", "Address to bind the proxy to in the format <host>:<port>. If port is set to 0, a random free port will be used.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] mapping_file.json\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

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
			log.Print("Received SIGHUP, reloading configuration...")
			if err := proxy.Reload(mappingFile); err != nil {
				log.Printf("Failed to reload configuration: %v", err)
			}
		}
	}()

	if err := proxy.Start(ctx, addr, mappingFile); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
