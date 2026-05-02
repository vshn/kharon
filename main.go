package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vshn/kharon/internal/pkg/proxy"
)

func main() {
	log.Print("What part of trying to connect to Kubernetes clusters is a fucking living?")

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s mapping_file.json", os.Args[0])
	}
	mappingFile := os.Args[1]

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

	if err := proxy.Start(ctx, "127.0.0.1:12000", mappingFile); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
