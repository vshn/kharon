package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/vshn/kharon/internal/pkg/proxy"
)

func main() {
	log.Print("What part of trying to connect to Kubernetes clusters is a fucking living?")

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s mapping_file.json", os.Args[0])
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var proxy proxy.Proxy
	if err := proxy.Start(ctx, "127.0.0.1:12000", os.Args[1]); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
