package main

import (
	"log"
	"os"

	"github.com/bastjan/smart-access/internal/pkg/proxy"
	"github.com/kevinburke/ssh_config"
)

func main() {
	log.Print("What part of trying to connect to Kubernetes clusters is a fucking living?")

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s mapping_file.json", os.Args[0])
	}

	if err := proxy.Start(os.Args[1], ssh_config.DefaultUserSettings); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
