package main

import (
	"github.com/vshn/kharon/internal/pkg/activation"
)

func main() {
	listener, err := activation.SystemdListener("activation.socket")()
	if err != nil {
		panic(err)
	}

	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	conn.Write([]byte("Hello from systemd socket activation!\n"))

	return
}
