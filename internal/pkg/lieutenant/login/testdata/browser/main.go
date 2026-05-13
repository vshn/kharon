package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: browser <url>")
		os.Exit(1)
	}
	url := os.Args[1]

	fmt.Println(">", url)
	r, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to make GET request: %v\n", err)
		os.Exit(1)
	}
	defer r.Body.Close()
	defer io.Copy(io.Discard, r.Body)

	fmt.Println("<", r.Status, r.Request.URL.String())
	fmt.Println(r.Header)
}
