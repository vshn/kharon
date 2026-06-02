package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
)

//go:embed kharon.rb
var caskTemplate string

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <version> <checksum.txt>\n", os.Args[0])
		os.Exit(1)
	}

	t, err := template.New("kharon.rb").Parse(caskTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing template: %v\n", err)
		os.Exit(1)
	}

	checkums, err := parseChecksums(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing checksums: %v\n", err)
		os.Exit(1)
	}

	if err := t.Execute(os.Stdout, map[string]string{
		"version":             os.Args[1],
		"sha256_arm":          mustFind(checkums, "kharon-darwin-aarch64"),
		"sha256_x86_64_linux": mustFind(checkums, "kharon-linux-x86_64"),
		"sha256_arm64_linux":  mustFind(checkums, "kharon-linux-aarch64"),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing template: %v\n", err)
		os.Exit(1)
	}
}

func mustFind(m map[string]string, key string) string {
	value, ok := m[key]
	if !ok {
		fmt.Fprintf(os.Stderr, "Checksum for %s not found. Checksums: %v\n", key, m)
		os.Exit(1)
	}
	return value
}

func parseChecksums(filePath string) (map[string]string, error) {
	checksums := make(map[string]string)

	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open checksum file: %w", err)
	}

	for line := range bytes.Lines(file) {
		line = bytes.TrimSpace(line)
		sum, filename, found := bytes.Cut(line, []byte("  "))
		if !found {
			continue
		}
		checksums[string(filename)] = string(sum)
	}
	return checksums, nil
}
