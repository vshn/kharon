package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

const defaultLieutenantURL = "https://api.syn.vshn.net"

var updateMappingFile, updateInventoryFile string
var lieutenantAPIURL string

func init() {
	RootCmd.AddCommand(updateCmd)

	flag := updateCmd.Flags()
	flag.StringVar(&updateMappingFile, "mapping-file", proxyMappingFilePath(), "Path to the domain to jumphost mapping file that should be written by this command.")
	flag.StringVar(&updateInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be written by this command.")
	flag.StringVar(&lieutenantAPIURL, "lieutenant-url", lieutenantURLFromEnvOrDefault(), "URL of the Lieutenant API.")
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the proxy configuration.",
	Long:  "Update the proxy configuration by loading the latest domain to jumphost mapping file from Lieutenant.",
	Run:   runUpdate,
}

func runUpdate(cmd *cobra.Command, args []string) {
	if updateMappingFile == "" {
		slog.Error("Mapping file path is required", "error", "mapping-file flag is empty and failed to determine default path.")
		os.Exit(1)
	}

	if lieutenantAPIURL == "" {
		slog.Error("Neither --lieutenant-url flag nor LIEUTENANT_URL or COMMODORE_API_URL environment variables are set. One of these is required to determine the Lieutenant API URL.")
		os.Exit(1)
	}

	clusters, err := lieutenant.NewClient(lieutenantAPIURL, nil).GetClusters(cmd.Context())
	if err != nil {
		slog.Error("Failed to get clusters", "error", err)
		os.Exit(1)
	}

	if err := cache.WriteInventoryFile(updateInventoryFile, clusters); err != nil {
		slog.Error("Failed to write inventory file", "error", err)
		os.Exit(1)
	}
	slog.Info("Wrote cluster inventory to file.", "file", updateInventoryFile)
	mapping, err := lieutenant.JumphostMappingFromClusters(clusters)
	if err != nil {
		slog.Warn("Jumphost mapping may be incomplete", "error", err)
	}
	if err := cache.WriteProxyMappingFile(updateMappingFile, mapping); err != nil {
		slog.Error("Failed to write proxy mapping file", "error", err)
		os.Exit(1)
	}
	slog.Info("Wrote domain to jumphost mapping to file.", "file", updateMappingFile)

	if err := sendSIGHUP(); err != nil {
		slog.Warn("Failed to send SIGHUP signal to kharon processes", "error", err)
	}
}

// sendSIGHUP sends a SIGHUP signal to all running kharon processes to trigger a reload of the configuration.
func sendSIGHUP() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cmd := exec.Command("pkill", "-SIGHUP", "-f", fmt.Sprintf("%s%s", regexp.QuoteMeta(filepath.Base(self)), ".+proxy"))
	if err := cmd.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			// pkill returns exit code 1 if no process was matched, which is not an error in this case.
			// Command errors are from exit code 2 and above.
			if exitErr.ExitCode() == 1 {
				slog.Info("No kharon processes found to send SIGHUP signal to or no signal could be sent.")
				return nil
			}
		}
		return fmt.Errorf("failed to send SIGHUP signal: %w", err)
	}
	return nil
}

// lieutenantURLFromEnvOrDefault returns the Lieutenant API URL from the LIEUTENANT_URL environment variable if set,
// otherwise from the COMMODORE_API_URL environment variable if set,
// and if neither is set, it returns the defaultLieutenantURL.
func lieutenantURLFromEnvOrDefault() string {
	apiURL := os.Getenv("LIEUTENANT_URL")
	if apiURL == "" {
		apiURL = os.Getenv("COMMODORE_API_URL")
	}
	if apiURL == "" {
		apiURL = defaultLieutenantURL
	}
	return apiURL
}

func inventoryFilePath() string {
	cd, err := cache.InventoryFilePath()
	if err != nil {
		slog.Warn("Failed to get inventory file path", slog.Any("error", err))
		return ""
	}
	return cd
}
