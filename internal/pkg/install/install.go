package install

import (
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

const launchdServiceFilePath = "~/Library/LaunchAgents/io.vshn.Kharon.plist"
const launchdServiceLabel = "io.vshn.Kharon"

//go:embed io.vshn.Kharon.plist
var launchdService string

const systemdServiceFilePath = "~/.config/systemd/user/kharon.service"
const systemdSocketFilePath = "~/.config/systemd/user/kharon.socket"

//go:embed kharon.service
var systemdService string

//go:embed kharon.socket
var systemdSocket string

var userHomeFunc = os.UserHomeDir

var stdin = os.Stdin

func InstallLaunchdService() error {
	home, err := userHomeFunc()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	launchdServiceFilePath := strings.ReplaceAll(launchdServiceFilePath, "~", home)

	exists, err := fileExists(launchdServiceFilePath)
	if err != nil {
		return fmt.Errorf("failed to check if launchd service file exists: %w", err)
	}
	fmt.Printf("The following launchd service will be installed to %s:\n", color.CyanString(launchdServiceFilePath))
	fmt.Println(renderLaunchdService(home, binaryPath, "12000", true))
	installAction := "Install launchd service to"
	if exists {
		installAction = "Overwrite existing launchd service at"
	}
	if !proceedPrompt(fmt.Sprintf("%s %s?", installAction, color.CyanString(launchdServiceFilePath))) {
		fmt.Println("Installation cancelled.")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(launchdServiceFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for launchd service file: %w", err)
	}
	if err := os.WriteFile(launchdServiceFilePath, []byte(renderLaunchdService(home, binaryPath, "12000", false)), 0644); err != nil {
		return fmt.Errorf("failed to write launchd service file: %w", err)
	}
	launchctlDomain := fmt.Sprintf("gui/%d", os.Getuid())

	slog.Info("Attempting to bootout existing launchd service (if loaded)", "domain", launchctlDomain, "label", launchdServiceLabel)
	if err := runCommand("launchctl", "bootout", launchctlDomain+"/"+launchdServiceLabel); err != nil {
		if eerr, ok := errors.AsType[*exec.ExitError](err); ok && eerr.ExitCode() != 3 {
			slog.Warn("Failed to bootout existing launchd service.", "error", err)
		}
	}

	slog.Info("Bootstrapping launchd service", "domain", launchctlDomain, "label", launchdServiceLabel)
	if err := runCommand("launchctl", "bootstrap", launchctlDomain, launchdServiceFilePath); err != nil {
		return fmt.Errorf("failed to bootstrap launchd service: %w", err)
	}

	return nil
}

func InstallSystemdService() error {
	return nil
}

func runCommand(name string, args ...string) error {
	color.New(color.Bold).Printf("> %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func renderLaunchdService(home, exe, port string, colorize bool) string {
	if colorize {
		home = color.BlueString(home)
		exe = color.MagentaString(exe)
		port = color.GreenString(port)
	}
	service := launchdService
	service = strings.ReplaceAll(service, "{{HOME}}", home)
	service = strings.ReplaceAll(service, "{{EXECUTABLE}}", exe)
	service = strings.ReplaceAll(service, "{{PORT}}", port)
	return service
}

func proceedPrompt(question string) bool {
	if question == "" {
		question = "Do you want to proceed?"
	}
	fmt.Print(question + " (y/N): ")

	var response string
	if _, err := fmt.Fscanln(stdin, &response); err != nil {
		slog.Debug("Failed to read user input, assuming 'no'", "error", err)
		return false
	}
	return strings.ToLower(response) == "y"
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
