package install

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
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
var uidFunc = os.Getuid

var stdin = io.Reader(os.Stdin)

// InstallLaunchdService installs the kharon launchd service with on-demand activation.
// Prompts the user for confirmation before installing or overwriting the service file.
// The service file will be created in the user's home directory under ~/Library/LaunchAgents.
// If yes is true, the user will not be prompted and the service will be installed or overwritten without confirmation.
func InstallLaunchdService(yes bool) error {
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
	fmt.Println(renderUnit(launchdService, home, binaryPath, "12000", true))
	installAction := "Install launchd service to"
	if exists {
		installAction = "Overwrite existing launchd service at"
	}
	if !yes && !proceedPrompt(fmt.Sprintf("%s %s?", installAction, color.CyanString(launchdServiceFilePath))) {
		fmt.Println("Installation cancelled.")
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(launchdServiceFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for launchd service file: %w", err)
	}
	if err := forceOverwriteFile(launchdServiceFilePath, renderUnit(launchdService, home, binaryPath, "12000", false)); err != nil {
		return fmt.Errorf("failed to write launchd service file: %w", err)
	}
	launchctlDomain := fmt.Sprintf("gui/%d", uidFunc())

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

// InstallSystemdService installs the kharon systemd service and socket with on-demand activation.
// Prompts the user for confirmation before installing or overwriting the service and socket files.
// The service and socket files will be created in the user's home directory under ~/.config/systemd/user.
// If yes is true, the user will not be prompted and the service and socket will be installed or overwritten without confirmation.
func InstallSystemdService(yes bool) error {
	home, err := userHomeFunc()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	systemdServiceFilePath := strings.ReplaceAll(systemdServiceFilePath, "~", home)
	systemdSocketFilePath := strings.ReplaceAll(systemdSocketFilePath, "~", home)

	for _, unit := range []struct {
		path    string
		content string
	}{
		{systemdServiceFilePath, systemdService},
		{systemdSocketFilePath, systemdSocket},
	} {
		exists, err := fileExists(unit.path)
		if err != nil {
			return fmt.Errorf("failed to check if systemd unit file exists: %w", err)
		}
		fmt.Printf("The following systemd unit will be installed to %s:\n", color.CyanString(unit.path))
		fmt.Println(renderUnit(unit.content, home, binaryPath, "12000", true))
		installAction := "Install systemd unit to"
		if exists {
			installAction = "Overwrite existing systemd unit at"
		}
		if !yes && !proceedPrompt(fmt.Sprintf("%s %s?", installAction, color.CyanString(unit.path))) {
			fmt.Println("Installation cancelled.")
			return nil
		}

		if err := os.MkdirAll(filepath.Dir(unit.path), 0755); err != nil {
			return fmt.Errorf("failed to create directory for systemd unit file: %w", err)
		}
		if err := forceOverwriteFile(unit.path, renderUnit(unit.content, home, binaryPath, "12000", false)); err != nil {
			return fmt.Errorf("failed to write systemd unit file: %w", err)
		}
	}

	slog.Info("Bootstrapping systemd service")
	if err := runCommand("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd user daemon: %w", err)
	}
	if err := runCommand("systemctl", "--user", "enable", filepath.Base(systemdSocketFilePath)); err != nil {
		return fmt.Errorf("failed to enable and start systemd socket: %w", err)
	}
	if err := runCommand("systemctl", "--user", "enable", "--now", filepath.Base(systemdServiceFilePath)); err != nil {
		return fmt.Errorf("failed to enable and start systemd service: %w", err)
	}

	return nil
}

// ShellCompletionNotice prints a notice about shell completion support and instructions to enable it.
func ShellCompletionNotice() {
	fmt.Println(color.GreenString("Kharon supports shell completion."))
	fmt.Println("To enable shell completion, add the following line to your shell configuration file (e.g., ~/.bashrc or ~/.zshrc):")
	fmt.Println(color.CyanString("source <(kharon completion bash)  # for bash"))
	fmt.Println(color.CyanString("source <(kharon completion zsh)   # for zsh"))
	fmt.Println(color.CyanString("kharon completion fish | source   # for fish"))
}

// BrowserSetupNotice prints a notice about browser setup to use the proxy.
func BrowserSetupNotice() {
	fmt.Println()
	fmt.Println(color.GreenString("Don't forget to setup your browser to use the proxy!"))
	fmt.Printf("Check %s for instructions.\n", color.CyanString("https://github.com/vshn/kharon/tree/main/docs/setup"))
}

func forceOverwriteFile(path, content string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing file: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

func runCommand(name string, args ...string) error {
	_, _ = color.New(color.Bold).Printf("> %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func renderUnit(template, home, exe, port string, colorize bool) string {
	if colorize {
		home = color.BlueString(home)
		exe = color.MagentaString(exe)
		port = color.GreenString(port)
	}
	template = strings.ReplaceAll(template, "{{HOME}}", home)
	template = strings.ReplaceAll(template, "{{EXECUTABLE}}", exe)
	template = strings.ReplaceAll(template, "{{PORT}}", port)
	return template
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
