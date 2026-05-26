package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vshn/kharon/internal/pkg/cache"
	"github.com/vshn/kharon/internal/pkg/completion"
	"github.com/vshn/kharon/internal/pkg/emcred"
	"github.com/vshn/kharon/internal/pkg/kubeconfig"
	"github.com/vshn/kharon/internal/pkg/lieutenant"
)

func init() {
	RootCmd.AddCommand(emergencyCredentialsCmd)

	flag := emergencyCredentialsCmd.Flags()
	flag.StringVar(&clustersInventoryFile, "inventory-file", inventoryFilePath(), "Path to the inventory file that should be used by this command.")
	flag.StringVar(&proxyAddr, "proxy-addr", defaultProxyAddr, "Address of the proxy to use in the generated kubeconfig file.")
}

const emergencyCredentialsCmdLongDesc = `Log in to OpenShift clusters with emergency credentials.

This command retrieves emergency credentials for the current cluster, or the specified cluster, decrypted with your Passbolt private key, and inserts them into the kubeconfig file for immediate use.
The credentials are stored in kubeconfig contexts named "emergency-credentials/<index>/<cluster-id>" and can be used like any other context.
The command requires the Passbolt private key, passphrase, and TOTP code to retrieve the credentials, which can be provided via environment variables or prompted for interactively.

See https://kb.vshn.ch/oc4/references/architecture/emergency_credentials.html for more details on how the emergency credentials are stored and how they are retrieved and decrypted by this command.

The command will first look for the Passbolt private key in the config file created by this command, then in the KHARON_PASSBOLT_KEY environment variable, and if not found, it will prompt the user to paste the key.
You can find the key at https://cloud.passbolt.com/vshn/app/settings/keys.
The passphrase and TOTP code are also first looked up in the environment variables KHARON_PASSBOLT_PASSPHRASE and KHARON_PASSBOLT_TOTP, respectively, before prompting the user.
The passbolt key is stored in the config file for future use, but the passphrase and TOTP code are not stored and must be provided each time.

The command tries to reuse the stored key from the legacy config file created by the "emergency-credentials-receive" command, so if you have previously run that command and stored the key there, it will be used automatically.

Works on the inventory downloaded by the 'update' command, so it does not require access to the Lieutenant API.`

const emergencyCredentialsCmdExample = `# Login to the current cluster with emergency credentials
kharon emergency-credentials

# Login to a specific cluster with emergency credentials
kharon emergency-credentials c-12345`

var emergencyCredentialsCmd = &cobra.Command{
	Use:     "emergency-credentials [c-cluster-id]",
	Short:   "Log in to OpenShift clusters with emergency credentials.",
	Long:    emergencyCredentialsCmdLongDesc,
	Example: emergencyCredentialsCmdExample,
	RunE:    runEmergencyCredentials,
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.ClusterID(clustersInventoryFile, func(cluster lieutenant.Cluster) bool {
		api, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
		return api != ""
	}),
}

func runEmergencyCredentials(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	var clusterID string
	if len(args) > 0 {
		clusterID = args[0]
	}

	if clustersInventoryFile == "" {
		return fmt.Errorf("inventory-file flag is empty and failed to determine default path")
	}

	clusters, err := cache.ReadInventoryFile(clustersInventoryFile)
	if err != nil {
		return fmt.Errorf("failed to read inventory file: %w", err)
	}
	var cluster lieutenant.Cluster
	if clusterID != "" {
		c, found := lieutenant.FindByID(clusters, clusterID)
		if !found {
			return fmt.Errorf("cluster not found: %s", clusterID)
		}
		cluster = c
	} else {
		kcc, err := kubeconfig.CurrentClusterConfig()
		if err != nil {
			return fmt.Errorf("failed to get current cluster config from kubeconfig: %w", err)
		}
		c, found := lieutenant.FindByAPIURL(clusters, kcc.Server)
		if !found {
			return fmt.Errorf("no cluster found in inventory with API URL matching current kubeconfig context: %s", kcc.Server)
		}
		cluster = c
	}
	apiURL, _, _ := cluster.DynamicStringFact(lieutenant.KnownDynamicFactOpenshiftApiURL)
	if apiURL == "" {
		return fmt.Errorf("cluster does not have a known API URL: %s", cluster.ID)
	}

	tokens, err := emcred.GetCredentials(
		ctx,
		cluster.ID,
		func() (string, error) {
			return envOrMultilineInput(cmd.InOrStdin(), "KHARON_PASSBOLT_KEY", "Please paste the passbolt key from https://cloud.passbolt.com/vshn/app/settings/keys:")
		},
		func() (string, error) {
			return envOrPasswordPrompt(cmd.InOrStdin(), "KHARON_PASSBOLT_PASSPHRASE", "Please enter your Passbolt passphrase:")
		},
		func() (string, error) {
			return envOrPasswordPrompt(cmd.InOrStdin(), "KHARON_PASSBOLT_TOTP", "Please enter the Passbolt TOTP code from your authenticator app:")
		},
	)
	if err != nil {
		return fmt.Errorf("failed to get emergency credentials: %w", err)
	}

	success := false
	for i, token := range tokens {
		err := kubeconfig.InsertConnectionInfoIntoKubeconfig(fmt.Sprintf("emergency-credentials/%d/%s", i, cluster.ID), apiURL, proxyAddrForKubeconfig(proxyAddr), token)
		if err != nil {
			slog.Error("Error inserting credentials into kubeconfig", "error", err)
		} else {
			success = true
		}
	}
	if !success {
		return fmt.Errorf("failed to insert any credentials into kubeconfig, see previous error messages for details")
	}
	return nil
}

func envOrMultilineInput(r io.Reader, envVar, prompt string) (string, error) {
	value := os.Getenv(envVar)
	if value != "" {
		return value, nil
	}
	fmt.Println(prompt + " (press Ctrl+D to finish):")
	input := &bytes.Buffer{}
	if _, err := io.Copy(input, r); err != nil {
		return "", fmt.Errorf("failed to read multiline input: %w", err)
	}
	return input.String(), nil
}

func envOrPasswordPrompt(r io.Reader, envVar, prompt string) (string, error) {
	value := os.Getenv(envVar)
	if value != "" {
		return value, nil
	}
	return passwordPrompt(r, prompt)
}

func passwordPrompt(r io.Reader, prompt string) (string, error) {
	fmt.Print(prompt + " ")

	if f, ok := r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		pw, err := term.ReadPassword(int(f.Fd()))
		fmt.Println()
		return string(pw), err
	}
	bufio := bufio.NewReader(r)
	value, err := bufio.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func proxyAddrForKubeconfig(addr string) string {
	if addr == "" {
		return ""
	}
	return fmt.Sprintf("socks5://%s", addr)
}
