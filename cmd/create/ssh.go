// cmd/create/ssh.go
package create

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"

	"github.com/spf13/cobra"
)

var (
	targetLogin string
	keyName     string
	force       bool
	alias       string
)

var CreateSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Create a FIPS-compliant SSH key and connect it to a remote host",
	Long: `Generates a 2048-bit RSA key for FIPS compliance, installs it to a remote host using ssh-copy-id,
and configures it in your ~/.ssh/config for easy reuse.`,
	RunE: runCreateSSH,
}

func init() {
	CreateCmd.AddCommand(CreateSSHCmd)
	CreateSSHCmd.Flags().StringVar(&targetLogin, "user", "", "Target SSH login in the format <user@host>")
	CreateSSHCmd.Flags().StringVar(&keyName, "key-name", "id_rsa_fips", "Filename for the SSH key")
	CreateSSHCmd.Flags().BoolVar(&force, "force", false, "Overwrite existing key if it already exists")
	CreateSSHCmd.Flags().StringVar(&alias, "alias", "", "Custom alias to use in SSH config (default: host)")
}

func runCreateSSH(cmd *cobra.Command, args []string) error {
	log := logger.L()

	// Resolve paths
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to detect current user: %w", err)
	}
	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	keyPath := filepath.Join(sshDir, keyName)
	pubKeyPath := keyPath + ".pub"
	configPath := os.Getenv("SSH_CONFIG_PATH")
	if configPath == "" {
		configPath = filepath.Join(os.Getenv("HOME"), ".ssh", "config")
	}

	if targetLogin == "" {
		targetLogin = interaction.PromptInput("Enter target login (<user@host>)", "")
	}
	parts := strings.Split(strings.TrimSpace(targetLogin), "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for target login (expected user@host)")
	}
	user := parts[0]
	host := parts[1]

	log.Info("Ensuring ~/.ssh exists", zap.String("path", sshDir))
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create ~/.ssh: %w", err)
	}

	// Generate key if needed
	if _, err := os.Stat(keyPath); err == nil && !force {
		fmt.Println("🔑 Key already exists:", keyPath)
	} else {
		log.Info("Generating FIPS-compliant RSA SSH key", zap.String("key", keyPath))
		if err := system.GenerateFIPSKey(keyPath); err != nil {
			return fmt.Errorf("failed to generate SSH key: %w", err)
		}
	}

	// Copy key to remote host
	fmt.Printf("📡 Copying public key to %s...\n", targetLogin)
	if err := system.CopyKeyToRemote(pubKeyPath, targetLogin); err != nil {
		return fmt.Errorf("failed to copy key to remote host: %w", err)
	}

	// Append to SSH config
	fmt.Println("🛠️ Updating SSH config...")
	if alias == "" {
		alias = host
	}
	if err := system.AppendToSSHConfig(alias, host, user, keyPath, configPath); err != nil {
		return fmt.Errorf("failed to update SSH config: %w", err)
	}

	fmt.Println("✅ SSH key setup complete.")
	return nil
}
