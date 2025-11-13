// cmd/create/ssh_key.go
package create

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ssh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system/system_config"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupSSHKeyCmd generates SSH key pairs
var SetupSSHKeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Generate SSH key pair",
	Long: `Generate SSH key pairs for secure authentication.

This command creates a new SSH key pair with the specified algorithm
and configuration. It supports RSA, ECDSA, and Ed25519 key types.

Examples:
  eos setup ssh-key                           # Generate Ed25519 key (recommended)
  eos setup ssh-key --type rsa --length 4096 # Generate 4096-bit RSA key
  eos setup ssh-key --email user@example.com # Set specific email
  eos setup ssh-key --interactive            # Interactive key generation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		email, _ := cmd.Flags().GetString("email")
		keyType, _ := cmd.Flags().GetString("type")
		keyLength, _ := cmd.Flags().GetInt("length")
		filePath, _ := cmd.Flags().GetString("file")
		comment, _ := cmd.Flags().GetString("comment")
		overwrite, _ := cmd.Flags().GetBool("overwrite")

		logger.Info("Setting up SSH key",
			zap.String("type", keyType),
			zap.String("email", email),
			zap.Bool("dry_run", dryRun))

		// Set defaults
		if email == "" {
			return fmt.Errorf("email is required for SSH key generation")
		}

		if keyType == "" {
			keyType = "ed25519"
		}

		if filePath == "" {
			homeDir, _ := os.UserHomeDir()
			filePath = filepath.Join(homeDir, ".ssh", fmt.Sprintf("id_%s", keyType))
		}

		// Build configuration
		config := &system_config.SSHKeyConfig{
			Email:     email,
			KeyType:   keyType,
			KeyLength: keyLength,
			FilePath:  filePath,
			Comment:   comment,
			Overwrite: overwrite,
		}

		// Interactive configuration
		if interactive {
			if err := ssh.RunInteractiveSSHKeySetup(rc, config); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		// Build options
		options := &system_config.ConfigurationOptions{
			Type:        system_config.ConfigTypeSSHKey,
			DryRun:      dryRun,
			Force:       force,
			Interactive: false, // We handle interactivity above
			Backup:      backup,
			Validate:    true,
		}

		// Use the helper function to create the SSH key
		return ssh.CreateSSHKeyWithConfig(rc, config, options)
	}),
}

func init() {
	SetupCmd.AddCommand(SetupSSHKeyCmd)

	SetupSSHKeyCmd.Flags().StringP("email", "e", "", "Email address for key comment (required)")
	SetupSSHKeyCmd.Flags().StringP("type", "t", "ed25519", "Key type (rsa, ecdsa, ed25519)")
	SetupSSHKeyCmd.Flags().IntP("length", "l", 0, "Key length (rsa: 2048/4096, ecdsa: 256/384/521)")
	SetupSSHKeyCmd.Flags().StringP("file", "f", "", "Output file path")
	SetupSSHKeyCmd.Flags().StringP("comment", "c", "", "Additional comment for the key")
	SetupSSHKeyCmd.Flags().Bool("overwrite", false, "Overwrite existing key")

	// Mark email as required
	if err := SetupSSHKeyCmd.MarkFlagRequired("email"); err != nil {
		// This is a programming error, not a runtime error
		panic(fmt.Sprintf("Failed to mark email flag as required: %v", err))
	}
}

var CreateSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Create a FIPS-compliant SSH key and connect it to a remote host",
	Long: `Generates a 2048-bit RSA key for FIPS compliance, installs it to a remote host using ssh-copy-id,
and configures it in your ~/.ssh/config for easy reuse.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		targetLogin, _ := cmd.Flags().GetString("user")
		keyName, _ := cmd.Flags().GetString("key-name")
		force, _ := cmd.Flags().GetBool("force")
		alias, _ := cmd.Flags().GetString("alias")

		// Create options
		opts := &ssh.SSHKeyOptions{
			TargetLogin: targetLogin,
			KeyName:     keyName,
			Force:       force,
			Alias:       alias,
		}

		logger.Info("Creating SSH key with remote host setup",
			zap.String("target", targetLogin),
			zap.String("key_name", keyName))

		return ssh.CreateSSHWithRemote(rc, opts)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateSSHCmd)
	CreateSSHCmd.Flags().String("user", "", "Target SSH login in the format <user@host>")
	CreateSSHCmd.Flags().String("key-name", "id_rsa_fips", "Filename for the SSH key")
	CreateSSHCmd.Flags().Bool("force", false, "Overwrite existing key if it already exists")
	CreateSSHCmd.Flags().String("alias", "", "Custom alias to use in SSH config (default: host)")
}

var SshKeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Create and store an SSH key securely",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		nameOverride, _ := cmd.Flags().GetString("name")
		printPrivate, _ := cmd.Flags().GetBool("print-private")
		diskFallback, _ := cmd.Flags().GetBool("disk-fallback")

		// Create options
		opts := &ssh.VaultSSHKeyOptions{
			NameOverride: nameOverride,
			PrintPrivate: printPrivate,
			DiskFallback: diskFallback,
		}

		logger.Info("Creating SSH key with Vault storage",
			zap.String("name", nameOverride),
			zap.Bool("disk_fallback", diskFallback))

		return ssh.CreateSSHKeyWithVault(rc, opts)
	}),
}

func init() {
	CreateCmd.AddCommand(SshKeyCmd)
	SshKeyCmd.Flags().String("name", "", "Optional basename for SSH key")
	SshKeyCmd.Flags().Bool("print-private", false, "Print private key to stdout")
	SshKeyCmd.Flags().Bool("disk-fallback", false, "Write to /home/eos/.ssh if Vault unavailable")
}

var pandoraSshKeyCmd = &cobra.Command{
	Use:     "pandora-ssh-key",
	Aliases: []string{"vault-ssh-key", "ssh-key-vault", "pandora-key"},
	Short:   "Create and store an SSH key securely in Vault",
	Long: `Create and store an SSH key securely in Vault (Pandora).

This command generates an Ed25519 SSH key pair and stores it securely in Vault.
If Vault is unavailable, it can fallback to disk storage.

Examples:
  eos create pandora-ssh-key                    # Generate with auto name
  eos create pandora-ssh-key --name mykey      # Generate with specific name
  eos create pandora-ssh-key --disk-fallback   # Allow disk fallback if Vault unavailable`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		nameOverride, _ := cmd.Flags().GetString("name")
		printPrivate, _ := cmd.Flags().GetBool("print-private")
		diskFallback, _ := cmd.Flags().GetBool("disk-fallback")

		// Create options
		opts := &ssh.VaultSSHKeyOptions{
			NameOverride: nameOverride,
			PrintPrivate: printPrivate,
			DiskFallback: diskFallback,
		}

		logger.Info("Creating Pandora SSH key",
			zap.String("name", nameOverride),
			zap.Bool("disk_fallback", diskFallback))

		return ssh.CreateSSHKeyWithVault(rc, opts)
	}),
}

func init() {
	pandoraSshKeyCmd.Flags().String("name", "", "Optional basename for SSH key")
	pandoraSshKeyCmd.Flags().Bool("print-private", false, "Print private key to stdout")
	pandoraSshKeyCmd.Flags().Bool("disk-fallback", false, "Write to /home/eos/.ssh if Vault unavailable")

	// Register with parent command
	CreateCmd.AddCommand(pandoraSshKeyCmd)
}
