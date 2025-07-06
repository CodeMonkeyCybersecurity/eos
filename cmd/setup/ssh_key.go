// cmd/setup/ssh_key.go
package setup

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_config"
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
			if err := runInteractiveSSHKeySetup(config); err != nil {
				return fmt.Errorf("interactive setup failed: %w", err)
			}
		}

		// Create manager
		manager := system_config.NewSSHKeyManager(rc, config)

		// Build options
		options := &system_config.ConfigurationOptions{
			Type:        system_config.ConfigTypeSSHKey,
			DryRun:      dryRun,
			Force:       force,
			Interactive: false, // We handle interactivity above
			Backup:      backup,
			Validate:    true,
		}

		return setupConfiguration(rc, system_config.ConfigTypeSSHKey, manager, options)
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
	SetupSSHKeyCmd.MarkFlagRequired("email")
}

func runInteractiveSSHKeySetup(config *system_config.SSHKeyConfig) error {
	fmt.Printf("🔐 Interactive SSH Key Setup\n")
	fmt.Printf("============================\n\n")

	// Email (already set, but allow override)
	fmt.Printf("Email address [%s]: ", config.Email)
	var email string
	fmt.Scanln(&email)
	if email != "" {
		config.Email = email
	}

	// Key type
	fmt.Printf("Key type options:\n")
	fmt.Printf("  1) Ed25519 (recommended)\n")
	fmt.Printf("  2) RSA\n")
	fmt.Printf("  3) ECDSA\n")
	fmt.Printf("Select key type [1]: ")
	var keyChoice string
	fmt.Scanln(&keyChoice)

	switch keyChoice {
	case "2":
		config.KeyType = "rsa"
		fmt.Printf("RSA key length (2048/4096) [4096]: ")
		var lengthStr string
		fmt.Scanln(&lengthStr)
		if lengthStr == "2048" {
			config.KeyLength = 2048
		} else {
			config.KeyLength = 4096
		}
	case "3":
		config.KeyType = "ecdsa"
		fmt.Printf("ECDSA key length (256/384/521) [256]: ")
		var lengthStr string
		fmt.Scanln(&lengthStr)
		switch lengthStr {
		case "384":
			config.KeyLength = 384
		case "521":
			config.KeyLength = 521
		default:
			config.KeyLength = 256
		}
	default:
		config.KeyType = "ed25519"
		config.KeyLength = 0 // Ed25519 doesn't use key length
	}

	// File path
	fmt.Printf("File path [%s]: ", config.FilePath)
	var filePath string
	fmt.Scanln(&filePath)
	if filePath != "" {
		config.FilePath = filePath
	}

	// Passphrase
	fmt.Print("Set passphrase? [y/N]: ")
	var setPassphrase string
	fmt.Scanln(&setPassphrase)
	if setPassphrase == "y" || setPassphrase == "Y" {
		fmt.Print("Passphrase: ")
		var passphrase string
		fmt.Scanln(&passphrase)
		config.Passphrase = passphrase
	}

	// Additional comment
	fmt.Printf("Additional comment [%s]: ", config.Comment)
	var comment string
	fmt.Scanln(&comment)
	if comment != "" {
		config.Comment = comment
	}

	// Overwrite confirmation
	if system_config.CheckFileExists(config.FilePath) {
		fmt.Printf("⚠️  SSH key already exists at %s\n", config.FilePath)
		fmt.Print("Overwrite existing key? [y/N]: ")
		var overwrite string
		fmt.Scanln(&overwrite)
		if overwrite == "y" || overwrite == "Y" {
			config.Overwrite = true
		} else {
			return fmt.Errorf("SSH key generation cancelled - file already exists")
		}
	}

	fmt.Printf("\n📋 Configuration Summary:\n")
	fmt.Printf("   Email: %s\n", config.Email)
	fmt.Printf("   Key Type: %s\n", config.KeyType)
	if config.KeyLength > 0 {
		fmt.Printf("   Key Length: %d bits\n", config.KeyLength)
	}
	fmt.Printf("   File Path: %s\n", config.FilePath)
	if config.Comment != "" {
		fmt.Printf("   Comment: %s\n", config.Comment)
	}
	if config.Passphrase != "" {
		fmt.Printf("   Passphrase: *** (set)\n")
	} else {
		fmt.Printf("   Passphrase: (none)\n")
	}

	fmt.Print("\nProceed with key generation? [Y/n]: ")
	var proceed string
	fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("SSH key generation cancelled by user")
	}

	return nil
}