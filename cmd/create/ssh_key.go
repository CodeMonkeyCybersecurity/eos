// cmd/create/ssh_key.go
package create

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return ssh.CreateSSH(rc, cmd, args)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateSSHCmd)
	CreateSSHCmd.Flags().StringVar(&targetLogin, "user", "", "Target SSH login in the format <user@host>")
	CreateSSHCmd.Flags().StringVar(&keyName, "key-name", "id_rsa_fips", "Filename for the SSH key")
	CreateSSHCmd.Flags().BoolVar(&force, "force", false, "Overwrite existing key if it already exists")
	CreateSSHCmd.Flags().StringVar(&alias, "alias", "", "Custom alias to use in SSH config (default: host)")
}

var (
	nameOverride string
	printPrivate bool
	diskFallback bool
)

func init() {
	CreateCmd.AddCommand(SshKeyCmd)
	SshKeyCmd.Flags().StringVar(&nameOverride, "name", "", "Optional basename for SSH key")
	SshKeyCmd.Flags().BoolVar(&printPrivate, "print-private", false, "Print private key to stdout")
	SshKeyCmd.Flags().BoolVar(&diskFallback, "disk-fallback", false, "Write to /home/eos/.ssh if Vault unavailable")
}

var SshKeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Create and store an SSH key securely",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		keyDir := "/home/eos/.ssh" // TODO: shared.EosUserHome()
		// our KV-v2 mount + base directory
		const mount = "secret"
		const baseDir = "pandora"
		const leafBase = "ssh-key"

		// vaultPath (directory) is fixed:
		vaultDir := baseDir
		// Determine base name for key
		name := nameOverride
		if name != "" && !isSafeName(name) {
			otelzap.Ctx(rc.Ctx).Warn("Invalid --name provided", zap.String("name", name))
			return fmt.Errorf("invalid --name: only alphanumeric, dashes, and underscores allowed")
		}

		// Authenticate to Vault
		client, err := vault.Authn(rc)
		// declare a local flag
		useVault := (err == nil)
		if !useVault {
			otelzap.Ctx(rc.Ctx).Warn("Vault unavailable — will fallback to disk", zap.Error(err))
		}

		// if Vault is up, pick the first free suffix
		if useVault {
			// find the first free leaf under "eos/pandora"
			leaf, err := vault.FindNextAvailableKVv2Path(rc, client, mount, baseDir, leafBase)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Error("no available Vault path", zap.Error(err))
				return err
			}
			// leaf == "eos/pandora/ssh-key" or ".../ssh-key-001"
			// extract just the final segment
			name = filepath.Base(leaf)
		}

		chosen := fmt.Sprintf("%s/%s", vaultDir, name)
		otelzap.Ctx(rc.Ctx).Info(" Chosen Vault path for new SSH key", zap.String("path", chosen))

		// Generate key
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("keygen failed: %w", err)
		}

		pubSSH, err := ssh.NewPublicKey(pub)
		if err != nil {
			return fmt.Errorf("encode public key failed: %w", err)
		}
		pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubSSH)))
		privPEM := encodePrivateKeyPEM(priv)
		fingerprint := fingerprintSHA256(pubSSH)

		fullVaultPath := fmt.Sprintf("%s/%s", vaultDir, name)

		// Vault Write
		if useVault {
			// Extract a real context.Context from your RuntimeContext:
			if err := vault.WriteSSHKey(
				rc,
				client,
				mount, // must supply the KV-v2 mount
				fullVaultPath,
				pubStr,
				string(privPEM),
				fingerprint,
			); err == nil {
				otelzap.Ctx(rc.Ctx).Info(" SSH key written to Vault",
					zap.String("path", fullVaultPath),
					zap.String("fingerprint", fingerprint),
				)
				return nil
			} else {
				otelzap.Ctx(rc.Ctx).Warn("Vault write failed, falling back to disk",
					zap.String("path", fullVaultPath),
					zap.Error(err),
				)
			}

			if !diskFallback {
				otelzap.Ctx(rc.Ctx).Error("Vault write failed and disk fallback is disabled")
				return fmt.Errorf("vault write failed and disk fallback is disabled")
			}
		}

		// Disk fallback
		pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", name))
		privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", name))

		if err := os.MkdirAll(keyDir, 0700); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to create .ssh directory", zap.String("dir", keyDir), zap.Error(err))
			return fmt.Errorf("mkdir failed: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write public key", zap.String("path", pubPath), zap.Error(err))
			return fmt.Errorf("write public key failed: %w", err)
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write private key", zap.String("path", privPath), zap.Error(err))
			return fmt.Errorf("write private key failed: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info(" SSH key written to disk",
			zap.String("private_key_path", privPath),
			zap.String("public_key_path", pubPath),
		)
		return nil
	}),
}

func isSafeName(name string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return ok
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
		nameOverride, _ := cmd.Flags().GetString("name")
		diskFallback, _ := cmd.Flags().GetBool("disk-fallback")
		_, _ = cmd.Flags().GetBool("print-private") // TODO: implement print functionality

		keyDir := "/home/eos/.ssh" // TODO: shared.EosUserHome()
		// our KV-v2 mount + base directory
		const mount = "secret"
		const baseDir = "pandora"
		const leafBase = "ssh-key"

		// vaultPath (directory) is fixed:
		vaultDir := baseDir
		// Determine base name for key
		name := nameOverride
		if name != "" && !isSafeName(name) {
			otelzap.Ctx(rc.Ctx).Warn("Invalid --name provided", zap.String("name", name))
			return fmt.Errorf("invalid --name: only alphanumeric, dashes, and underscores allowed")
		}

		// Authenticate to Vault
		client, err := vault.Authn(rc)
		// declare a local flag
		useVault := (err == nil)
		if !useVault {
			otelzap.Ctx(rc.Ctx).Warn("Vault unavailable — will fallback to disk", zap.Error(err))
		}

		// if Vault is up, pick the first free suffix
		if useVault {
			// find the first free leaf under "eos/pandora"
			leaf, err := vault.FindNextAvailableKVv2Path(rc, client, mount, baseDir, leafBase)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Error("no available Vault path", zap.Error(err))
				return err
			}
			// leaf == "eos/pandora/ssh-key" or ".../ssh-key-001"
			// extract just the final segment
			name = filepath.Base(leaf)
		}

		chosen := fmt.Sprintf("%s/%s", vaultDir, name)
		otelzap.Ctx(rc.Ctx).Info("Chosen Vault path for new SSH key", zap.String("path", chosen))

		// Generate key
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("keygen failed: %w", err)
		}

		pubSSH, err := ssh.NewPublicKey(pub)
		if err != nil {
			return fmt.Errorf("encode public key failed: %w", err)
		}
		pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubSSH)))
		privPEM := encodePrivateKeyPEM(priv)
		fingerprint := fingerprintSHA256(pubSSH)

		fullVaultPath := fmt.Sprintf("%s/%s", vaultDir, name)

		// Vault Write
		if useVault {
			// Extract a real context.Context from your RuntimeContext:
			if err := vault.WriteSSHKey(
				rc,
				client,
				mount, // must supply the KV-v2 mount
				fullVaultPath,
				pubStr,
				string(privPEM),
				fingerprint,
			); err == nil {
				otelzap.Ctx(rc.Ctx).Info("SSH key written to Vault",
					zap.String("path", fullVaultPath),
					zap.String("fingerprint", fingerprint),
				)
				return nil
			} else {
				otelzap.Ctx(rc.Ctx).Warn("Vault write failed, falling back to disk",
					zap.String("path", fullVaultPath),
					zap.Error(err),
				)
			}

			if !diskFallback {
				otelzap.Ctx(rc.Ctx).Error("Vault write failed and disk fallback is disabled")
				return fmt.Errorf("vault write failed and disk fallback is disabled")
			}
		}

		// Disk fallback
		pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", name))
		privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", name))

		if err := os.MkdirAll(keyDir, 0700); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to create .ssh directory", zap.String("dir", keyDir), zap.Error(err))
			return fmt.Errorf("mkdir failed: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write public key", zap.String("path", pubPath), zap.Error(err))
			return fmt.Errorf("write public key failed: %w", err)
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to write private key", zap.String("path", privPath), zap.Error(err))
			return fmt.Errorf("write private key failed: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info("SSH key written to disk",
			zap.String("private_key_path", privPath),
			zap.String("public_key_path", pubPath),
		)
		return nil
	}),
}

func init() {
	pandoraSshKeyCmd.Flags().String("name", "", "Optional basename for SSH key")
	pandoraSshKeyCmd.Flags().Bool("print-private", false, "Print private key to stdout")
	pandoraSshKeyCmd.Flags().Bool("disk-fallback", false, "Write to /home/eos/.ssh if Vault unavailable")

	// Register with parent command
	CreateCmd.AddCommand(pandoraSshKeyCmd)
}

// Helper functions
func encodePrivateKeyPEM(key ed25519.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: key.Seed(), // optional: switch to ssh.MarshalED25519PrivateKey
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, block)
	return buf.Bytes()
}

func fingerprintSHA256(pub ssh.PublicKey) string {
	hash := sha256.Sum256(pub.Marshal())
	return fmt.Sprintf("SHA256:%s", base64.StdEncoding.EncodeToString(hash[:]))
}
