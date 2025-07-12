package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

// SSHKeyOptions contains options for SSH key creation
type SSHKeyOptions struct {
	TargetLogin string // Target login in format user@host
	KeyName     string // SSH key name
	Force       bool   // Force overwrite existing keys
	Alias       string // SSH config alias
}

// VaultSSHKeyOptions contains options for Vault-stored SSH keys
type VaultSSHKeyOptions struct {
	NameOverride string // Optional basename for SSH key
	PrintPrivate bool   // Print private key to stdout
	DiskFallback bool   // Write to disk if Vault unavailable
}

// CreateSSHWithRemote creates an SSH key and sets it up with a remote host
// This follows the Assess → Intervene → Evaluate pattern
func CreateSSHWithRemote(rc *eos_io.RuntimeContext, opts *SSHKeyOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing SSH key creation prerequisites")

	// Resolve user home directory and SSH paths
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to detect current user: %w", err)
	}
	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	keyPath := filepath.Join(sshDir, opts.KeyName)
	pubKeyPath := keyPath + ".pub"

	configPath := os.Getenv("SSH_CONFIG_PATH")
	if configPath == "" {
		configPath = filepath.Join(currentUser.HomeDir, ".ssh", "config")
	}

	// Validate target login format
	if opts.TargetLogin == "" {
		return fmt.Errorf("target login is required")
	}
	parts := strings.Split(strings.TrimSpace(opts.TargetLogin), "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for target login (expected user@host)")
	}
	remoteUser, host := parts[0], parts[1]

	// INTERVENE - Perform the operations
	logger.Info("Creating SSH key and configuring remote access",
		zap.String("key_path", keyPath),
		zap.String("target", opts.TargetLogin))

	// Ensure .ssh directory exists
	logger.Info("Ensuring ~/.ssh directory exists", zap.String("path", sshDir))
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create ~/.ssh: %w", err)
	}

	// Generate key if necessary
	if _, err := os.Stat(keyPath); err == nil && !opts.Force {
		logger.Info("SSH key already exists", zap.String("path", keyPath))
	} else {
		logger.Info("Generating FIPS-compliant RSA SSH key", zap.String("key", keyPath))
		if err := eos_unix.GenerateFIPSKey(keyPath); err != nil {
			return fmt.Errorf("failed to generate SSH key: %w", err)
		}
	}

	// Copy key to remote host
	logger.Info("Copying public key to remote host", zap.String("target", opts.TargetLogin))
	if err := eos_unix.CopyKeyToRemote(pubKeyPath, opts.TargetLogin); err != nil {
		return fmt.Errorf("failed to copy key to remote host: %w", err)
	}

	// Update SSH config
	logger.Info("Updating SSH config")
	if opts.Alias == "" {
		opts.Alias = host
	}
	if err := eos_unix.AppendToSSHConfig(rc.Ctx, opts.Alias, host, remoteUser, keyPath, configPath); err != nil {
		return fmt.Errorf("failed to update SSH config: %w", err)
	}

	// EVALUATE - Verify the setup worked
	logger.Info("Verifying SSH key setup")

	// Check that files exist with correct permissions
	if info, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("private key verification failed: %w", err)
	} else if info.Mode().Perm() != 0600 {
		logger.Warn("Private key has incorrect permissions", zap.String("mode", info.Mode().String()))
	}

	if info, err := os.Stat(pubKeyPath); err != nil {
		return fmt.Errorf("public key verification failed: %w", err)
	} else if info.Mode().Perm() != 0644 {
		logger.Warn("Public key has incorrect permissions", zap.String("mode", info.Mode().String()))
	}

	logger.Info("SSH key setup completed successfully",
		zap.String("key_path", keyPath),
		zap.String("alias", opts.Alias))
	return nil
}

// CreateSSHKeyWithVault creates an Ed25519 SSH key and stores it in Vault
// This follows the Assess → Intervene → Evaluate pattern
func CreateSSHKeyWithVault(rc *eos_io.RuntimeContext, opts *VaultSSHKeyOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing Vault SSH key creation prerequisites")

	keyDir := "/home/eos/.ssh" // TODO: shared.EosUserHome()
	const mount = "secret"
	const baseDir = "pandora"
	const leafBase = "ssh-key"

	vaultDir := baseDir
	name := opts.NameOverride
	if name != "" && !isSafeName(name) {
		logger.Warn("Invalid --name provided", zap.String("name", name))
		return fmt.Errorf("invalid --name: only alphanumeric, dashes, and underscores allowed")
	}

	// Check Vault availability
	client, err := vault.Authn(rc)
	useVault := (err == nil)
	if !useVault {
		logger.Warn("Vault unavailable — will fallback to disk", zap.Error(err))
		if !opts.DiskFallback {
			return fmt.Errorf("vault unavailable and disk fallback is disabled")
		}
	}

	// INTERVENE - Generate and store the key
	logger.Info("Generating Ed25519 SSH key")

	// If Vault is available, find the next available path
	if useVault {
		leaf, err := vault.FindNextAvailableKVv2Path(rc, client, mount, baseDir, leafBase)
		if err != nil {
			logger.Error("No available Vault path", zap.Error(err))
			return err
		}
		name = filepath.Base(leaf)
	}

	chosen := fmt.Sprintf("%s/%s", vaultDir, name)
	logger.Info("Chosen Vault path for new SSH key", zap.String("path", chosen))

	// Generate Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen failed: %w", err)
	}

	pubSSH, err := gossh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encode public key failed: %w", err)
	}
	pubStr := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(pubSSH)))
	privPEM := encodePrivateKeyPEM(priv)
	fingerprint := fingerprintSHA256(pubSSH)

	fullVaultPath := fmt.Sprintf("%s/%s", vaultDir, name)

	// Try to write to Vault first
	if useVault {
		if err := vault.WriteSSHKey(
			rc,
			client,
			mount,
			fullVaultPath,
			pubStr,
			string(privPEM),
			fingerprint,
		); err == nil {
			logger.Info("SSH key written to Vault",
				zap.String("path", fullVaultPath),
				zap.String("fingerprint", fingerprint))
			return nil
		} else {
			logger.Warn("Vault write failed, falling back to disk",
				zap.String("path", fullVaultPath),
				zap.Error(err))
			if !opts.DiskFallback {
				return fmt.Errorf("vault write failed and disk fallback is disabled")
			}
		}
	}

	// Fallback to disk storage
	logger.Info("Storing SSH key on disk")
	pubPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s.pub", name))
	privPath := filepath.Join(keyDir, fmt.Sprintf("id_ed25519-%s", name))

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		logger.Error("Failed to create .ssh directory", zap.String("dir", keyDir), zap.Error(err))
		return fmt.Errorf("mkdir failed: %w", err)
	}

	if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
		logger.Error("Failed to write public key", zap.String("path", pubPath), zap.Error(err))
		return fmt.Errorf("write public key failed: %w", err)
	}

	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		logger.Error("Failed to write private key", zap.String("path", privPath), zap.Error(err))
		return fmt.Errorf("write private key failed: %w", err)
	}

	// EVALUATE - Verify the keys were stored correctly
	logger.Info("Verifying SSH key storage")

	if _, err := os.Stat(privPath); err != nil {
		return fmt.Errorf("private key verification failed: %w", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		return fmt.Errorf("public key verification failed: %w", err)
	}

	logger.Info("SSH key written to disk successfully",
		zap.String("private_key_path", privPath),
		zap.String("public_key_path", pubPath),
		zap.String("fingerprint", fingerprint))

	return nil
}

// CreateSSHKeyWithConfig creates an SSH key using system_config.SSHKeyManager
// This is a wrapper around the existing SSHKeyManager functionality
func CreateSSHKeyWithConfig(rc *eos_io.RuntimeContext, config *system_config.SSHKeyConfig, options *system_config.ConfigurationOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating SSH key with configuration",
		zap.String("type", config.KeyType),
		zap.String("path", config.FilePath))

	// Create manager
	manager := system_config.NewSSHKeyManager(rc, config)

	// Validate configuration
	if err := manager.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Backup existing keys if requested
	if options.Backup {
		if backup, err := manager.Backup(); err != nil {
			logger.Warn("Failed to create backup", zap.Error(err))
		} else {
			logger.Info("Created backup", zap.String("backup_id", backup.ID))
		}
	}

	// Apply configuration (generate keys)
	result, err := manager.Apply()
	if err != nil {
		return fmt.Errorf("failed to generate SSH key: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("SSH key generation failed: %s", result.Error)
	}

	logger.Info("SSH key generation completed",
		zap.String("message", result.Message),
		zap.Duration("duration", result.Duration))

	return nil
}

// RunInteractiveSSHKeySetup runs an interactive SSH key setup wizard
func RunInteractiveSSHKeySetup(rc *eos_io.RuntimeContext, config *system_config.SSHKeyConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting interactive SSH key setup")

	// Email (already set, but allow override)
	logger.Info("terminal prompt: Email address")
	if email := interaction.PromptInput(rc.Ctx, fmt.Sprintf("Email address [%s]", config.Email), config.Email); email != "" {
		config.Email = email
	}

	// Key type - simplified implementation for now
	logger.Info("terminal prompt: Select key type")
	// For now, use YesNo prompts to select key type
	if interaction.PromptYesNo(rc.Ctx, "Use RSA key instead of Ed25519?", false) {
		config.KeyType = "rsa"
		if interaction.PromptYesNo(rc.Ctx, "Use 4096-bit RSA key? (otherwise 2048-bit)", true) {
			config.KeyLength = 4096
		} else {
			config.KeyLength = 2048
		}
	} else {
		config.KeyType = "ed25519"
		config.KeyLength = 0
	}

	// File path
	logger.Info("terminal prompt: File path")
	if filePath := interaction.PromptInput(rc.Ctx, fmt.Sprintf("File path [%s]", config.FilePath), config.FilePath); filePath != "" {
		config.FilePath = filePath
	}

	// Passphrase
	logger.Info("terminal prompt: Set passphrase?")
	if interaction.PromptYesNo(rc.Ctx, "Set passphrase?", false) {
		logger.Info("terminal prompt: Enter passphrase")
		// Use PromptSecret for password input
		if passphrase, err := interaction.PromptSecret(rc.Ctx, "Passphrase: "); err == nil {
			config.Passphrase = passphrase
		} else {
			return fmt.Errorf("failed to read passphrase: %w", err)
		}
	}

	// Additional comment
	logger.Info("terminal prompt: Additional comment")
	if comment := interaction.PromptInput(rc.Ctx, fmt.Sprintf("Additional comment [%s]", config.Comment), config.Comment); comment != "" {
		config.Comment = comment
	}

	// Overwrite confirmation
	if system_config.CheckFileExists(config.FilePath) {
		logger.Info("terminal prompt: Overwrite existing key?")
		if !interaction.PromptYesNo(rc.Ctx, fmt.Sprintf("SSH key already exists at %s. Overwrite?", config.FilePath), false) {
			return fmt.Errorf("SSH key generation cancelled - file already exists")
		}
		config.Overwrite = true
	}

	// Summary and confirmation
	logger.Info("Presenting configuration summary")
	summary := fmt.Sprintf(`Configuration Summary:
   Email: %s
   Key Type: %s`, config.Email, config.KeyType)
	if config.KeyLength > 0 {
		summary += fmt.Sprintf("\n   Key Length: %d bits", config.KeyLength)
	}
	summary += fmt.Sprintf("\n   File Path: %s", config.FilePath)
	if config.Comment != "" {
		summary += fmt.Sprintf("\n   Comment: %s", config.Comment)
	}
	if config.Passphrase != "" {
		summary += "\n   Passphrase: *** (set)"
	} else {
		summary += "\n   Passphrase: (none)"
	}

	logger.Info("terminal prompt: Configuration summary", zap.String("summary", summary))
	if !interaction.PromptYesNo(rc.Ctx, "Proceed with key generation?", true) {
		return fmt.Errorf("SSH key generation cancelled by user")
	}

	return nil
}

// Helper functions

// encodePrivateKeyPEM encodes an Ed25519 private key to PEM format
func encodePrivateKeyPEM(key ed25519.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: key.Seed(),
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, block)
	return buf.Bytes()
}

// fingerprintSHA256 calculates the SHA256 fingerprint of an SSH public key
func fingerprintSHA256(pub gossh.PublicKey) string {
	hash := sha256.Sum256(pub.Marshal())
	return fmt.Sprintf("SHA256:%s", base64.StdEncoding.EncodeToString(hash[:]))
}

// isSafeName checks if a name contains only safe characters
func isSafeName(name string) bool {
	ok, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return ok
}
