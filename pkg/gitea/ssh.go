// pkg/gitea/ssh.go
// SSH key generation and configuration for Gitea access
// Manages SSH keys and ~/.ssh/config entries for git operations

package gitea

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// GenerateSSHKey generates a new SSH key pair for Gitea authentication
func GenerateSSHKey(rc *eos_io.RuntimeContext, config *SSHKeyConfig) (*SSHKeyResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result := &SSHKeyResult{}

	// Ensure key directory exists
	keyDir := filepath.Dir(config.KeyPath)
	if err := os.MkdirAll(keyDir, ConfigDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Check if key already exists
	if _, err := os.Stat(config.KeyPath); err == nil {
		if !config.Overwrite {
			logger.Info("SSH key already exists, skipping generation",
				zap.String("path", config.KeyPath))
			result.KeyPath = config.KeyPath
			result.PublicKeyPath = config.KeyPath + ".pub"
			result.AlreadyExists = true
			return result, nil
		}
		logger.Warn("Overwriting existing SSH key",
			zap.String("path", config.KeyPath))
	}

	// Generate key pair based on type
	switch config.KeyType {
	case SSHKeyTypeEd25519, "": // Default to Ed25519
		if err := generateEd25519Key(rc, config, result); err != nil {
			return nil, err
		}
	case SSHKeyTypeRSA:
		if err := generateRSAKeyViaCLI(rc, config, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", config.KeyType)
	}

	logger.Info("Generated SSH key pair",
		zap.String("type", string(config.KeyType)),
		zap.String("private_key", result.KeyPath),
		zap.String("public_key", result.PublicKeyPath))

	return result, nil
}

// SSHKeyResult holds the result of SSH key generation
type SSHKeyResult struct {
	// KeyPath is the path to the private key
	KeyPath string

	// PublicKeyPath is the path to the public key
	PublicKeyPath string

	// PublicKey is the public key content (for adding to Gitea)
	PublicKey string

	// AlreadyExists indicates the key was not generated (already existed)
	AlreadyExists bool
}

// generateEd25519Key generates an Ed25519 key pair using pure Go
func generateEd25519Key(rc *eos_io.RuntimeContext, config *SSHKeyConfig, result *SSHKeyResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Generating Ed25519 SSH key", zap.String("name", config.KeyName))

	// Generate key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// Convert private key to OpenSSH format
	privateKeyBytes, err := ssh.MarshalPrivateKey(privKey, config.KeyName)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Write private key
	if err := os.WriteFile(config.KeyPath, pem.EncodeToMemory(privateKeyBytes), SSHKeyPrivatePerm); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Create SSH public key
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH public key: %w", err)
	}

	// Format public key with comment
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
	pubKeyStr := strings.TrimSpace(string(pubKeyBytes)) + " " + config.KeyName + "\n"

	// Write public key
	publicKeyPath := config.KeyPath + ".pub"
	if err := os.WriteFile(publicKeyPath, []byte(pubKeyStr), SSHKeyPublicPerm); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	result.KeyPath = config.KeyPath
	result.PublicKeyPath = publicKeyPath
	result.PublicKey = strings.TrimSpace(pubKeyStr)

	return nil
}

// generateRSAKeyViaCLI generates an RSA key using ssh-keygen CLI
// RATIONALE: RSA key generation in pure Go is complex; CLI is more reliable
func generateRSAKeyViaCLI(rc *eos_io.RuntimeContext, config *SSHKeyConfig, result *SSHKeyResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Generating RSA SSH key via ssh-keygen", zap.String("name", config.KeyName))

	// Use ssh-keygen for RSA (simpler and more reliable)
	cmd := exec.Command("ssh-keygen",
		"-t", "rsa",
		"-b", "4096",
		"-C", config.KeyName,
		"-f", config.KeyPath,
		"-N", "", // Empty passphrase
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen failed: %s: %w", stderr.String(), err)
	}

	// Read public key
	pubKeyBytes, err := os.ReadFile(config.KeyPath + ".pub")
	if err != nil {
		return fmt.Errorf("failed to read generated public key: %w", err)
	}

	result.KeyPath = config.KeyPath
	result.PublicKeyPath = config.KeyPath + ".pub"
	result.PublicKey = strings.TrimSpace(string(pubKeyBytes))

	return nil
}

// UpdateSSHConfig adds or updates an entry in ~/.ssh/config for the Gitea instance
func UpdateSSHConfig(rc *eos_io.RuntimeContext, instance *InstanceConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	sshConfigPath := filepath.Join(homeDir, SSHConfigPath)

	// Ensure .ssh directory exists
	sshDir := filepath.Dir(sshConfigPath)
	if err := os.MkdirAll(sshDir, ConfigDirPerm); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Read existing config
	existingConfig := ""
	if data, err := os.ReadFile(sshConfigPath); err == nil {
		existingConfig = string(data)
	}

	// Generate host alias (e.g., "gitea-vhost7")
	hostAlias := instance.SSHConfigHost
	if hostAlias == "" {
		hostAlias = fmt.Sprintf("gitea-%s", instance.Name)
	}

	// Check if entry already exists
	hostMarker := fmt.Sprintf("Host %s", hostAlias)
	if strings.Contains(existingConfig, hostMarker) {
		logger.Info("SSH config entry already exists",
			zap.String("host", hostAlias))
		// Update the instance with the host alias
		instance.SSHConfigHost = hostAlias
		return nil
	}

	// Build new entry
	var entry strings.Builder
	entry.WriteString("\n# Gitea instance: " + instance.Name + "\n")
	entry.WriteString("# Added by 'eos create gitea'\n")
	entry.WriteString(fmt.Sprintf("Host %s\n", hostAlias))
	entry.WriteString(fmt.Sprintf("    HostName %s\n", instance.Hostname))
	entry.WriteString(fmt.Sprintf("    Port %d\n", instance.SSHPort))
	entry.WriteString(fmt.Sprintf("    User %s\n", SSHUserDefault))
	entry.WriteString(fmt.Sprintf("    IdentityFile %s\n", instance.SSHKeyPath))
	entry.WriteString("    IdentitiesOnly yes\n")

	// Append to config
	newConfig := existingConfig + entry.String()
	if err := os.WriteFile(sshConfigPath, []byte(newConfig), SSHConfigPerm); err != nil {
		return fmt.Errorf("failed to write SSH config: %w", err)
	}

	// Update instance with the host alias
	instance.SSHConfigHost = hostAlias

	logger.Info("Added SSH config entry",
		zap.String("host", hostAlias),
		zap.String("config_path", sshConfigPath))

	return nil
}

// GetSSHKeyPath returns the default path for a Gitea SSH key
func GetSSHKeyPath(keyName string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	// Store in ~/.ssh/gitea/ to keep gitea keys organized
	keyDir := filepath.Join(homeDir, ".ssh", SSHKeyDirName)
	return filepath.Join(keyDir, keyName), nil
}

// TestSSHConnection tests SSH connectivity to the Gitea instance
func TestSSHConnection(rc *eos_io.RuntimeContext, instance *InstanceConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Testing SSH connection to Gitea",
		zap.String("host", instance.Hostname),
		zap.Int("port", instance.SSHPort))

	// Use ssh command with the configured host alias
	hostAlias := instance.SSHConfigHost
	if hostAlias == "" {
		hostAlias = fmt.Sprintf("gitea-%s", instance.Name)
	}

	// Test connection with timeout
	cmd := exec.Command("ssh",
		"-T", // Disable pseudo-terminal allocation
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(SSHConnectionTimeout.Seconds())),
		hostAlias,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Note: Gitea SSH returns exit code 1 for successful auth but no shell
	// The success message is in stderr: "Hi there! You've successfully authenticated"
	err := cmd.Run()
	output := stdout.String() + stderr.String()

	// Check for Gitea's success message
	if strings.Contains(output, "successfully authenticated") {
		logger.Info("SSH connection test successful",
			zap.String("host", hostAlias))
		return nil
	}

	// If we get permission denied, the key isn't added to Gitea
	if strings.Contains(output, "Permission denied") {
		return fmt.Errorf("authentication failed: SSH key not added to Gitea\n"+
			"Add the public key to Gitea:\n"+
			"  1. Go to %s Settings -> SSH/GPG Keys\n"+
			"  2. Add new key with contents of: %s",
			fmt.Sprintf("http://%s:%d", instance.Hostname, instance.HTTPPort),
			instance.SSHKeyPath+".pub")
	}

	// Other errors
	if err != nil {
		return fmt.Errorf("SSH connection failed: %s\nOutput: %s", err, output)
	}

	return nil
}
