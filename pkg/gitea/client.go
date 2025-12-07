// pkg/gitea/client.go
// Client-side setup logic for connecting to Gitea instances
// Follows Assess -> Intervene -> Evaluate pattern

package gitea

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Setup configures a new Gitea instance for SSH-based git operations
// This is the main entry point called from cmd/create/gitea.go
//
// ASSESS: Validate inputs and check prerequisites
// INTERVENE: Generate SSH key, update SSH config, save configuration
// EVALUATE: Test connection (optional) and provide instructions
func Setup(rc *eos_io.RuntimeContext, config *Config) (*ConfigResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Gitea integration",
		zap.String("instance", config.InstanceName),
		zap.String("hostname", config.Hostname),
		zap.Int("ssh_port", config.SSHPort))

	result := &ConfigResult{
		Warnings: []string{},
	}

	// ASSESS - Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// INTERVENE - Generate SSH key
	keyName := config.SSHKeyName
	if keyName == "" {
		keyName = fmt.Sprintf("gitea-%s", config.InstanceName)
	}

	keyPath := config.SSHKeyPath
	if keyPath == "" {
		var err error
		keyPath, err = GetSSHKeyPath(keyName)
		if err != nil {
			return nil, fmt.Errorf("failed to determine key path: %w", err)
		}
	}

	keyConfig := &SSHKeyConfig{
		KeyName:   keyName,
		KeyPath:   keyPath,
		KeyType:   SSHKeyTypeEd25519,
		Overwrite: false,
	}

	keyResult, err := GenerateSSHKey(rc, keyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w", err)
	}

	result.SSHKeyGenerated = !keyResult.AlreadyExists
	result.SSHKeyPath = keyResult.KeyPath
	result.SSHPublicKeyPath = keyResult.PublicKeyPath

	// Create instance configuration
	instance := &InstanceConfig{
		Name:       config.InstanceName,
		Hostname:   config.Hostname,
		HTTPPort:   config.HTTPPort,
		SSHPort:    config.SSHPort,
		SSHKeyPath: keyResult.KeyPath,
		Organization: config.Organization,
	}

	// INTERVENE - Update SSH config
	if err := UpdateSSHConfig(rc, instance); err != nil {
		return nil, fmt.Errorf("failed to update SSH config: %w", err)
	}
	result.SSHConfigUpdated = true

	// INTERVENE - Save configuration
	if err := AddInstance(rc, instance, config.Default); err != nil {
		return nil, fmt.Errorf("failed to save configuration: %w", err)
	}

	configPath, _ := GetConfigPath()
	result.ConfigPath = configPath

	// EVALUATE - Generate instructions
	result.Instructions = generateInstructions(rc, config, instance, keyResult)

	logger.Info("Gitea integration setup completed",
		zap.String("instance", config.InstanceName),
		zap.String("ssh_config_host", instance.SSHConfigHost))

	return result, nil
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	if config.InstanceName == "" {
		return fmt.Errorf("instance name is required")
	}

	if config.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	if config.HTTPPort <= 0 || config.HTTPPort > 65535 {
		return fmt.Errorf("HTTP port must be between 1 and 65535")
	}

	if config.SSHPort <= 0 || config.SSHPort > 65535 {
		return fmt.Errorf("SSH port must be between 1 and 65535")
	}

	return nil
}

// generateInstructions creates user-friendly setup instructions
func generateInstructions(rc *eos_io.RuntimeContext, config *Config, instance *InstanceConfig, keyResult *SSHKeyResult) string {
	logger := otelzap.Ctx(rc.Ctx)
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("Gitea Integration Setup Complete!\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	// Instance info
	sb.WriteString("Instance Configuration:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString(fmt.Sprintf("  Name:        %s\n", instance.Name))
	sb.WriteString(fmt.Sprintf("  Hostname:    %s\n", instance.Hostname))
	sb.WriteString(fmt.Sprintf("  HTTP Port:   %d\n", instance.HTTPPort))
	sb.WriteString(fmt.Sprintf("  SSH Port:    %d\n", instance.SSHPort))
	sb.WriteString(fmt.Sprintf("  SSH Host:    %s\n", instance.SSHConfigHost))
	if instance.Organization != "" {
		sb.WriteString(fmt.Sprintf("  Organization: %s\n", instance.Organization))
	}
	sb.WriteString("\n")

	// SSH Key info
	sb.WriteString("SSH Key:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	if keyResult.AlreadyExists {
		sb.WriteString("  Status: Using existing key\n")
	} else {
		sb.WriteString("  Status: Generated new key\n")
	}
	sb.WriteString(fmt.Sprintf("  Private Key: %s\n", keyResult.KeyPath))
	sb.WriteString(fmt.Sprintf("  Public Key:  %s\n", keyResult.PublicKeyPath))
	sb.WriteString("\n")

	// Next steps
	sb.WriteString("Next Steps:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString("1. Add the public key to Gitea:\n")
	sb.WriteString(fmt.Sprintf("   - Go to: http://%s:%d\n", instance.Hostname, instance.HTTPPort))
	sb.WriteString("   - Navigate to: Your Profile -> Settings -> SSH/GPG Keys\n")
	sb.WriteString("   - Click 'Add Key' and paste the contents of:\n")
	sb.WriteString(fmt.Sprintf("     %s\n\n", keyResult.PublicKeyPath))

	sb.WriteString("   To copy the public key:\n")
	sb.WriteString(fmt.Sprintf("     cat %s\n\n", keyResult.PublicKeyPath))

	sb.WriteString("2. Create the repository in Gitea:\n")
	if instance.Organization != "" {
		sb.WriteString(fmt.Sprintf("   - Go to: http://%s:%d/org/%s/repo/create\n",
			instance.Hostname, instance.HTTPPort, instance.Organization))
	} else {
		sb.WriteString(fmt.Sprintf("   - Go to: http://%s:%d/repo/create\n",
			instance.Hostname, instance.HTTPPort))
	}
	sb.WriteString("   - Create your repository (e.g., 'hecate')\n\n")

	sb.WriteString("3. Test the SSH connection:\n")
	sb.WriteString(fmt.Sprintf("   ssh -T %s\n\n", instance.SSHConfigHost))

	sb.WriteString("4. Add the remote to your git repo:\n")
	if instance.Organization != "" {
		sb.WriteString(fmt.Sprintf("   git remote add origin git@%s:%s/<repo>.git\n\n",
			instance.SSHConfigHost, instance.Organization))
	} else {
		sb.WriteString(fmt.Sprintf("   git remote add origin git@%s:<user>/<repo>.git\n\n",
			instance.SSHConfigHost))
	}

	sb.WriteString("5. Push your code:\n")
	sb.WriteString("   git push -u origin main\n\n")

	// Quick reference
	sb.WriteString("Quick Reference:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString(fmt.Sprintf("  Web UI:      http://%s:%d\n", instance.Hostname, instance.HTTPPort))
	sb.WriteString(fmt.Sprintf("  SSH Clone:   git@%s:<org>/<repo>.git\n", instance.SSHConfigHost))
	sb.WriteString(fmt.Sprintf("  SSH Config:  ~/.ssh/config (Host: %s)\n", instance.SSHConfigHost))

	logger.Debug("Generated setup instructions")
	return sb.String()
}

// TestConnection tests SSH connectivity to the configured Gitea instance
func TestConnection(rc *eos_io.RuntimeContext, instanceName string) error {
	instance, err := GetInstance(rc, instanceName)
	if err != nil {
		return err
	}

	return TestSSHConnection(rc, instance)
}

// AddRepoRemote adds a git remote for a repository using the configured Gitea instance
func AddRepoRemote(rc *eos_io.RuntimeContext, instanceName, repoPath, remoteName, org, repoName string) error {
	instance, err := GetInstance(rc, instanceName)
	if err != nil {
		return err
	}

	// Default remote name
	if remoteName == "" {
		remoteName = "origin"
	}

	config := &GitRemoteConfig{
		RemoteName:   remoteName,
		RepoPath:     repoPath,
		Organization: org,
		RepoName:     repoName,
	}

	return AddRemote(rc, instance, config)
}
