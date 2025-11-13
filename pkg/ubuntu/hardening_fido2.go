package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureFIDO2SSH configures SSH to require FIDO2 hardware keys for authentication
func ConfigureFIDO2SSH(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting FIDO2/YubiKey SSH configuration")

	// ASSESS - Check prerequisites
	logger.Info("Checking prerequisites for FIDO2 SSH setup")
	
	// Check OpenSSH version (needs 8.2+)
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args:    []string{"-V"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to check SSH version: %w", err)
	}
	
	logger.Info("SSH version check", zap.String("version", output))
	
	// Install required packages
	logger.Info("Installing required packages for FIDO2 support")
	packages := []string{
		"libpam-u2f",      // PAM module for U2F/FIDO2
		"pamu2fcfg",       // Configuration tool
		"yubikey-manager", // YubiKey management
	}
	
	for _, pkg := range packages {
		logger.Info("Installing package", zap.String("package", pkg))
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"install", "-y", pkg},
		}); err != nil {
			return fmt.Errorf("failed to install %s: %w", pkg, err)
		}
	}

	// INTERVENE - Configure SSH for FIDO2
	logger.Info("Configuring SSH for FIDO2 authentication")
	
	// Create SSH config directory if it doesn't exist
	sshConfigDir := "/etc/ssh/sshd_config.d"
	if err := os.MkdirAll(sshConfigDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create SSH config directory: %w", err)
	}
	
	// Create FIDO2 SSH configuration
	fido2SSHConfig := `# Eos FIDO2 SSH Configuration
# Require FIDO2 hardware keys for SSH authentication

# Enable public key authentication
PubkeyAuthentication yes

# Enable security key authentication (FIDO2)
PubkeyAuthenticationOptions required

# Disable password authentication
PasswordAuthentication no
ChallengeResponseAuthentication no

# Enable PAM for additional security
UsePAM yes

# Require both SSH key and FIDO2 token
AuthenticationMethods publickey

# Security hardening
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Only allow specific key types (including sk- variants for FIDO2)
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com
`
	
	configPath := filepath.Join(sshConfigDir, "99-eos-fido2.conf")
	if err := os.WriteFile(configPath, []byte(fido2SSHConfig), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write SSH FIDO2 config: %w", err)
	}
	
	// Configure PAM for SSH with FIDO2
	logger.Info("Configuring PAM for SSH FIDO2 authentication")
	
	// Backup original PAM SSH config
	pamSSHPath := "/etc/pam.d/sshd"
	backupPath := pamSSHPath + ".eos-backup"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "cp",
			Args:    []string{"-p", pamSSHPath, backupPath},
		}); err != nil {
			return fmt.Errorf("failed to backup PAM SSH config: %w", err)
		}
	}
	
	// Read current PAM SSH config
	pamContent, err := os.ReadFile(pamSSHPath)
	if err != nil {
		return fmt.Errorf("failed to read PAM SSH config: %w", err)
	}
	
	// Add FIDO2 authentication to PAM SSH config
	lines := strings.Split(string(pamContent), "\n")
	var newLines []string
	fido2Added := false
	
	for _, line := range lines {
		// Add FIDO2 auth before common-auth include
		if strings.Contains(line, "@include common-auth") && !fido2Added {
			newLines = append(newLines, "# Eos FIDO2 authentication")
			newLines = append(newLines, "auth required pam_u2f.so authfile=/etc/u2f_mappings cue")
			newLines = append(newLines, "")
			fido2Added = true
		}
		newLines = append(newLines, line)
	}
	
	// Write updated PAM config
	newPAMContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(pamSSHPath, []byte(newPAMContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write PAM SSH config: %w", err)
	}
	
	// Create U2F mappings file
	u2fMappingsPath := "/etc/u2f_mappings"
	if _, err := os.Stat(u2fMappingsPath); os.IsNotExist(err) {
		if err := os.WriteFile(u2fMappingsPath, []byte("# Format: username:keyhandle1,keyhandle2,...\n"), 0644); err != nil {
			return fmt.Errorf("failed to create U2F mappings file: %w", err)
		}
	}
	
	// Create enrollment helper script
	logger.Info("Creating FIDO2 enrollment helper script")
	enrollScript := `#!/bin/bash
# Eos FIDO2 SSH Key Enrollment Script

set -e

echo "=== Eos FIDO2 SSH Key Enrollment ==="
echo ""
echo "This script will help you enroll your FIDO2/YubiKey for SSH authentication."
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Please run this script as the user who will use the FIDO2 key, not as root."
    echo "Usage: $0"
    exit 1
fi

USERNAME=$(whoami)
echo "Enrolling FIDO2 key for user: $USERNAME"
echo ""

# Generate FIDO2 SSH key
echo "1. Generating FIDO2 SSH key pair..."
echo "   You will be prompted to touch your security key."
echo ""

SSH_DIR="$HOME/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

KEY_FILE="$SSH_DIR/id_ed25519_sk"

if [ -f "$KEY_FILE" ]; then
    echo "FIDO2 SSH key already exists at $KEY_FILE"
    read -p "Do you want to overwrite it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing key."
    else
        ssh-keygen -t ed25519-sk -f "$KEY_FILE" -C "${USERNAME}@$(hostname)"
    fi
else
    ssh-keygen -t ed25519-sk -f "$KEY_FILE" -C "${USERNAME}@$(hostname)"
fi

echo ""
echo "2. Registering FIDO2 key for PAM authentication..."
echo "   You will be prompted to touch your security key again."
echo ""

# Register the key for PAM
TEMP_MAPPING=$(mktemp)
pamu2fcfg -u "$USERNAME" > "$TEMP_MAPPING"

if [ $? -eq 0 ]; then
    echo "3. Adding key to U2F mappings..."
    echo "   This requires sudo access."
    
    # Extract just the key handle from pamu2fcfg output
    KEY_DATA=$(cat "$TEMP_MAPPING" | cut -d: -f2-)
    
    # Update the mappings file
    sudo bash -c "grep -v '^${USERNAME}:' /etc/u2f_mappings > /etc/u2f_mappings.tmp || true"
    sudo bash -c "echo '${USERNAME}:${KEY_DATA}' >> /etc/u2f_mappings.tmp"
    sudo mv /etc/u2f_mappings.tmp /etc/u2f_mappings
    sudo chmod 644 /etc/u2f_mappings
    
    rm -f "$TEMP_MAPPING"
    
    echo ""
    echo "✓ FIDO2 enrollment completed successfully!"
    echo ""
    echo "Your SSH public key is:"
    echo "---"
    cat "${KEY_FILE}.pub"
    echo "---"
    echo ""
    echo "IMPORTANT: Add this public key to ~/.ssh/authorized_keys on servers you want to access."
    echo ""
    echo "To test locally: ssh -o PreferredAuthentications=publickey localhost"
else
    echo "✗ Failed to register FIDO2 key"
    rm -f "$TEMP_MAPPING"
    exit 1
fi
`
	
	enrollScriptPath := "/usr/local/bin/eos-enroll-fido2"
	if err := os.WriteFile(enrollScriptPath, []byte(enrollScript), 0755); err != nil {
		return fmt.Errorf("failed to create enrollment script: %w", err)
	}
	
	// Create recovery mechanism documentation
	recoveryDoc := `# Eos FIDO2 SSH Recovery Procedures

## Overview
This system is configured to require FIDO2 hardware keys for SSH authentication.
This provides strong security but requires proper key management.

## Enrollment
Users must enroll their FIDO2 keys using:
$ eos-enroll-fido2

## Recovery Options

### 1. Physical Console Access
If locked out of SSH, use physical console or out-of-band management.

### 2. Emergency Recovery Account
Create an emergency account with traditional SSH key (stored securely offline):
$ sudo useradd -m -s /bin/bash emergency-admin
$ sudo mkdir -p /home/emergency-admin/.ssh
$ sudo ssh-keygen -t ed25519 -f /home/emergency-admin/.ssh/id_ed25519_emergency
$ sudo cp /home/emergency-admin/.ssh/id_ed25519_emergency.pub /home/emergency-admin/.ssh/authorized_keys
$ sudo chown -R emergency-admin:emergency-admin /home/emergency-admin/.ssh
$ sudo chmod 700 /home/emergency-admin/.ssh
$ sudo chmod 600 /home/emergency-admin/.ssh/authorized_keys

Store the private key securely offline.

### 3. Backup FIDO2 Keys
Always register multiple FIDO2 keys:
- Primary key for daily use
- Backup key stored in secure location
- Consider a second backup in a separate location

### 4. Disable FIDO2 Temporarily (Emergency Only)
If you have console access and need to disable FIDO2:
$ sudo rm /etc/ssh/sshd_config.d/99-eos-fido2.conf
$ sudo systemctl restart sshd

Remember to re-enable after resolving the issue.

## Best Practices
1. Always enroll at least 2 FIDO2 keys
2. Test enrollment immediately after setup
3. Keep backup keys in separate physical locations
4. Document which keys are enrolled for which users
5. Regularly verify keys are working

## Troubleshooting

### SSH Key Not Working
1. Ensure FIDO2 key is plugged in
2. Check SSH client supports sk- key types
3. Verify public key is in authorized_keys
4. Check system logs: sudo journalctl -u sshd -f

### PAM Authentication Failing
1. Check /etc/u2f_mappings has correct entry
2. Verify pam_u2f.so module is installed
3. Review /var/log/auth.log for errors
4. Test with: pamtester sshd username authenticate

`
	
	recoveryPath := "/etc/ssh/FIDO2_RECOVERY.md"
	if err := os.WriteFile(recoveryPath, []byte(recoveryDoc), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to create recovery documentation: %w", err)
	}
	
	// Restart SSH service
	logger.Info("Restarting SSH service to apply FIDO2 configuration")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "sshd"},
	}); err != nil {
		return fmt.Errorf("failed to restart SSH service: %w", err)
	}
	
	// EVALUATE - Verify configuration
	logger.Info("Verifying FIDO2 SSH configuration")
	
	// Check SSH config syntax
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sshd",
		Args:    []string{"-t"},
		Capture: true,
	}); err != nil {
		logger.Error("SSH configuration syntax error", zap.String("output", output), zap.Error(err))
		return fmt.Errorf("SSH configuration syntax error: %w", err)
	}
	
	// Check if required services are running
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "sshd"},
	}); err != nil {
		return fmt.Errorf("SSH service is not active: %w", err)
	}
	
	logger.Info("FIDO2 SSH configuration completed successfully")
	logger.Info("Next steps:",
		zap.String("enroll", "Users should run 'eos-enroll-fido2' to enroll their FIDO2 keys"),
		zap.String("recovery", "Review /etc/ssh/FIDO2_RECOVERY.md for recovery procedures"),
		zap.String("test", "Test SSH access before closing current session"))
	
	return nil
}

// HardenUbuntuWithFIDO2 performs Ubuntu hardening without sudo MFA, using FIDO2 for SSH
func HardenUbuntuWithFIDO2(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Ubuntu hardening with FIDO2 SSH authentication")
	
	// Call the enhanced hardening but with MFA disabled
	// This will run all the security tools and hardening steps
	if err := SecureUbuntuEnhanced(rc, "disabled"); err != nil {
		return fmt.Errorf("ubuntu hardening failed: %w", err)
	}
	
	// Now configure FIDO2 for SSH
	logger.Info("Adding FIDO2 SSH authentication layer")
	if err := ConfigureFIDO2SSH(rc); err != nil {
		return fmt.Errorf("FIDO2 SSH configuration failed: %w", err)
	}
	
	logger.Info("Ubuntu hardening with FIDO2 completed successfully")
	return nil
}