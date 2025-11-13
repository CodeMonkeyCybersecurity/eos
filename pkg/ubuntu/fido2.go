// pkg/ubuntu/fido2.go

package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FIDO2Config represents FIDO2/WebAuthn configuration options
type FIDO2Config struct {
	EnabledMethods          []string `json:"enabled_methods"`           // ["fido2", "totp", "backup_codes"]
	RequireResidentKey      bool     `json:"require_resident_key"`      // Require passwordless authentication
	RequireUserVerification bool     `json:"require_user_verification"` // Require PIN or biometric
	TimeoutSeconds          int      `json:"timeout_seconds"`           // Authentication timeout
	MaxCredentials          int      `json:"max_credentials"`           // Max FIDO2 keys per user
	EnforceForSudo          bool     `json:"enforce_for_sudo"`          // Require FIDO2 for sudo
	EnforceForSSH           bool     `json:"enforce_for_ssh"`           // Require FIDO2 for SSH
	BackupMethods           []string `json:"backup_methods"`            // Fallback authentication methods
	LoggingEnabled          bool     `json:"logging_enabled"`           // Enable FIDO2 authentication logging
}

// FIDO2Device represents a FIDO2 authenticator device
type FIDO2Device struct {
	DeviceID          string    `json:"device_id"`
	VendorID          string    `json:"vendor_id"`
	ProductID         string    `json:"product_id"`
	Manufacturer      string    `json:"manufacturer"`
	Product           string    `json:"product"`
	SerialNumber      string    `json:"serial_number"`
	FirmwareVersion   string    `json:"firmware_version"`
	SupportedFeatures []string  `json:"supported_features"`
	AttestationType   string    `json:"attestation_type"`
	Connected         bool      `json:"connected"`
	LastSeen          time.Time `json:"last_seen"`
	SecurityLevel     string    `json:"security_level"` // high, medium, low
}

// FIDO2Credential represents a registered FIDO2 credential
type FIDO2Credential struct {
	CredentialID      string    `json:"credential_id"`
	PublicKey         string    `json:"public_key"`
	DeviceID          string    `json:"device_id"`
	UserHandle        string    `json:"user_handle"`
	Username          string    `json:"username"`
	DisplayName       string    `json:"display_name"`
	CreatedAt         time.Time `json:"created_at"`
	LastUsed          time.Time `json:"last_used"`
	UseCount          int       `json:"use_count"`
	IsResident        bool      `json:"is_resident"`
	RequiresPIN       bool      `json:"requires_pin"`
	RequiresBiometric bool      `json:"requires_biometric"`
}

// FIDO2Status represents current FIDO2 system status
type FIDO2Status struct {
	SystemConfigured    bool               `json:"system_configured"`
	PAMConfigured       bool               `json:"pam_configured"`
	UdevRulesConfigured bool               `json:"udev_rules_configured"`
	ConnectedDevices    []FIDO2Device      `json:"connected_devices"`
	RegisteredUsers     []string           `json:"registered_users"`
	TotalCredentials    int                `json:"total_credentials"`
	RecentAuthAttempts  []FIDO2AuthAttempt `json:"recent_auth_attempts"`
	ComplianceScore     int                `json:"compliance_score"`
}

// FIDO2AuthAttempt represents a FIDO2 authentication attempt
type FIDO2AuthAttempt struct {
	Timestamp    time.Time `json:"timestamp"`
	Username     string    `json:"username"`
	DeviceID     string    `json:"device_id"`
	Operation    string    `json:"operation"` // sudo, ssh, login
	Success      bool      `json:"success"`
	ErrorMessage string    `json:"error_message,omitempty"`
	IPAddress    string    `json:"ip_address,omitempty"`
}

// DefaultFIDO2Config returns secure defaults for FIDO2
func DefaultFIDO2Config() *FIDO2Config {
	return &FIDO2Config{
		EnabledMethods:          []string{"fido2", "totp"},
		RequireResidentKey:      true,
		RequireUserVerification: true,
		TimeoutSeconds:          30,
		MaxCredentials:          3,
		EnforceForSudo:          true,
		EnforceForSSH:           true,
		BackupMethods:           []string{"totp", "backup_codes"},
		LoggingEnabled:          true,
	}
}

// PhaseConfigureFIDO2 provides comprehensive FIDO2 setup and integration
func PhaseConfigureFIDO2(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting comprehensive FIDO2 configuration")

	if config == nil {
		config = DefaultFIDO2Config()
	}

	// Step 1: Install FIDO2 packages
	log.Info(" Installing FIDO2 packages")
	if err := installFIDO2Packages(rc); err != nil {
		log.Error(" FIDO2 package installation failed", zap.Error(err))
		return cerr.Wrap(err, "FIDO2 package installation failed")
	}

	// Step 2: Configure udev rules for FIDO2 devices
	log.Info(" Configuring udev rules for FIDO2 devices")
	if err := configureFIDO2UdevRules(rc); err != nil {
		log.Error(" FIDO2 udev configuration failed", zap.Error(err))
		return cerr.Wrap(err, "FIDO2 udev configuration failed")
	}

	// Step 3: Configure PAM for FIDO2 authentication
	log.Info(" Configuring PAM for FIDO2 authentication")
	if err := configureFIDO2PAM(rc, config); err != nil {
		log.Error(" FIDO2 PAM configuration failed", zap.Error(err))
		return cerr.Wrap(err, "FIDO2 PAM configuration failed")
	}

	// Step 4: Set up FIDO2 user enrollment
	log.Info(" Setting up FIDO2 user enrollment system")
	if err := setupFIDO2Enrollment(rc, config); err != nil {
		log.Error(" FIDO2 enrollment setup failed", zap.Error(err))
		return cerr.Wrap(err, "FIDO2 enrollment setup failed")
	}

	// Step 5: Configure FIDO2 logging and monitoring
	log.Info(" Configuring FIDO2 monitoring")
	if err := configureFIDO2Monitoring(rc, config); err != nil {
		log.Error(" FIDO2 monitoring setup failed", zap.Error(err))
		return cerr.Wrap(err, "FIDO2 monitoring setup failed")
	}

	// Step 6: Validate FIDO2 configuration
	log.Info(" Validating FIDO2 configuration")
	if err := validateFIDO2Setup(rc, config); err != nil {
		log.Error(" FIDO2 validation failed", zap.Error(err))
		return cerr.Wrap(err, "FIDO2 validation failed")
	}

	log.Info(" FIDO2 configuration completed successfully")
	return nil
}

// installFIDO2Packages installs required FIDO2 packages
func installFIDO2Packages(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	packages := []string{
		"libfido2-1",
		"libfido2-dev",
		"fido2-tools",
		"libpam-u2f",
		"pamu2fcfg",
		"libu2f-udev",
		"python3-fido2",
	}

	for _, pkg := range packages {
		log.Info(" Installing FIDO2 package", zap.String("package", pkg))
		if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", pkg); err != nil {
			log.Error(" Failed to install package", zap.String("package", pkg), zap.Error(err))
			return cerr.Wrapf(err, "failed to install package: %s", pkg)
		}
	}

	log.Info(" All FIDO2 packages installed successfully")
	return nil
}

// configureFIDO2UdevRules configures udev rules for FIDO2 device access
func configureFIDO2UdevRules(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	udevRules := `# FIDO2/U2F device udev rules for Eos
# Allow access to FIDO2 devices for authentication

# YubiKey devices
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0010|0111|0114|0116|0401|0402|0403|0404|0405|0406|0407|0410", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# Google Titan Security Key
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="18d1", ATTRS{idProduct}=="5026", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# SoloKeys
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="a2ca", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# Nitrokey FIDO2
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="42b1|42b2", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# OnlyKey
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="60fc", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# Feitian ePass FIDO2
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="096e", ATTRS{idProduct}=="0858|0880", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# Generic FIDO2 devices
SUBSYSTEM=="hidraw", ATTRS{usage}=="00010006", TAG+="uaccess", GROUP="plugdev", MODE="0664"

# Ensure eos user is in plugdev group
ACTION=="add", SUBSYSTEM=="hidraw", ATTRS{usage}=="00010006", RUN+="/usr/sbin/usermod -a -G plugdev eos"
`

	udevPath := "/etc/udev/rules.d/70-fido2.rules"
	log.Info(" Writing FIDO2 udev rules", zap.String("path", udevPath))
	if err := os.WriteFile(udevPath, []byte(udevRules), shared.ConfigFilePerm); err != nil {
		log.Error(" Failed to write udev rules", zap.Error(err))
		return cerr.Wrap(err, "failed to write udev rules")
	}

	// Reload udev rules
	log.Info(" Reloading udev rules")
	if err := execute.RunSimple(rc.Ctx, "udevadm", "control", "--reload-rules"); err != nil {
		log.Error(" Failed to reload udev rules", zap.Error(err))
		return cerr.Wrap(err, "failed to reload udev rules")
	}

	if err := execute.RunSimple(rc.Ctx, "udevadm", "trigger"); err != nil {
		log.Error(" Failed to trigger udev", zap.Error(err))
		return cerr.Wrap(err, "failed to trigger udev")
	}

	log.Info(" FIDO2 udev rules configured and loaded")
	return nil
}

// configureFIDO2PAM configures PAM modules for FIDO2 authentication
func configureFIDO2PAM(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)

	// Configure PAM for sudo if enabled
	if config.EnforceForSudo {
		log.Info(" Configuring PAM for sudo FIDO2 authentication")
		if err := configurePAMForSudo(rc, config); err != nil {
			log.Error(" Failed to configure sudo PAM", zap.Error(err))
			return cerr.Wrap(err, "failed to configure sudo PAM")
		}
	}

	// Configure PAM for SSH if enabled
	if config.EnforceForSSH {
		log.Info(" Configuring PAM for SSH FIDO2 authentication")
		if err := configurePAMForSSH(rc, config); err != nil {
			log.Error(" Failed to configure SSH PAM", zap.Error(err))
			return cerr.Wrap(err, "failed to configure SSH PAM")
		}
	}

	log.Info(" FIDO2 PAM configuration completed")
	return nil
}

// configurePAMForSudo configures PAM for sudo FIDO2 authentication
func configurePAMForSudo(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)

	// Backup original sudo PAM configuration
	backupPath := "/etc/pam.d/sudo.backup-" + time.Now().Format("20060102-150405")
	if err := execute.RunSimple(rc.Ctx, "cp", "/etc/pam.d/sudo", backupPath); err != nil {
		log.Error(" Failed to backup sudo PAM config", zap.Error(err))
		return cerr.Wrap(err, "failed to backup sudo PAM config")
	}

	sudoPAMConfig := fmt.Sprintf(`#%%PAM-1.0
# PAM configuration for sudo with FIDO2 support
# Generated by Eos at %s

# FIDO2 authentication (primary method)
auth    sufficient    pam_u2f.so cue origin=pam://hostname appid=pam://hostname
# TOTP authentication (backup method)  
auth    sufficient    pam_google_authenticator.so
# Standard password authentication (fallback)
auth    required      pam_unix.so

@include common-account
@include common-session-noninteractive
`, time.Now().Format(time.RFC3339))

	log.Info(" Writing sudo PAM configuration")
	if err := os.WriteFile("/etc/pam.d/sudo", []byte(sudoPAMConfig), shared.ConfigFilePerm); err != nil {
		log.Error(" Failed to write sudo PAM config", zap.Error(err))
		return cerr.Wrap(err, "failed to write sudo PAM config")
	}

	log.Info(" Sudo PAM configured for FIDO2")
	return nil
}

// configurePAMForSSH configures PAM for SSH FIDO2 authentication
func configurePAMForSSH(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)

	// Update SSH daemon configuration
	sshConfigPath := "/etc/ssh/sshd_config"

	// Read current SSH config
	sshConfigBytes, err := os.ReadFile(sshConfigPath)
	if err != nil {
		log.Error(" Failed to read SSH config", zap.Error(err))
		return cerr.Wrap(err, "failed to read SSH config")
	}

	sshConfig := string(sshConfigBytes)

	// Add FIDO2-related SSH configuration
	fido2SSHConfig := `
# FIDO2/U2F Authentication Configuration
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive:pam
UsePAM yes
`

	// Append FIDO2 config if not already present
	if !strings.Contains(sshConfig, "ChallengeResponseAuthentication") {
		sshConfig += fido2SSHConfig
	}

	// Backup original SSH config
	backupPath := sshConfigPath + ".backup-" + time.Now().Format("20060102-150405")
	if err := execute.RunSimple(rc.Ctx, "cp", sshConfigPath, backupPath); err != nil {
		log.Error(" Failed to backup SSH config", zap.Error(err))
		return cerr.Wrap(err, "failed to backup SSH config")
	}

	log.Info(" Writing SSH configuration")
	if err := os.WriteFile(sshConfigPath, []byte(sshConfig), shared.ConfigFilePerm); err != nil {
		log.Error(" Failed to write SSH config", zap.Error(err))
		return cerr.Wrap(err, "failed to write SSH config")
	}

	// Restart SSH service
	log.Info(" Restarting SSH service")
	if err := eos_unix.RestartSystemdUnitWithRetry(rc.Ctx, "ssh", 3, 2); err != nil {
		log.Error(" Failed to restart SSH service", zap.Error(err))
		return cerr.Wrap(err, "failed to restart SSH service")
	}

	log.Info(" SSH configured for FIDO2 authentication")
	return nil
}

// setupFIDO2Enrollment creates user enrollment system
func setupFIDO2Enrollment(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)

	// Create FIDO2 enrollment script
	enrollmentScript := `#!/bin/bash
# FIDO2 Key Enrollment Script for Eos
# Generated automatically - do not edit manually

set -euo pipefail

USER="${1:-$USER}"
FIDO2_DIR="/home/$USER/.config/fido2"

echo " FIDO2 Key Enrollment for user: $USER"
echo "=================================================="

# Create FIDO2 directory
mkdir -p "$FIDO2_DIR"
chmod 700 "$FIDO2_DIR"

# Check for existing registrations
if [[ -f "$FIDO2_DIR/u2f_keys" ]]; then
    echo " Existing FIDO2 registrations found:"
    cat "$FIDO2_DIR/u2f_keys"
    echo ""
fi

echo " Please insert your FIDO2 security key and touch it when it blinks..."
echo ""

# Generate new U2F registration
if pamu2fcfg -u "$USER" >> "$FIDO2_DIR/u2f_keys"; then
    echo " FIDO2 key registered successfully!"
    echo ""
    echo "Your FIDO2 key is now configured for:"
    echo "  • sudo authentication"
    echo "  • SSH authentication"
    echo ""
    echo " Backup your recovery codes:"
    echo "   • TOTP: Use Google Authenticator app"
    echo "   • Backup codes: Save in secure location"
    
    # Set proper permissions
    chmod 600 "$FIDO2_DIR/u2f_keys"
    chown "$USER:$USER" "$FIDO2_DIR/u2f_keys"
    
else
    echo " FIDO2 key registration failed!"
    exit 1
fi
`

	enrollmentPath := "/usr/local/bin/setup-fido2"
	log.Info(" Creating FIDO2 enrollment script", zap.String("path", enrollmentPath))
	if err := os.WriteFile(enrollmentPath, []byte(enrollmentScript), shared.ExecutablePerm); err != nil {
		log.Error(" Failed to write enrollment script", zap.Error(err))
		return cerr.Wrap(err, "failed to write enrollment script")
	}

	// Create FIDO2 management script
	managementScript := `#!/bin/bash
# FIDO2 Key Management Script for Eos
# Generated automatically - do not edit manually

set -euo pipefail

USER="${1:-$USER}"
FIDO2_DIR="/home/$USER/.config/fido2"
ACTION="${2:-list}"

case "$ACTION" in
    "list")
        echo " FIDO2 Keys for user: $USER"
        if [[ -f "$FIDO2_DIR/u2f_keys" ]]; then
            echo "Registered keys:"
            cat "$FIDO2_DIR/u2f_keys"
        else
            echo "No FIDO2 keys registered"
        fi
        ;;
    "remove")
        if [[ -f "$FIDO2_DIR/u2f_keys" ]]; then
            rm "$FIDO2_DIR/u2f_keys"
            echo " All FIDO2 keys removed for user: $USER"
        else
            echo "No FIDO2 keys to remove"
        fi
        ;;
    "test")
        echo " Testing FIDO2 authentication..."
        if sudo -u "$USER" pam_test_fido2; then
            echo " FIDO2 authentication test successful"
        else
            echo " FIDO2 authentication test failed"
        fi
        ;;
    *)
        echo "Usage: $0 [username] [list|remove|test]"
        exit 1
        ;;
esac
`

	managementPath := "/usr/local/bin/manage-fido2"
	log.Info(" Creating FIDO2 management script", zap.String("path", managementPath))
	if err := os.WriteFile(managementPath, []byte(managementScript), shared.ExecutablePerm); err != nil {
		log.Error(" Failed to write management script", zap.Error(err))
		return cerr.Wrap(err, "failed to write management script")
	}

	log.Info(" FIDO2 enrollment system configured")
	return nil
}

// configureFIDO2Monitoring sets up FIDO2 authentication monitoring
func configureFIDO2Monitoring(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)

	if !config.LoggingEnabled {
		log.Info("FIDO2 logging disabled, skipping monitoring setup")
		return nil
	}

	// Create FIDO2 log directory
	logDir := "/var/log/fido2"
	if err := os.MkdirAll(logDir, shared.ServiceDirPerm); err != nil {
		log.Error(" Failed to create FIDO2 log directory", zap.Error(err))
		return cerr.Wrap(err, "failed to create FIDO2 log directory")
	}

	// Configure rsyslog for FIDO2 logging
	rsyslogConfig := `# FIDO2 authentication logging
# Log FIDO2 PAM messages to separate file
:msg,contains,"pam_u2f" /var/log/fido2/auth.log
& stop
`

	configPath := "/etc/rsyslog.d/60-fido2.conf"
	log.Info(" Configuring FIDO2 logging", zap.String("path", configPath))
	if err := os.WriteFile(configPath, []byte(rsyslogConfig), shared.ConfigFilePerm); err != nil {
		log.Error(" Failed to write rsyslog config", zap.Error(err))
		return cerr.Wrap(err, "failed to write rsyslog config")
	}

	// Restart rsyslog service
	log.Info(" Restarting rsyslog service")
	if err := eos_unix.RestartSystemdUnitWithRetry(rc.Ctx, "rsyslog", 3, 2); err != nil {
		log.Error(" Failed to restart rsyslog", zap.Error(err))
		return cerr.Wrap(err, "failed to restart rsyslog")
	}

	log.Info(" FIDO2 monitoring configured")
	return nil
}

// validateFIDO2Setup validates the FIDO2 configuration
func validateFIDO2Setup(rc *eos_io.RuntimeContext, config *FIDO2Config) error {
	log := otelzap.Ctx(rc.Ctx)

	// Check FIDO2 status
	status, err := GetFIDO2Status(rc)
	if err != nil {
		log.Error(" Failed to get FIDO2 status", zap.Error(err))
		return cerr.Wrap(err, "failed to get FIDO2 status")
	}

	if !status.SystemConfigured {
		log.Error(" FIDO2 system is not properly configured")
		return cerr.New("FIDO2 system is not properly configured")
	}

	log.Info(" FIDO2 validation completed",
		zap.Bool("pam_configured", status.PAMConfigured),
		zap.Bool("udev_configured", status.UdevRulesConfigured),
		zap.Int("connected_devices", len(status.ConnectedDevices)),
		zap.Int("compliance_score", status.ComplianceScore))

	return nil
}

// GetFIDO2Status returns the current FIDO2 system status
func GetFIDO2Status(rc *eos_io.RuntimeContext) (*FIDO2Status, error) {
	log := otelzap.Ctx(rc.Ctx)

	status := &FIDO2Status{
		ConnectedDevices:   []FIDO2Device{},
		RegisteredUsers:    []string{},
		RecentAuthAttempts: []FIDO2AuthAttempt{},
	}

	// Check if FIDO2 packages are installed
	requiredPackages := []string{"libfido2-1", "libpam-u2f", "fido2-tools"}
	for _, pkg := range requiredPackages {
		if err := execute.RunSimple(rc.Ctx, "dpkg", "-l", pkg); err != nil {
			log.Warn("Required FIDO2 package not installed", zap.String("package", pkg))
			status.SystemConfigured = false
			return status, nil
		}
	}

	// Check PAM configuration
	if _, err := os.Stat("/etc/pam.d/sudo"); err == nil {
		// Check if pam_u2f is configured
		pamContent, err := os.ReadFile("/etc/pam.d/sudo")
		if err == nil && strings.Contains(string(pamContent), "pam_u2f") {
			status.PAMConfigured = true
		}
	}

	// Check udev rules
	if _, err := os.Stat("/etc/udev/rules.d/70-fido2.rules"); err == nil {
		status.UdevRulesConfigured = true
	}

	// Check for connected FIDO2 devices
	devices, err := detectFIDO2Devices(rc)
	if err != nil {
		log.Warn("Failed to detect FIDO2 devices", zap.Error(err))
	} else {
		status.ConnectedDevices = devices
	}

	// Check registered users
	users, err := findRegisteredFIDO2Users(rc)
	if err != nil {
		log.Warn("Failed to find registered FIDO2 users", zap.Error(err))
	} else {
		status.RegisteredUsers = users
	}

	// Calculate compliance score
	score := 0
	if status.PAMConfigured {
		score += 30
	}
	if status.UdevRulesConfigured {
		score += 20
	}
	if len(status.ConnectedDevices) > 0 {
		score += 25
	}
	if len(status.RegisteredUsers) > 0 {
		score += 25
	}
	status.ComplianceScore = score

	status.SystemConfigured = status.PAMConfigured && status.UdevRulesConfigured

	log.Debug("FIDO2 status retrieved",
		zap.Bool("system_configured", status.SystemConfigured),
		zap.Bool("pam_configured", status.PAMConfigured),
		zap.Bool("udev_configured", status.UdevRulesConfigured),
		zap.Int("connected_devices", len(status.ConnectedDevices)),
		zap.Int("registered_users", len(status.RegisteredUsers)),
		zap.Int("compliance_score", status.ComplianceScore))

	return status, nil
}

// detectFIDO2Devices detects connected FIDO2 devices
func detectFIDO2Devices(rc *eos_io.RuntimeContext) ([]FIDO2Device, error) {
	devices := []FIDO2Device{}

	// Use fido2-token to list connected devices
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "fido2-token",
		Args:    []string{"-L"},
	})
	if err != nil {
		return devices, cerr.Wrap(err, "failed to list FIDO2 devices")
	}

	// Parse device list (simplified parsing)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/dev/hidraw") {
			// Extract device information
			device := FIDO2Device{
				DeviceID:      line,
				Connected:     true,
				LastSeen:      time.Now(),
				SecurityLevel: "medium", // Default, would need more sophisticated detection
			}
			devices = append(devices, device)
		}
	}

	return devices, nil
}

// findRegisteredFIDO2Users finds users with registered FIDO2 keys
func findRegisteredFIDO2Users(rc *eos_io.RuntimeContext) ([]string, error) {
	users := []string{}

	// Check /home directory for users with FIDO2 configurations
	homeDir := "/home"
	entries, err := os.ReadDir(homeDir)
	if err != nil {
		return users, cerr.Wrap(err, "failed to read home directory")
	}

	for _, entry := range entries {
		if entry.IsDir() {
			username := entry.Name()
			fido2ConfigPath := filepath.Join(homeDir, username, ".config", "fido2", "u2f_keys")
			if _, err := os.Stat(fido2ConfigPath); err == nil {
				users = append(users, username)
			}
		}
	}

	return users, nil
}
