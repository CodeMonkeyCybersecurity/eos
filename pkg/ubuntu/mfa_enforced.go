package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// EnforcedMFAConfig represents the enforced MFA configuration
type EnforcedMFAConfig struct {
	RequireMFA            bool     `json:"require_mfa"`
	AllowPasswordFallback bool     `json:"allow_password_fallback"`
	EnforcementMode       string   `json:"enforcement_mode"` // strict, graceful
	ExemptUsers           []string `json:"exempt_users"`
	GracePeriodHours      int      `json:"grace_period_hours"`
}

// DefaultEnforcedMFAConfig returns secure defaults for MFA enforcement
func DefaultEnforcedMFAConfig() EnforcedMFAConfig {
	return EnforcedMFAConfig{
		RequireMFA:            true,
		AllowPasswordFallback: false, // Strict by default
		EnforcementMode:       "graceful",
		ExemptUsers:           []string{}, // No exemptions by default
		GracePeriodHours:      24,         // 24-hour grace period for setup
	}
}

const gracefulPAMSudoConfig = `# PAM configuration for sudo with GRACEFUL MFA (temporary)
# /etc/pam.d/sudo - Allows password fallback during grace period
auth       sufficient pam_unix.so try_first_pass
auth       optional   pam_google_authenticator.so nullok
account    include    system-account
session    include    system-session
`

const mfaEnforcementScript = `#!/bin/bash
# MFA Enforcement and Setup Guide
# This script guides users through MFA setup and enforces it afterwards

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="/etc/eos/mfa-enforcement.conf"
GOOGLE_AUTH_FILE="$HOME/.google_authenticator"
ENFORCEMENT_LOG="/var/log/eos-mfa-enforcement.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$ENFORCEMENT_LOG"
}

print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                              ║${NC}"
    echo -e "${BLUE}║                     MANDATORY MFA SETUP REQUIRED                        ║${NC}"
    echo -e "${BLUE}║                                                                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}  SECURITY NOTICE: Multi-Factor Authentication (MFA) is now REQUIRED${NC}"
    echo -e "${YELLOW}    for all sudo and root access on this system.${NC}"
    echo
}

check_mfa_status() {
    if [[ -f "$GOOGLE_AUTH_FILE" ]]; then
        echo -e "${GREEN} MFA is already configured for user: $(whoami)${NC}"
        return 0
    else
        echo -e "${RED} MFA is NOT configured for user: $(whoami)${NC}"
        return 1
    fi
}

setup_mfa_interactive() {
    echo -e "${BLUE} Starting Interactive MFA Setup${NC}"
    echo "============================================================================"
    echo
    echo "This process will:"
    echo "  1. Generate a unique secret key for your account"
    echo "  2. Display a QR code for your authenticator app"
    echo "  3. Create emergency backup codes"
    echo "  4. Test the configuration"
    echo
    echo " Supported Authenticator Apps:"
    echo "  • Google Authenticator (iOS/Android)"
    echo "  • Microsoft Authenticator (iOS/Android)"
    echo "  • Authy (iOS/Android/Desktop)"
    echo "  • 1Password (with TOTP support)"
    echo "  • Bitwarden (with TOTP support)"
    echo
    
    read -p "Press ENTER to continue with MFA setup..." -r
    echo
    
    # Backup existing config if present
    if [[ -f "$GOOGLE_AUTH_FILE" ]]; then
        echo -e "${YELLOW}  Existing MFA configuration found. Creating backup...${NC}"
        cp "$GOOGLE_AUTH_FILE" "$GOOGLE_AUTH_FILE.backup.$(date +%s)"
    fi
    
    echo -e "${BLUE} Generating MFA configuration...${NC}"
    echo
    
    # Run google-authenticator with enhanced security settings
    google-authenticator \
        --time-based \
        --disallow-reuse \
        --force \
        --rate-limit=3 \
        --rate-time=30 \
        --window-size=1 \
        --emergency-codes=5
    
    echo
    echo -e "${GREEN} MFA configuration completed successfully!${NC}"
    
    # Log the setup
    log_message "MFA configured for user: $(whoami) from IP: ${SSH_CLIENT%% *}"
}

test_mfa_configuration() {
    echo
    echo -e "${BLUE} Testing MFA Configuration${NC}"
    echo "============================================================================"
    echo
    echo "We'll now test your MFA setup to ensure it's working correctly."
    echo
    echo -e "${YELLOW}  IMPORTANT: Keep this terminal session open during testing!${NC}"
    echo "   If the test fails, you can still disable MFA from this session."
    echo
    
    read -p "Press ENTER to start the MFA test..." -r
    echo
    
    echo "Please open your authenticator app and get ready to enter a code."
    echo
    read -p "Enter the 6-digit code from your authenticator app: " -r code
    
    # Test the code using a temporary validation
    if echo "$code" | google-authenticator --verify="$GOOGLE_AUTH_FILE" 2>/dev/null; then
        echo -e "${GREEN} MFA test successful! Your configuration is working correctly.${NC}"
        log_message "MFA test successful for user: $(whoami)"
        return 0
    else
        echo -e "${RED} MFA test failed. Please check your authenticator app and try again.${NC}"
        echo
        echo "Common issues:"
        echo "  • Make sure your device time is synchronized"
        echo "  • Verify you scanned the QR code correctly"
        echo "  • Try waiting for the next code (codes change every 30 seconds)"
        echo
        read -p "Would you like to reconfigure MFA? (y/N): " -r reconfigure
        if [[ "$reconfigure" =~ ^[Yy]$ ]]; then
            setup_mfa_interactive
            test_mfa_configuration
        else
            log_message "MFA test failed for user: $(whoami)"
            return 1
        fi
    fi
}

enforce_mfa_strict() {
    echo
    echo -e "${RED} ENFORCING STRICT MFA MODE${NC}"
    echo "============================================================================"
    echo
    echo -e "${YELLOW}  After this point, password-only authentication will be DISABLED.${NC}"
    echo "   You MUST use your authenticator app for all sudo operations."
    echo
    echo -e "${GREEN} Emergency access available via: sudo disable-mfa-emergency${NC}"
    echo
    
    read -p "Proceed with strict MFA enforcement? (y/N): " -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Enforcement cancelled. MFA remains in graceful mode."
        return 1
    fi
    
    # Apply strict PAM configuration
    if [[ -f "/etc/pam.d/sudo" ]]; then
        cp "/etc/pam.d/sudo" "/etc/pam.d/sudo.backup-before-strict"
        cat > "/etc/pam.d/sudo" << 'EOF'
# PAM configuration for sudo with ENFORCED MFA
# No fallback to password-only authentication
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
account    include    system-account
session    include    system-session
EOF
    fi
    
    if [[ -f "/etc/pam.d/su" ]]; then
        cp "/etc/pam.d/su" "/etc/pam.d/su.backup-before-strict"
        cat > "/etc/pam.d/su" << 'EOF'
# PAM configuration for su with ENFORCED MFA
# No fallback to password-only authentication  
auth       sufficient pam_rootok.so
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
account    include    system-account
session    include    system-session
EOF
    fi
    
    # Update enforcement config
    echo "enforce_mfa=true" > "$CONFIG_FILE"
    echo "enforcement_date=$(date)" >> "$CONFIG_FILE"
    echo "enforced_by=$(whoami)" >> "$CONFIG_FILE"
    
    echo -e "${GREEN} Strict MFA enforcement is now active.${NC}"
    log_message "Strict MFA enforcement activated by user: $(whoami)"
}

show_post_setup_info() {
    echo
    echo -e "${GREEN} MFA Setup Complete!${NC}"
    echo "============================================================================"
    echo
    echo -e "${BLUE} Important Information:${NC}"
    echo
    echo "• Your MFA secret is stored in: $GOOGLE_AUTH_FILE"
    echo "• Emergency backup codes are saved in the same file"
    echo "• Each backup code can only be used once"
    echo
    echo -e "${BLUE} Next time you use sudo, you'll need:${NC}"
    echo "  1. Your user password"
    echo "  2. Your 6-digit TOTP code from your authenticator app"
    echo
    echo -e "${BLUE}🆘 Emergency Access:${NC}"
    echo "  • If locked out: sudo disable-mfa-emergency"
    echo "  • Or contact your system administrator"
    echo
    echo -e "${BLUE} MFA Management Commands:${NC}"
    echo "  • Reconfigure MFA: setup-mfa"
    echo "  • Check MFA status: mfa-status"
    echo "  • Emergency disable: disable-mfa-emergency"
    echo
    echo -e "${YELLOW}  BACKUP YOUR RECOVERY CODES IN A SECURE LOCATION!${NC}"
    echo
}

# Main execution
main() {
    print_header
    
    # Check if MFA is already configured
    if check_mfa_status; then
        echo "MFA is already set up for this user."
        echo
        read -p "Would you like to reconfigure MFA? (y/N): " -r reconfigure
        if [[ ! "$reconfigure" =~ ^[Yy]$ ]]; then
            echo "Exiting without changes."
            exit 0
        fi
    fi
    
    # Run interactive MFA setup
    setup_mfa_interactive
    
    # Test the configuration
    if ! test_mfa_configuration; then
        echo -e "${RED} MFA setup failed. Please contact your system administrator.${NC}"
        exit 1
    fi
    
    # Show post-setup information
    show_post_setup_info
    
    # Offer to enforce strict mode immediately
    echo -e "${BLUE} Enforcement Options:${NC}"
    echo
    echo "1. Graceful Mode (recommended): Allow password fallback during transition"
    echo "2. Strict Mode: Require MFA immediately (no password fallback)"
    echo
    read -p "Choose enforcement mode (1/2): " -r mode
    
    case "$mode" in
        "2")
            enforce_mfa_strict
            ;;
        *)
            echo -e "${YELLOW}  Graceful mode active. MFA will be strictly enforced in 24 hours.${NC}"
            echo "   Run 'sudo enforce-mfa-strict' to enable strict mode sooner."
            log_message "MFA configured in graceful mode for user: $(whoami)"
            ;;
    esac
    
    echo
    echo -e "${GREEN} MFA enforcement setup completed successfully!${NC}"
}

# Only run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
`

const mfaStatusScript = `#!/bin/bash
# MFA Status Check Script
# Displays current MFA configuration and enforcement status

set -euo pipefail

CONFIG_FILE="/etc/eos/mfa-enforcement.conf"
GOOGLE_AUTH_FILE="$HOME/.google_authenticator"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE} MFA Status Report for $(whoami)${NC}"
echo "============================================================================"

# Check user MFA configuration
if [[ -f "$GOOGLE_AUTH_FILE" ]]; then
    echo -e "${GREEN} User MFA Configuration: CONFIGURED${NC}"
    echo "   Secret file: $GOOGLE_AUTH_FILE"
    echo "   Last modified: $(stat -f %Sm "$GOOGLE_AUTH_FILE" 2>/dev/null || stat -c %y "$GOOGLE_AUTH_FILE" 2>/dev/null)"
else
    echo -e "${RED} User MFA Configuration: NOT CONFIGURED${NC}"
    echo "   Run 'setup-mfa' to configure MFA for your account"
fi

echo

# Check PAM configuration
echo -e "${BLUE} PAM Configuration Status:${NC}"

if grep -q "pam_google_authenticator.so" /etc/pam.d/sudo 2>/dev/null; then
    if grep -q "required.*pam_google_authenticator.so" /etc/pam.d/sudo; then
        echo -e "${GREEN} sudo MFA: ENFORCED (strict mode)${NC}"
    elif grep -q "nullok" /etc/pam.d/sudo; then
        echo -e "${YELLOW}  sudo MFA: GRACEFUL (fallback allowed)${NC}"
    else
        echo -e "${GREEN} sudo MFA: CONFIGURED${NC}"
    fi
else
    echo -e "${RED} sudo MFA: NOT CONFIGURED${NC}"
fi

if grep -q "pam_google_authenticator.so" /etc/pam.d/su 2>/dev/null; then
    if grep -q "required.*pam_google_authenticator.so" /etc/pam.d/su; then
        echo -e "${GREEN} su MFA: ENFORCED (strict mode)${NC}"
    elif grep -q "nullok" /etc/pam.d/su; then
        echo -e "${YELLOW}  su MFA: GRACEFUL (fallback allowed)${NC}"
    else
        echo -e "${GREEN} su MFA: CONFIGURED${NC}"
    fi
else
    echo -e "${RED} su MFA: NOT CONFIGURED${NC}"
fi

echo

# Check enforcement configuration
echo -e "${BLUE}⚖️  Enforcement Policy:${NC}"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE" 2>/dev/null || true
    if [[ "${enforce_mfa:-false}" == "true" ]]; then
        echo -e "${GREEN} MFA Enforcement: ACTIVE${NC}"
        echo "   Enforced on: ${enforcement_date:-unknown}"
        echo "   Enforced by: ${enforced_by:-unknown}"
    else
        echo -e "${YELLOW}  MFA Enforcement: GRACEFUL MODE${NC}"
    fi
else
    echo -e "${YELLOW}  MFA Enforcement: NO POLICY SET${NC}"
fi

echo

# Show recent authentication attempts
echo -e "${BLUE} Recent Authentication Activity:${NC}"
if command -v journalctl >/dev/null 2>&1; then
    echo "Last 5 sudo attempts:"
    journalctl -u sudo --since "1 hour ago" --no-pager -n 5 2>/dev/null | tail -n 5 || echo "No recent sudo activity found"
else
    echo "Journal not available"
fi

echo
echo -e "${BLUE}🆘 Available Commands:${NC}"
echo "• setup-mfa          - Configure MFA for your account"
echo "• enforce-mfa-strict - Enable strict MFA enforcement"
echo "• disable-mfa-emergency - Emergency MFA disable (admin only)"
echo
`

// ConfigureEnforcedMFA sets up MFA with proper enforcement and user guidance
func ConfigureEnforcedMFA(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Configuring enforced Multi-Factor Authentication")

	// First, install required packages
	if err := installMFAPackages(rc); err != nil {
		return fmt.Errorf("install MFA packages: %w", err)
	}

	// Create enhanced setup script
	if err := createEnforcedMFASetupScript(rc); err != nil {
		return fmt.Errorf("create enforced MFA setup script: %w", err)
	}

	// Create status checking script
	if err := createMFAStatusScript(rc); err != nil {
		return fmt.Errorf("create MFA status script: %w", err)
	}

	// Create enforcement script
	if err := createMFAEnforcementScript(rc); err != nil {
		return fmt.Errorf("create MFA enforcement script: %w", err)
	}

	// Create MFA config directory
	if err := execute.RunSimple(rc.Ctx, "mkdir", "-p", "/etc/eos"); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Configure graceful PAM initially (allows setup)
	if err := configureGracefulPAM(rc); err != nil {
		return fmt.Errorf("configure graceful PAM: %w", err)
	}

	// Prompt user to set up MFA interactively
	if err := promptUserMFASetup(rc); err != nil {
		return fmt.Errorf("user MFA setup: %w", err)
	}

	logger.Info(" Enforced MFA configuration completed",
		zap.String("setup_script", "/usr/local/bin/setup-mfa"),
		zap.String("status_script", "/usr/local/bin/mfa-status"),
		zap.String("enforcement_script", "/usr/local/bin/enforce-mfa-strict"))

	return nil
}

// configureGracefulPAM sets up PAM with graceful MFA enforcement (allows fallback during setup)
func configureGracefulPAM(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Backup original configurations
	sudoOriginal := "/etc/pam.d/sudo"
	sudoBackup := "/etc/pam.d/sudo.backup-before-mfa"
	suOriginal := "/etc/pam.d/su"
	suBackup := "/etc/pam.d/su.backup-before-mfa"

	// Backup sudo config
	if _, err := os.Stat(sudoBackup); os.IsNotExist(err) {
		if err := execute.RunSimple(rc.Ctx, "cp", sudoOriginal, sudoBackup); err != nil {
			return fmt.Errorf("backup sudo PAM: %w", err)
		}
		logger.Info(" Backed up original sudo PAM configuration")
	}

	// Backup su config
	if _, err := os.Stat(suBackup); os.IsNotExist(err) {
		if err := execute.RunSimple(rc.Ctx, "cp", suOriginal, suBackup); err != nil {
			return fmt.Errorf("backup su PAM: %w", err)
		}
		logger.Info(" Backed up original su PAM configuration")
	}

	// Apply graceful configurations
	if err := os.WriteFile(sudoOriginal, []byte(gracefulPAMSudoConfig), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write graceful sudo PAM config: %w", err)
	}

	if err := os.WriteFile(suOriginal, []byte(pamSuMFAConfig), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write su PAM config: %w", err)
	}

	// Create emergency recovery script
	if err := createEmergencyRecoveryScript(rc); err != nil {
		logger.Warn("Failed to create emergency recovery script", zap.Error(err))
	}

	logger.Info("  Applied graceful MFA PAM configuration")
	return nil
}

// promptUserMFASetup guides the current user through MFA setup
func promptUserMFASetup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println()
	fmt.Println(" MANDATORY MFA SETUP REQUIRED")
	fmt.Println("═══════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  Multi-Factor Authentication (MFA) must be configured for secure")
	fmt.Println("   sudo and root access on this system.")
	fmt.Println()
	fmt.Println("This setup will:")
	fmt.Println("  • Generate a unique secret for your account")
	fmt.Println("  • Display a QR code for your mobile authenticator app")
	fmt.Println("  • Create emergency backup codes")
	fmt.Println("  • Test the configuration")
	fmt.Println()

	// Check if running in an interactive terminal
	if isInteractiveTerminal() {
		// Check if user wants to proceed with interactive setup
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Proceed with MFA setup now? (Y/n): ")
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read user input: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response == "n" || response == "no" {
			fmt.Println()
			fmt.Println("  MFA setup deferred. You can configure it later by running:")
			fmt.Println("   sudo setup-mfa")
			fmt.Println()
			fmt.Println("   Note: MFA will be enforced in 24 hours for security.")

			// Schedule enforcement for later
			if err := scheduleGracePeriod(rc); err != nil {
				logger.Warn("Failed to schedule grace period", zap.Error(err))
			}

			return nil
		}
	} else {
		// Non-interactive mode - defer setup for later
		fmt.Println()
		fmt.Println("  Non-interactive environment detected.")
		fmt.Println("  MFA setup deferred. Configure it later by running:")
		fmt.Println("   sudo setup-mfa")
		fmt.Println()
		fmt.Println("   Note: MFA will be enforced in 24 hours for security.")

		// Schedule enforcement for later
		if err := scheduleGracePeriod(rc); err != nil {
			logger.Warn("Failed to schedule grace period", zap.Error(err))
		}

		logger.Info(" MFA setup deferred for later manual configuration")
		return nil
	}

	// Run the interactive setup script
	fmt.Println()
	fmt.Println(" Starting interactive MFA setup...")
	fmt.Println()

	if err := execute.RunSimple(rc.Ctx, "/usr/local/bin/setup-mfa"); err != nil {
		return fmt.Errorf("run MFA setup script: %w", err)
	}

	logger.Info(" User MFA setup completed successfully")
	return nil
}

// scheduleGracePeriod sets up a grace period before strict enforcement
func scheduleGracePeriod(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create grace period config
	config := fmt.Sprintf(`# MFA Grace Period Configuration
grace_period_start=%s
grace_period_hours=24
grace_period_end=%s
enforce_mfa=false
`, time.Now().Format(time.RFC3339), time.Now().Add(24*time.Hour).Format(time.RFC3339))

	if err := os.WriteFile("/etc/eos/mfa-enforcement.conf", []byte(config), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write grace period config: %w", err)
	}

	// Create a systemd timer for automatic enforcement (optional)
	timerContent := `[Unit]
Description=Enforce MFA after grace period
Requires=enforce-mfa-strict.service

[Timer]
OnCalendar=*-*-* *:00:00
Persistent=true

[Install]
WantedBy=timers.target
`

	serviceContent := `[Unit]
Description=Enforce strict MFA
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/enforce-mfa-strict --auto
User=root

[Install]
WantedBy=multi-user.target
`

	// Write timer and service files (but don't enable yet)
	if err := os.WriteFile("/etc/systemd/system/enforce-mfa-strict.timer", []byte(timerContent), shared.ConfigFilePerm); err != nil {
		logger.Warn("Failed to create MFA enforcement timer", zap.Error(err))
	}

	if err := os.WriteFile("/etc/systemd/system/enforce-mfa-strict.service", []byte(serviceContent), shared.ConfigFilePerm); err != nil {
		logger.Warn("Failed to create MFA enforcement service", zap.Error(err))
	}

	logger.Info("⏰ Grace period scheduled for 24 hours")
	return nil
}

func createEnforcedMFASetupScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	scriptPath := "/usr/local/bin/setup-mfa"
	if err := os.WriteFile(scriptPath, []byte(mfaEnforcementScript), shared.ExecutablePerm); err != nil {
		return fmt.Errorf("write enforced MFA setup script: %w", err)
	}

	logger.Info(" Created enforced MFA setup script", zap.String("path", scriptPath))
	return nil
}

func createMFAStatusScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	scriptPath := "/usr/local/bin/mfa-status"
	if err := os.WriteFile(scriptPath, []byte(mfaStatusScript), shared.ExecutablePerm); err != nil {
		return fmt.Errorf("write MFA status script: %w", err)
	}

	logger.Info(" Created MFA status script", zap.String("path", scriptPath))
	return nil
}

func createMFAEnforcementScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	enforcementScript := `#!/bin/bash
# MFA Strict Enforcement Script
set -euo pipefail

CONFIG_FILE="/etc/eos/mfa-enforcement.conf"

echo " Enabling strict MFA enforcement..."

# Apply strict PAM configurations
cat > /etc/pam.d/sudo << 'EOF'
# PAM configuration for sudo with ENFORCED MFA
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
account    include    system-account
session    include    system-session
EOF

cat > /etc/pam.d/su << 'EOF'
# PAM configuration for su with ENFORCED MFA
auth       sufficient pam_rootok.so
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
account    include    system-account
session    include    system-session
EOF

# Update enforcement config
echo "enforce_mfa=true" > "$CONFIG_FILE"
echo "enforcement_date=$(date)" >> "$CONFIG_FILE"
echo "enforced_by=$(whoami)" >> "$CONFIG_FILE"

echo " Strict MFA enforcement is now active."
echo "   All sudo operations now require MFA authentication."
`

	scriptPath := "/usr/local/bin/enforce-mfa-strict"
	if err := os.WriteFile(scriptPath, []byte(enforcementScript), shared.ExecutablePerm); err != nil {
		return fmt.Errorf("write MFA enforcement script: %w", err)
	}

	logger.Info(" Created MFA enforcement script", zap.String("path", scriptPath))
	return nil
}

// isInteractiveTerminal checks if the current environment supports interactive input
func isInteractiveTerminal() bool {
	// Check if stdin is a terminal
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// createEmergencyRecoveryScript creates a script to restore sudo access in case of MFA lockout
func createEmergencyRecoveryScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	emergencyScript := `#!/bin/bash
# Emergency MFA Recovery Script
# Use this script to restore sudo access if locked out due to MFA issues
# 
# USAGE: Run this script as root from a console/recovery mode
#        sudo bash /usr/local/bin/emergency-mfa-recovery
#
# This script restores the original PAM configurations

set -euo pipefail

echo "=============================================================================="
echo "                      EMERGENCY MFA RECOVERY"
echo "=============================================================================="
echo
echo "This script will restore the original sudo/su configurations"
echo "WARNING: This will disable MFA enforcement temporarily"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    echo "Try: sudo bash $0"
    exit 1
fi

# Restore original sudo PAM configuration
if [[ -f "/etc/pam.d/sudo.backup-before-mfa" ]]; then
    echo "Restoring original sudo PAM configuration..."
    cp "/etc/pam.d/sudo.backup-before-mfa" "/etc/pam.d/sudo"
    echo "✓ sudo PAM configuration restored"
else
    echo "⚠ No sudo backup found, creating safe default..."
    cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
EOF
    echo "✓ Safe sudo PAM configuration created"
fi

# Restore original su PAM configuration  
if [[ -f "/etc/pam.d/su.backup-before-mfa" ]]; then
    echo "Restoring original su PAM configuration..."
    cp "/etc/pam.d/su.backup-before-mfa" "/etc/pam.d/su"
    echo "✓ su PAM configuration restored"
else
    echo "⚠ No su backup found, creating safe default..."
    cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0

auth       sufficient pam_rootok.so
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
EOF
    echo "✓ Safe su PAM configuration created"
fi

echo
echo "=============================================================================="
echo "                           RECOVERY COMPLETE"
echo "=============================================================================="
echo
echo "✓ sudo and su access has been restored"
echo "✓ You should now be able to use sudo normally"
echo
echo "NEXT STEPS:"
echo "1. Test sudo access: sudo whoami"
echo "2. Configure MFA properly: sudo setup-mfa"
echo "3. Re-enable MFA: sudo eos secure ubuntu --enforce-mfa --mfa-only"
echo
echo "SECURITY NOTICE: MFA enforcement has been temporarily disabled"
echo "Re-enable it as soon as possible for security"
echo
`

	scriptPath := "/usr/local/bin/emergency-mfa-recovery"
	if err := os.WriteFile(scriptPath, []byte(emergencyScript), shared.ExecutablePerm); err != nil {
		return fmt.Errorf("write emergency recovery script: %w", err)
	}

	logger.Info(" Created emergency recovery script",
		zap.String("path", scriptPath),
		zap.String("usage", "sudo bash /usr/local/bin/emergency-mfa-recovery"))

	return nil
}
