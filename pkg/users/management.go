// pkg/users/management.go
//
// # EOS User Management System
//
// This package provides comprehensive user management capabilities for EOS
// infrastructure. It handles system user creation, SSH key management, sudo
// configuration, and integrates with the HashiCorp stack for modern user
// management patterns.
//
// Architecture Decision:
// Following the EOS  to HashiCorp migration, user management operations
// are handled through administrator escalation patterns. System-level user
// operations require administrator intervention rather than allowing the
// HashiCorp stack to perform privileged operations directly.
//
// Key Features:
// - System user creation with secure defaults
// - SSH key management and authentication setup
// - Sudo configuration with principle of least privilege
// - Integration with Vault for credential storage
// - Administrator escalation for system-level operations
// - Comprehensive audit logging for user operations
//
// User Management Components:
// - User Creation: System user accounts with secure configuration
// - SSH Management: Key generation, distribution, and access control
// - Permission Management: Sudo rules, group membership, access controls
// - Credential Management: Secure storage and rotation via Vault
// - Assessment: User existence verification and validation
// - Operations: CRUD operations for user lifecycle management
//
// Security Features:
// - Secure password generation and storage
// - SSH key-based authentication (password auth disabled by default)
// - Principle of least privilege for sudo access
// - Audit logging for all user operations
// - Integration with security hardening system
// - Vault integration for credential management
//
// Administrator Escalation Pattern:
// Complex user management operations escalate to administrator intervention:
//
//	Error: User management requires administrator intervention
//	Reason: System-level user operations require root privileges
//	Action: Administrator should manually create user with proper security controls
//	Config: User configuration stored in Vault for administrator reference
//
// Usage Examples:
//
//	// Create user with administrator escalation
//	userManager := users.NewHashiCorpUserManager(rc)
//	err := userManager.CreateUser(ctx, users.UserCreationOptions{
//	    Username: "deploy",
//	    SudoAccess: true,
//	    SSHAccess: true,
//	})
//	// This will escalate to administrator with clear instructions
//
//	// Assess user existence
//	exists, err := userManager.UserExists(ctx, "deploy")
//
// Integration Points:
// - Vault: Secure credential storage and SSH key management
// - Security Package: Integration with system hardening
// - Audit System: Comprehensive logging of user operations
// - : System-level user configuration (via administrator)
// - HashiCorp Stack: Application-level user management
//
// Migration Notes:
// This package has been migrated from direct  operations to the
// administrator escalation pattern, maintaining security while providing
// clear guidance for manual user management operations.
package users

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// UserCreationOptions represents options for creating a new user
type UserCreationOptions struct {
	Username   string
	Password   string
	SudoAccess bool
	HomeDir    string
	Shell      string
	SSHAccess  bool
}

// CreateUser creates a new user account with specified options
func CreateUser(rc *eos_io.RuntimeContext, options *UserCreationOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "CreateUser")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting user creation", zap.String("username", options.Username))

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Error("Root privileges required")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("this operation requires root privileges. Try using sudo"))
	}

	// Validate username
	if err := validateUsername(rc, options.Username); err != nil {
		return err
	}

	// Check if user already exists
	if userExists(options.Username) {
		logger.Error("User already exists", zap.String("username", options.Username))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("user '%s' already exists", options.Username))
	}

	// Set default shell if not provided
	if options.Shell == "" {
		options.Shell = "/bin/bash"
	}

	// Create user account
	if err := createUserAccount(rc, options); err != nil {
		return err
	}

	// Set password
	if err := setUserPassword(rc, options.Username, options.Password); err != nil {
		return err
	}

	// Add to sudo group if requested
	if options.SudoAccess {
		if err := addUserToSudoGroup(rc, options.Username); err != nil {
			return err
		}
	}

	// Grant SSH access if requested
	if options.SSHAccess {
		if err := GrantSSHAccess(rc, options.Username); err != nil {
			logger.Warn("Failed to grant SSH access", zap.Error(err))
		}
	}

	logger.Info("User created successfully",
		zap.String("username", options.Username),
		zap.Bool("sudo_access", options.SudoAccess),
		zap.Bool("ssh_access", options.SSHAccess))

	return nil
}

// CreateUserInteractive creates a user with interactive prompts
func CreateUserInteractive(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "CreateUserInteractive")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting interactive user creation")

	// Get username
	username, err := interaction.PromptUser(rc, "Enter username: ")
	if err != nil {
		return fmt.Errorf("failed to get username: %w", err)
	}
	username = strings.TrimSpace(username)

	// Get password with confirmation
	password, err := promptPassword(rc, "Enter password: ")
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}

	confirmPassword, err := promptPassword(rc, "Confirm password: ")
	if err != nil {
		return fmt.Errorf("failed to get password confirmation: %w", err)
	}

	if password != confirmPassword {
		logger.Error("Passwords do not match")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("passwords do not match"))
	}

	// Ask for sudo access
	sudoResponse, err := interaction.PromptUser(rc, "Grant sudo privileges? (y/n): ")
	if err != nil {
		return fmt.Errorf("failed to get sudo preference: %w", err)
	}
	sudoAccess := strings.ToLower(strings.TrimSpace(sudoResponse)) == "y"

	// Ask for SSH access
	sshResponse, err := interaction.PromptUser(rc, "Grant SSH access? (y/n): ")
	if err != nil {
		return fmt.Errorf("failed to get SSH preference: %w", err)
	}
	sshAccess := strings.ToLower(strings.TrimSpace(sshResponse)) == "y"

	// Create user
	options := &UserCreationOptions{
		Username:   username,
		Password:   password,
		SudoAccess: sudoAccess,
		Shell:      "/bin/bash",
		SSHAccess:  sshAccess,
	}

	return CreateUser(rc, options)
}

// ChangeUserPassword changes the password for an existing user
func ChangeUserPassword(rc *eos_io.RuntimeContext, username, newPassword string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ChangeUserPassword")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Changing user password", zap.String("username", username))

	// Check if user exists
	if !userExists(username) {
		logger.Error("User does not exist", zap.String("username", username))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("user '%s' does not exist", username))
	}

	// Set new password
	if err := setUserPassword(rc, username, newPassword); err != nil {
		return err
	}

	logger.Info("Password changed successfully", zap.String("username", username))
	return nil
}

// ChangeUserPasswordInteractive changes password with interactive prompts
func ChangeUserPasswordInteractive(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "ChangeUserPasswordInteractive")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting interactive password change")

	// Get username
	username, err := interaction.PromptUser(rc, "Enter username: ")
	if err != nil {
		return fmt.Errorf("failed to get username: %w", err)
	}
	username = strings.TrimSpace(username)

	// Get new password
	newPassword, err := promptPassword(rc, "Enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to get new password: %w", err)
	}

	return ChangeUserPassword(rc, username, newPassword)
}

// ListUsersWithSSHAccess lists all users who have SSH access
func ListUsersWithSSHAccess(rc *eos_io.RuntimeContext) ([]string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ListUsersWithSSHAccess")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Listing users with SSH access")

	// Get all users with bash shell
	bashUsers, err := getUsersWithBashShell(rc)
	if err != nil {
		return nil, err
	}

	// Check SSH configuration for AllowUsers
	allowedUsers, err := getSSHAllowedUsers(rc)
	if err != nil {
		return nil, err
	}

	// If no AllowUsers directive, all bash users have access
	if len(allowedUsers) == 0 {
		logger.Info("No AllowUsers directive found, all bash users have SSH access")
		return bashUsers, nil
	}

	// Filter bash users by those in AllowUsers
	var usersWithAccess []string
	allowedSet := make(map[string]bool)
	for _, user := range allowedUsers {
		allowedSet[user] = true
	}

	for _, user := range bashUsers {
		if allowedSet[user] {
			usersWithAccess = append(usersWithAccess, user)
		}
	}

	logger.Info("Found users with SSH access",
		zap.Strings("users", usersWithAccess),
		zap.Int("count", len(usersWithAccess)))

	return usersWithAccess, nil
}

// GrantSSHAccess grants SSH access to a user by adding them to AllowUsers
func GrantSSHAccess(rc *eos_io.RuntimeContext, username string) error {
	ctx, span := telemetry.Start(rc.Ctx, "GrantSSHAccess")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Granting SSH access", zap.String("username", username))

	// Check if user exists
	if !userExists(username) {
		logger.Error("User does not exist", zap.String("username", username))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("user '%s' does not exist", username))
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Error("Root privileges required")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("this operation requires root privileges. Try using sudo"))
	}

	// Get current SSH configuration
	allowedUsers, err := getSSHAllowedUsers(rc)
	if err != nil {
		return err
	}

	// Check if user already has access
	for _, user := range allowedUsers {
		if user == username {
			logger.Info("User already has SSH access", zap.String("username", username))
			return nil
		}
	}

	// Add user to AllowUsers
	if err := addUserToSSHConfig(rc, username); err != nil {
		return err
	}

	// Reload SSH daemon
	if err := reloadSSHDaemon(rc); err != nil {
		return err
	}

	logger.Info("SSH access granted successfully", zap.String("username", username))
	return nil
}

// GetUserHostnameStamp generates a user-hostname identifier
func GetUserHostnameStamp() (string, error) {
	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}

	// Create stamp in format: hostname_username
	stamp := fmt.Sprintf("%s_%s", hostname, currentUser.Username)
	return stamp, nil
}

// validateUsername validates that a username meets requirements
func validateUsername(rc *eos_io.RuntimeContext, username string) error {
	ctx, span := telemetry.Start(rc.Ctx, "validateUsername")
	defer span.End()

	logger := otelzap.Ctx(ctx)

	if username == "" {
		logger.Error("Username cannot be empty")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("username cannot be empty"))
	}

	// Check username format (alphanumeric, underscore, hyphen)
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		logger.Error("Invalid username format", zap.String("username", username))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens"))
	}

	// Check length
	if len(username) > 32 {
		logger.Error("Username too long", zap.String("username", username))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("username cannot be longer than 32 characters"))
	}

	logger.Debug("Username validated successfully", zap.String("username", username))
	return nil
}

// userExists checks if a user already exists on the system
func userExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

// createUserAccount creates the user account using useradd
func createUserAccount(rc *eos_io.RuntimeContext, options *UserCreationOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "createUserAccount")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Creating user account", zap.String("username", options.Username))

	// Build useradd command
	args := []string{"useradd", "-m", "-s", options.Shell}
	if options.HomeDir != "" {
		args = append(args, "-d", options.HomeDir)
	}
	args = append(args, options.Username)

	cmd := exec.CommandContext(ctx, "sudo", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to create user account",
			zap.String("username", options.Username),
			zap.ByteString("output", output),
			zap.Error(err))
		return fmt.Errorf("failed to create user account: %w", err)
	}

	logger.Debug("User account created",
		zap.String("username", options.Username),
		zap.ByteString("output", output))

	return nil
}

// setUserPassword sets the password for a user using chpasswd
func setUserPassword(rc *eos_io.RuntimeContext, username, password string) error {
	ctx, span := telemetry.Start(rc.Ctx, "setUserPassword")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Setting user password", zap.String("username", username))

	// Prepare password input for chpasswd
	passwordInput := fmt.Sprintf("%s:%s", username, password)

	cmd := exec.CommandContext(ctx, "sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(passwordInput)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to set user password",
			zap.String("username", username),
			zap.ByteString("output", output),
			zap.Error(err))
		return fmt.Errorf("failed to set password for user '%s': %w", username, err)
	}

	logger.Debug("Password set successfully", zap.String("username", username))
	return nil
}

// addUserToSudoGroup adds a user to the sudo group
func addUserToSudoGroup(rc *eos_io.RuntimeContext, username string) error {
	ctx, span := telemetry.Start(rc.Ctx, "addUserToSudoGroup")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Adding user to sudo group", zap.String("username", username))

	cmd := exec.CommandContext(ctx, "sudo", "usermod", "-a", "-G", "sudo", username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to add user to sudo group",
			zap.String("username", username),
			zap.ByteString("output", output),
			zap.Error(err))
		return fmt.Errorf("failed to add user '%s' to sudo group: %w", username, err)
	}

	logger.Debug("User added to sudo group", zap.String("username", username))
	return nil
}

// promptPassword prompts for a password without echoing to screen
func promptPassword(rc *eos_io.RuntimeContext, prompt string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Prompting for password")

	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after password input

	if err != nil {
		logger.Error("Failed to read password", zap.Error(err))
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(passwordBytes), nil
}

// getUsersWithBashShell gets all users with /bin/bash shell from /etc/passwd
func getUsersWithBashShell(rc *eos_io.RuntimeContext) ([]string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "getUsersWithBashShell")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting users with bash shell")

	file, err := os.Open("/etc/passwd")
	if err != nil {
		logger.Error("Failed to open /etc/passwd", zap.Error(err))
		return nil, fmt.Errorf("failed to open /etc/passwd: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close /etc/passwd", zap.Error(closeErr))
		}
	}()

	var bashUsers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")

		// passwd format: username:password:uid:gid:gecos:home:shell
		if len(fields) >= 7 && fields[6] == "/bin/bash" {
			bashUsers = append(bashUsers, fields[0])
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Error reading /etc/passwd", zap.Error(err))
		return nil, fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	logger.Info("Found users with bash shell",
		zap.Strings("users", bashUsers),
		zap.Int("count", len(bashUsers)))

	return bashUsers, nil
}

// getSSHAllowedUsers gets the list of users from AllowUsers directive in SSH config
func getSSHAllowedUsers(rc *eos_io.RuntimeContext) ([]string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "getSSHAllowedUsers")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting SSH allowed users")

	file, err := os.Open("/etc/ssh/sshd_config")
	if err != nil {
		logger.Error("Failed to open SSH config", zap.Error(err))
		return nil, fmt.Errorf("failed to open SSH config: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close SSH config", zap.Error(closeErr))
		}
	}()

	var allowedUsers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for AllowUsers directive
		if strings.HasPrefix(line, "AllowUsers ") {
			// Extract users from the line
			usersPart := strings.TrimPrefix(line, "AllowUsers ")
			users := strings.Fields(usersPart)
			allowedUsers = append(allowedUsers, users...)
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Error reading SSH config", zap.Error(err))
		return nil, fmt.Errorf("error reading SSH config: %w", err)
	}

	logger.Info("Found SSH allowed users",
		zap.Strings("users", allowedUsers),
		zap.Int("count", len(allowedUsers)))

	return allowedUsers, nil
}

// addUserToSSHConfig adds a user to the AllowUsers directive in SSH config
func addUserToSSHConfig(rc *eos_io.RuntimeContext, username string) error {
	ctx, span := telemetry.Start(rc.Ctx, "users.addUserToSSHConfig")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Adding user to SSH config", zap.String("username", username))

	const sshConfigFile = "/etc/ssh/sshd_config"

	// Read current config
	file, err := os.Open(sshConfigFile)
	if err != nil {
		logger.Error("Failed to open SSH config", zap.Error(err))
		return fmt.Errorf("failed to open SSH config: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close SSH config", zap.Error(closeErr))
		}
	}()

	var lines []string
	allowUsersFound := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check for existing AllowUsers line
		if strings.HasPrefix(strings.TrimSpace(line), "AllowUsers ") {
			// Add user to existing line
			line = line + " " + username
			allowUsersFound = true
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Error reading SSH config", zap.Error(err))
		return fmt.Errorf("error reading SSH config: %w", err)
	}

	// If no AllowUsers directive exists, add one
	if !allowUsersFound {
		lines = append(lines, fmt.Sprintf("AllowUsers %s", username))
	}

	// Write updated config
	outputFile, err := os.Create(sshConfigFile)
	if err != nil {
		logger.Error("Failed to open SSH config for writing", zap.Error(err))
		return fmt.Errorf("failed to open SSH config for writing: %w", err)
	}
	defer func() {
		if closeErr := outputFile.Close(); closeErr != nil {
			logger.Warn("Failed to close SSH config output file", zap.Error(closeErr))
		}
	}()

	writer := bufio.NewWriter(outputFile)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			logger.Error("Failed to write SSH config line", zap.Error(err))
			return fmt.Errorf("failed to write SSH config: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		logger.Error("Failed to flush SSH config changes", zap.Error(err))
		return fmt.Errorf("failed to flush SSH config changes: %w", err)
	}

	logger.Info("User added to SSH config successfully", zap.String("username", username))
	return nil
}

// reloadSSHDaemon reloads the SSH daemon to apply configuration changes
func reloadSSHDaemon(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "users.reloadSSHDaemon")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Reloading SSH daemon")

	// Try multiple reload commands in order of preference
	commands := [][]string{
		{"systemctl", "reload", "sshd"},
		{"systemctl", "reload", "ssh"},
		{"service", "sshd", "reload"},
		{"service", "ssh", "reload"},
	}

	for _, cmdArgs := range commands {
		logger.Debug("Attempting SSH reload command", zap.Strings("command", cmdArgs))

		cmd := exec.CommandContext(ctx, "sudo", cmdArgs...)
		if err := cmd.Run(); err != nil {
			logger.Warn("SSH reload command failed",
				zap.Strings("command", cmdArgs),
				zap.Error(err))
			continue
		}

		logger.Info("SSH daemon reloaded successfully", zap.Strings("command", cmdArgs))
		return nil
	}

	logger.Error("Failed to reload SSH daemon with all attempted methods")
	return eos_err.NewExpectedError(ctx, fmt.Errorf("could not reload SSH daemon automatically. Please reload it manually with 'sudo systemctl reload sshd' or 'sudo service ssh reload'"))
}

func RunUpdateUserPassword(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting user password update")

	// Use interactive mode if no username provided
	if len(args) == 0 {
		return ChangeUserPasswordInteractive(rc)
	}

	username := strings.TrimSpace(args[0])
	if username == "" {
		return ChangeUserPasswordInteractive(rc)
	}

	// Get new password interactively for security
	newPassword, err := interaction.PromptUser(rc, "Enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to get new password: %w", err)
	}

	return ChangeUserPassword(rc, username, newPassword)
}

func runUpdateUserSSHAccess(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting SSH access grant")

	var username string
	if len(args) > 0 {
		username = strings.TrimSpace(args[0])
	}

	// If no username provided, prompt for it
	if username == "" {
		var err error
		username, err = interaction.PromptUser(rc, "Enter username to grant SSH access: ")
		if err != nil {
			return fmt.Errorf("failed to get username: %w", err)
		}
		username = strings.TrimSpace(username)
	}

	if username == "" {
		otelzap.Ctx(rc.Ctx).Error("No username provided")
		return fmt.Errorf("username cannot be empty")
	}

	return GrantSSHAccess(rc, username)
}

// RunUpdateUserSSHAccess handles SSH access grant operations
func RunUpdateUserSSHAccess(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting SSH access grant operation")

	// ASSESS - Determine username
	var username string
	if len(args) > 0 {
		username = args[0]
	} else {
		// Interactive mode - prompt for username
		logger.Info("terminal prompt: Enter username to grant SSH access to")
		var err error
		username, err = interaction.PromptSecret(rc.Ctx, "Enter username: ")
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
	}

	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	logger.Info("Granting SSH access to user", zap.String("username", username))

	// INTERVENE - Grant SSH access using existing function
	return GrantSSHAccess(rc, username)
}
