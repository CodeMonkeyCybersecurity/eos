// TODO: Pattern 1 - This command needs to be registered with UpdateCmd in init() function
// TODO: Pattern 1 - Based on the "secure permissions" example paths, this might belong in a different command structure
package update

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/output"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security/security_permissions"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// permissionsCmd manages security permissions for SSH keys and system files
var permissionsCmd = &cobra.Command{
	Use:   "permissions",
	Short: "Manage security permissions for SSH keys and system files",
	Long: `Manages security permissions for SSH keys, system files, and SSL certificates.
This command helps ensure proper file permissions are set according to security best practices.

Categories:
- ssh: SSH keys and configuration files (~/.ssh directory)
- system: Critical system files (/etc/passwd, /etc/shadow, etc.)
- ssl: SSL certificates and private keys

Operations:
- check: Analyze current permissions without making changes
- fix: Correct permission issues (with optional dry-run mode)`,
	Example: `  # Check SSH permissions
  eos secure permissions check ssh
  
  # Fix SSH permissions
  eos secure permissions fix ssh
  
  # Fix all permissions with dry run
  eos secure permissions fix ssh system --dry-run
  
  # Check with custom SSH directory
  eos secure permissions check ssh --ssh-dir /custom/ssh`,
}

// Flag variables for permissions check command
var (
	permissionsCheckSSHDir     string
	permissionsCheckOutputJSON bool
)

// permissionsCheckCmd checks file permissions without making changes
var permissionsCheckCmd = &cobra.Command{
	Use:   "check [categories...]",
	Short: "Check file permissions without making changes",
	Long: `Analyzes current file permissions and reports issues without making any changes.
		
Available categories: ssh, system, ssl`,
	Example: `  # Check SSH permissions
  eos secure permissions check ssh
  
  # Check all categories
  eos secure permissions check ssh system ssl
  
  # Check with JSON output
  eos secure permissions check ssh --json`,
	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		logger.Info("Checking security permissions",
			zap.Strings("categories", args),
			zap.String("ssh_dir", permissionsCheckSSHDir))

		config := &security_permissions.SecurityConfig{
			SSHDirectory: permissionsCheckSSHDir,
			DryRun:       true, // Check is always dry-run
		}

		result, err := security_permissions.CheckPermissions(rc, config, args)
		if err != nil {
			logger.Error("Permission check failed", zap.Error(err))
			return fmt.Errorf("permission check failed: %v", err)
		}

		if permissionsCheckOutputJSON {
			return output.JSONToStdout(result)
		} else {
			return output.TextToStdout(result, true)
		}
	}),
}

// Flag variables for permissions fix command
var (
	permissionsFixSSHDir        string
	permissionsFixOutputJSON    bool
	permissionsFixDryRun        bool
	permissionsFixCreateBackups bool
)

// permissionsFixCmd fixes file permission issues
var permissionsFixCmd = &cobra.Command{
	Use:   "fix [categories...]",
	Short: "Fix file permission issues",
	Long: `Corrects file permission issues according to security best practices.
		
Available categories: ssh, system, ssl

Creates backups by default before making changes.`,
	Example: `  # Fix SSH permissions
  eos secure permissions fix ssh
  
  # Fix with dry run (preview changes)
  eos secure permissions fix ssh --dry-run
  
  # Fix without creating backups
  eos secure permissions fix ssh --no-backups`,
	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Fixing security permissions",
			zap.Strings("categories", args),
			zap.String("ssh_dir", permissionsFixSSHDir),
			zap.Bool("dry_run", permissionsFixDryRun))

		config := &security_permissions.SecurityConfig{
			SSHDirectory:  permissionsFixSSHDir,
			CreateBackups: permissionsFixCreateBackups,
			DryRun:        permissionsFixDryRun,
		}

		result, err := security_permissions.FixPermissions(rc, config, args)
		if err != nil {
			logger.Error("Permission fix failed", zap.Error(err))
			return fmt.Errorf("permission fix failed: %v", err)
		}

		if permissionsFixOutputJSON {
			return output.JSONToStdout(result)
		} else {
			return output.TextToStdout(result, permissionsFixDryRun)
		}
	}),
}

// All output formatting functions have been moved to pkg/output/

// init registers permissions commands and their flags
func init() {
	// TODO: Pattern 1 - Need to determine correct parent command for registration
	// Based on examples showing "eos secure permissions", this might need a "secure" parent command
	// UpdateCmd.AddCommand(permissionsCmd)

	// Add subcommands to permissions command
	permissionsCmd.AddCommand(permissionsCheckCmd)
	permissionsCmd.AddCommand(permissionsFixCmd)

	// Add flags for permissions check command
	permissionsCheckCmd.Flags().StringVar(&permissionsCheckSSHDir, "ssh-dir", os.ExpandEnv("$HOME/.ssh"), "SSH directory to check")
	permissionsCheckCmd.Flags().BoolVar(&permissionsCheckOutputJSON, "json", false, "Output results in JSON format")

	// Add flags for permissions fix command
	permissionsFixCmd.Flags().StringVar(&permissionsFixSSHDir, "ssh-dir", os.ExpandEnv("$HOME/.ssh"), "SSH directory to fix")
	permissionsFixCmd.Flags().BoolVar(&permissionsFixOutputJSON, "json", false, "Output results in JSON format")
	permissionsFixCmd.Flags().BoolVar(&permissionsFixDryRun, "dry-run", false, "Show what would be changed without making modifications")
	permissionsFixCmd.Flags().BoolVar(&permissionsFixCreateBackups, "backups", true, "Create backup files before modification")
}
