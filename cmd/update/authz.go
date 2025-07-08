package update

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security_permissions"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewPermissionsCmd creates the permissions command
func NewPermissionsCmd() *cobra.Command {
	cmd := &cobra.Command{
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

	cmd.AddCommand(NewPermissionsCheckCmd())
	cmd.AddCommand(NewPermissionsFixCmd())
	return cmd
}

// NewPermissionsCheckCmd creates the check subcommand
func NewPermissionsCheckCmd() *cobra.Command {
	var (
		sshDir     string
		outputJSON bool
	)

	cmd := &cobra.Command{
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

			logger.Info("Checking security permissions",
				zap.Strings("categories", args),
				zap.String("ssh_dir", sshDir))

			config := &security_permissions.SecurityConfig{
				SSHDirectory: sshDir,
				DryRun:       true, // Check is always dry-run
			}

			manager := security_permissions.NewPermissionManager(config)
			result, err := manager.CheckPermissions(args)
			if err != nil {
				logger.Error("Permission check failed", zap.Error(err))
				return fmt.Errorf("permission check failed: %v", err)
			}

			if outputJSON {
				return outputJSONResult(result)
			} else {
				return outputTextResult(result, true)
			}
		}),
	}

	cmd.Flags().StringVar(&sshDir, "ssh-dir", os.ExpandEnv("$HOME/.ssh"), "SSH directory to check")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output results in JSON format")

	return cmd
}

// NewPermissionsFixCmd creates the fix subcommand
func NewPermissionsFixCmd() *cobra.Command {
	var (
		sshDir        string
		outputJSON    bool
		dryRun        bool
		createBackups bool
	)

	cmd := &cobra.Command{
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
				zap.String("ssh_dir", sshDir),
				zap.Bool("dry_run", dryRun))

			config := &security_permissions.SecurityConfig{
				SSHDirectory:  sshDir,
				CreateBackups: createBackups,
				DryRun:        dryRun,
			}

			manager := security_permissions.NewPermissionManager(config)
			result, err := manager.FixPermissions(args)
			if err != nil {
				logger.Error("Permission fix failed", zap.Error(err))
				return fmt.Errorf("permission fix failed: %v", err)
			}

			if outputJSON {
				return outputJSONResult(result)
			} else {
				return outputTextResult(result, dryRun)
			}
		}),
	}

	cmd.Flags().StringVar(&sshDir, "ssh-dir", os.ExpandEnv("$HOME/.ssh"), "SSH directory to fix")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without making modifications")
	cmd.Flags().BoolVar(&createBackups, "backups", true, "Create backup files before modification")

	return cmd
}

// outputJSONResult outputs results in JSON format
func outputJSONResult(result *security_permissions.PermissionFixResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputTextResult outputs results in human-readable format
func outputTextResult(result *security_permissions.PermissionFixResult, dryRun bool) error {
	if dryRun {
		fmt.Println("🔒 Security Permissions Check (DRY RUN)")
	} else {
		fmt.Println("🔒 Security Permissions Fix")
	}
	fmt.Println(strings.Repeat("=", 50))

	for category, scanResult := range result.Results {
		fmt.Printf("\n %s (%d files checked)\n", strings.ToUpper(category), scanResult.TotalChecks)

		for _, check := range scanResult.Checks {
			if check.Error != "" {
				fmt.Printf("   ❌ %s: %s\n", check.Rule.Description, check.Error)
			} else if check.NeedsChange {
				if dryRun {
					fmt.Printf("    %s: %o → %o (would fix)\n",
						check.Rule.Description, check.CurrentMode, check.ExpectedMode)
				} else {
					fmt.Printf("    %s: %o → %o (fixed)\n",
						check.Rule.Description, check.CurrentMode, check.ExpectedMode)
				}
			} else {
				fmt.Printf("    %s: %o (correct)\n",
					check.Rule.Description, check.CurrentMode)
			}
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf(" Summary: %d files processed, %d fixed, %d skipped\n",
		result.Summary.TotalFiles, result.Summary.FilesFixed, result.Summary.FilesSkipped)

	if len(result.Summary.Errors) > 0 {
		fmt.Printf("❌ Errors: %d\n", len(result.Summary.Errors))
		for _, err := range result.Summary.Errors {
			fmt.Printf("   • %s\n", err)
		}
	}

	if result.Summary.Success {
		if dryRun && result.Summary.FilesFixed > 0 {
			fmt.Println(" Run without --dry-run to apply changes")
		} else if !dryRun {
			fmt.Println(" Permission fixes completed successfully")
		} else {
			fmt.Println(" All permissions are correctly configured")
		}
	} else {
		fmt.Println("❌ Permission operation completed with errors")
		os.Exit(1)
	}

	fmt.Println(strings.Repeat("=", 50))
	return nil
}

// Helper function for legacy outputJSON calls
func outputJSON(result *security_permissions.PermissionFixResult) error {
	return outputJSONResult(result)
}

// Helper function for legacy outputText calls
func outputText(result *security_permissions.PermissionFixResult, isCheck bool) error {
	return outputTextResult(result, isCheck)
}
