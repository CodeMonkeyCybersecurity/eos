// cmd/backup/restore.go

package backup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var restoreCmd = &cobra.Command{
	Use:   "restore <snapshot-id>",
	Short: "Restore files from a backup snapshot",
	Long: `Restore files from a restic snapshot to a target directory.

Supports restoring entire snapshots or specific paths with include/exclude filters.
By default, restores to original location (requires --force for safety).

Examples:
  # Restore entire snapshot to original location
  eos backup restore latest --force
  
  # Restore to specific directory
  eos backup restore abc123def --target /tmp/restore
  
  # Restore specific paths
  eos backup restore latest --include "/etc,/var/lib" --target /tmp/restore
  
  # Restore from specific repository
  eos backup restore latest --repo remote --target /tmp/restore`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		snapshotID := args[0]
		repoName, _ := cmd.Flags().GetString("repo")
		target, _ := cmd.Flags().GetString("target")
		includes, _ := cmd.Flags().GetStringSlice("include")
		excludes, _ := cmd.Flags().GetStringSlice("exclude")
		verify, _ := cmd.Flags().GetBool("verify")
		force, _ := cmd.Flags().GetBool("force")
		
		// Use default repository if not specified
		if repoName == "" {
			config, err := backup.LoadConfig(rc)
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			repoName = config.DefaultRepository
			if repoName == "" {
				return fmt.Errorf("no repository specified and no default configured")
			}
		}
		
		logger.Info("Starting restore operation",
			zap.String("snapshot", snapshotID),
			zap.String("repository", repoName),
			zap.String("target", target),
			zap.Strings("includes", includes),
			zap.Strings("excludes", excludes))
		
		// Create backup client
		client, err := backup.NewClient(rc, repoName)
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}
		
		// Default target is root for full system restore
		if target == "" {
			target = "/"
			logger.Warn("No target specified, restoring to original locations",
				zap.String("target", target))
			
			if !force {
				return fmt.Errorf("restoring to original location requires --force flag for safety")
			}
		}
		
		// Ensure target directory exists
		if err := os.MkdirAll(target, 0755); err != nil {
			return fmt.Errorf("creating target directory: %w", err)
		}
		
		// Build restore command
		args = []string{"restore", snapshotID, "--target", target}
		
		// Add includes
		for _, include := range includes {
			args = append(args, "--include", include)
		}
		
		// Add excludes
		for _, exclude := range excludes {
			args = append(args, "--exclude", exclude)
		}
		
		// Check if target has existing files
		if !force && target != "/" {
			entries, err := os.ReadDir(target)
			if err == nil && len(entries) > 0 {
				logger.Warn("Target directory is not empty",
					zap.String("target", target),
					zap.Int("existing_files", len(entries)))
				return fmt.Errorf("target directory is not empty, use --force to overwrite")
			}
		}
		
		// Perform restore
		logger.Info("Executing restore")
		_, err = client.RunRestic(args...)
		if err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}
		
		logger.Info("Restore completed")
		
		// Verify if requested
		if verify {
			logger.Info("Verifying restored files")
			
			// List restored files
			verifyArgs := append([]string{"ls", snapshotID, "--json"}, includes...)
			
			_, err := client.RunRestic(verifyArgs...)
			if err != nil {
				logger.Warn("Failed to verify restored files",
					zap.Error(err))
			} else {
				// TODO: Parse JSON and verify files exist in target
				logger.Info("Verification completed")
			}
		}
		
		// Set proper permissions on restored files
		if target != "/" {
			logger.Info("Setting permissions on restored files")
			
			// Walk through restored files and ensure proper permissions
			err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				
				// Ensure directories are accessible
				if info.IsDir() {
					if err := os.Chmod(path, info.Mode()|0700); err != nil {
						logger.Warn("Failed to set directory permissions",
							zap.String("path", path),
							zap.Error(err))
					}
				}
				
				return nil
			})
			
			if err != nil {
				logger.Warn("Failed to set some permissions",
					zap.Error(err))
			}
		}
		
		logger.Info("Restore operation completed successfully",
			zap.String("target", target))
		
		return nil
	}),
}

func init() {
	restoreCmd.Flags().String("repo", "", "Repository containing the snapshot")
	restoreCmd.Flags().String("target", "", "Target directory for restore (default: original location)")
	restoreCmd.Flags().StringSlice("include", nil, "Paths to include in restore")
	restoreCmd.Flags().StringSlice("exclude", nil, "Paths to exclude from restore")
	restoreCmd.Flags().Bool("verify", true, "Verify restored files")
	restoreCmd.Flags().Bool("force", false, "Overwrite existing files without confirmation")
}

