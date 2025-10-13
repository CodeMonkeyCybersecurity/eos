// cmd/delete/openwebui.go
package delete

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	openwebuiDeleteSkipBackup bool
	openwebuiDeleteForce      bool
)

var deleteOpenWebUICmd = &cobra.Command{
	Use:   "openwebui",
	Short: "Delete Open WebUI installation and optionally backup data",
	Long: `Safely delete Open WebUI installation with optional data backup.

This command will:
1. Stop the Open WebUI container
2. Optionally backup the data volume to /opt/openwebui/backups/
3. Remove the Docker container
4. Remove the Docker volume (contains all user data)
5. Remove the Docker image
6. Remove installation directory /opt/openwebui

WARNING: This will delete ALL Open WebUI data including:
- User accounts and settings
- Chat history
- Uploaded files
- Vector database

Examples:
  # Delete with backup (recommended)
  sudo eos delete openwebui

  # Delete without backup (faster, no recovery possible)
  sudo eos delete openwebui --skip-backup

  # Force delete even if already partially removed
  sudo eos delete openwebui --force

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(runDeleteOpenWebUI),
}

func init() {
	deleteOpenWebUICmd.Flags().BoolVar(&openwebuiDeleteSkipBackup, "skip-backup", false,
		"Skip backup before deletion (not recommended)")
	deleteOpenWebUICmd.Flags().BoolVar(&openwebuiDeleteForce, "force", false,
		"Force deletion even if components already removed")

	DeleteCmd.AddCommand(deleteOpenWebUICmd)
}

func runDeleteOpenWebUI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Open WebUI deletion process")

	installDir := "/opt/openwebui"
	composeFile := filepath.Join(installDir, "docker-compose.yml")
	backupDir := filepath.Join(installDir, "backups")

	// Confirmation prompt unless force is specified
	if !openwebuiDeleteForce {
		logger.Info("terminal prompt: Confirm deletion")
		fmt.Println()
		fmt.Println("⚠️  WARNING: This will permanently delete Open WebUI")
		fmt.Println()
		fmt.Println("The following will be removed:")
		fmt.Println("  • Open WebUI container")
		fmt.Println("  • Docker volume 'open-webui-data' (contains all user data)")
		fmt.Println("  • Docker image")
		fmt.Println("  • Installation directory /opt/openwebui")
		fmt.Println()

		if !openwebuiDeleteSkipBackup {
			fmt.Println("A backup will be created in:", backupDir)
			fmt.Println()
		} else {
			fmt.Println("⚠️  NO BACKUP will be created (--skip-backup specified)")
			fmt.Println()
		}

		confirmation, err := eos_io.PromptInput(rc, "Type 'yes' to confirm deletion: ", "delete_confirmation")
		if err != nil {
			logger.Error("Failed to read confirmation", zap.Error(err))
			return fmt.Errorf("confirmation failed: %w", err)
		}

		if confirmation != "yes" {
			logger.Info("Deletion cancelled by user")
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	logger.Info("Deletion confirmed, proceeding")

	// Step 1: Stop container using docker compose
	logger.Info("Stopping Open WebUI container")
	if _, err := os.Stat(composeFile); err == nil {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "-f", composeFile, "down"},
			Dir:     installDir,
			Capture: true,
		})
		if err != nil {
			logger.Warn("Failed to stop container via docker compose",
				zap.Error(err),
				zap.String("output", output))
			if !openwebuiDeleteForce {
				return fmt.Errorf("failed to stop container: %s", output)
			}
		} else {
			logger.Info("Container stopped successfully")
		}
	} else {
		logger.Warn("docker-compose.yml not found, skipping compose down",
			zap.String("file", composeFile))
	}

	// Step 2: Backup volume if not skipped
	var backupPath string
	if !openwebuiDeleteSkipBackup {
		logger.Info("Creating backup of open-webui-data volume")

		// Check if volume exists
		checkOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"volume", "inspect", "open-webui-data"},
			Capture: true,
		})

		if err != nil {
			logger.Warn("Volume does not exist, skipping backup",
				zap.String("volume", "open-webui-data"),
				zap.String("output", checkOutput))
		} else {
			// Create backup directory
			if err := os.MkdirAll(backupDir, 0755); err != nil {
				logger.Error("Failed to create backup directory",
					zap.String("dir", backupDir),
					zap.Error(err))
				return fmt.Errorf("failed to create backup directory: %w", err)
			}

			// Generate backup filename
			timestamp := fmt.Sprintf("%d", os.Getpid()) // Use PID for uniqueness in deletion context
			backupName := fmt.Sprintf("openwebui-final-backup-%s.tar.gz", timestamp)
			backupPath = filepath.Join(backupDir, backupName)

			logger.Debug("Creating volume backup",
				zap.String("volume", "open-webui-data"),
				zap.String("backup_path", backupPath))

			output, err := execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args: []string{
					"run", "--rm",
					"-v", "open-webui-data:/data:ro",
					"-v", fmt.Sprintf("%s:/backup", backupDir),
					"alpine",
					"tar", "czf", fmt.Sprintf("/backup/%s", backupName),
					"-C", "/data", ".",
				},
				Capture: true,
				Timeout: 5 * 60 * 1000, // 5 minutes
			})

			if err != nil {
				logger.Error("Backup failed",
					zap.Error(err),
					zap.String("output", output))
				if !openwebuiDeleteForce {
					return fmt.Errorf("backup failed: %s", output)
				}
				logger.Warn("Continuing deletion despite backup failure (--force)")
			} else {
				info, err := os.Stat(backupPath)
				if err != nil {
					logger.Warn("Backup file not found after creation",
						zap.String("path", backupPath))
				} else {
					logger.Info("Backup created successfully",
						zap.String("path", backupPath),
						zap.Int64("size_bytes", info.Size()))
					fmt.Printf("✓ Backup created: %s (%.2f MB)\n",
						backupPath, float64(info.Size())/(1024*1024))
				}
			}
		}
	} else {
		logger.Info("Backup skipped by user (--skip-backup)")
	}

	// Step 3: Remove container (in case it wasn't removed by compose down)
	logger.Info("Removing Open WebUI container")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"rm", "-f", "open-webui"},
		Capture: true,
	})
	if err != nil {
		logger.Debug("Container already removed or doesn't exist",
			zap.String("output", output))
	} else {
		logger.Info("Container removed")
	}

	// Step 4: Remove Docker volume
	logger.Info("Removing Docker volume", zap.String("volume", "open-webui-data"))
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"volume", "rm", "open-webui-data"},
		Capture: true,
	})
	if err != nil {
		logger.Debug("Volume already removed or doesn't exist",
			zap.String("output", output))
	} else {
		logger.Info("Volume removed successfully")
	}

	// Step 5: Remove Docker image
	logger.Info("Removing Docker image")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"rmi", "ghcr.io/open-webui/open-webui"},
		Capture: true,
	})
	if err != nil {
		logger.Debug("Image already removed or doesn't exist",
			zap.String("output", output))
	} else {
		logger.Info("Image removed")
	}

	// Step 6: Remove installation directory
	logger.Info("Removing installation directory", zap.String("dir", installDir))
	if _, err := os.Stat(installDir); err == nil {
		if err := os.RemoveAll(installDir); err != nil {
			logger.Error("Failed to remove installation directory",
				zap.String("dir", installDir),
				zap.Error(err))
			if !openwebuiDeleteForce {
				return fmt.Errorf("failed to remove installation directory: %w", err)
			}
		} else {
			logger.Info("Installation directory removed")
		}
	} else {
		logger.Debug("Installation directory already removed")
	}

	// Summary
	logger.Info("Open WebUI deletion completed successfully")
	fmt.Println()
	fmt.Println("✓ Open WebUI has been completely removed")
	if backupPath != "" {
		fmt.Printf("✓ Backup saved to: %s\n", backupPath)
		fmt.Println()
		fmt.Println("To restore from this backup:")
		fmt.Printf("  sudo eos update openwebui-restore --backup-file %s\n", backupPath)
	}
	fmt.Println()

	return nil
}
