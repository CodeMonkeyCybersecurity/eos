// Package bionicgpt provides installation logic for BionicGPT
// following the Assess → Intervene → Evaluate pattern.
package bionicgpt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/purge"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func RunDeleteBionicGPT(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting BionicGPT deletion process")

	// ASSESS Phase 1: Check Docker availability (using SDK)
	logger.Info("Checking Docker availability")
	if err := container.CheckIfDockerInstalled(rc); err != nil {
		logger.Error("Docker is not available",
			zap.Error(err),
			zap.String("remediation", "Install Docker or use 'eos create docker'"))

		fmt.Println()
		fmt.Println("✗ Docker is not installed or not available")
		fmt.Println()
		fmt.Println("BionicGPT uses Docker containers. To delete it, Docker must be available.")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  1. Install Docker:    sudo eos create docker")
		fmt.Println("  2. Manual cleanup:    sudo rm -rf /opt/bionicgpt")
		fmt.Println()

		return fmt.Errorf("Docker not available - cannot proceed with deletion")
	}

	// Also check if Docker daemon is running
	if err := container.CheckRunning(rc); err != nil {
		logger.Error("Docker daemon is not running",
			zap.Error(err),
			zap.String("remediation", "Start Docker daemon"))

		fmt.Println()
		fmt.Println("✗ Docker is installed but not running")
		fmt.Println()
		fmt.Println("Remediation:")
		fmt.Println("  • Start Docker: sudo systemctl start docker")
		fmt.Println("  • Check status:  sudo systemctl status docker")
		fmt.Println()

		return fmt.Errorf("Docker daemon not running - cannot proceed with deletion")
	}
	logger.Info("Docker is available and running")

	installDir := DefaultInstallDir
	composeFile := filepath.Join(installDir, "docker-compose.yml")

	// ASSESS Phase 2: Check if BionicGPT is actually installed
	logger.Info("Checking if BionicGPT is installed")
	installationExists := false
	var installedComponents []string
	var missingComponents []string

	// Check for installation directory
	if _, err := os.Stat(installDir); err == nil {
		installationExists = true
		installedComponents = append(installedComponents, fmt.Sprintf("Installation directory (%s)", installDir))
	} else {
		missingComponents = append(missingComponents, "Installation directory")
	}

	// Check for docker-compose.yml
	if _, err := os.Stat(composeFile); err == nil {
		installationExists = true
		installedComponents = append(installedComponents, "Docker Compose file")
	} else {
		missingComponents = append(missingComponents, "Docker Compose file")
	}

	// Check for running or stopped containers using Docker SDK
	foundContainers, foundVolumes, sdkInstallExists, err := AssessInstallation(rc)
	if err != nil {
		logger.Warn("Failed to assess installation via Docker SDK", zap.Error(err))
		// Non-fatal - containers/volumes lists will be empty
	} else if sdkInstallExists {
		installationExists = true
	}

	if len(foundContainers) > 0 {
		installedComponents = append(installedComponents, fmt.Sprintf("%d Docker containers", len(foundContainers)))
	}
	if len(foundVolumes) > 0 {
		installedComponents = append(installedComponents, fmt.Sprintf("%d Docker volumes", len(foundVolumes)))
	}

	// If nothing is installed, inform user
	if !installationExists {
		logger.Info("BionicGPT is not installed")
		fmt.Println()
		fmt.Println("✓ BionicGPT is not installed on this system")
		fmt.Println()
		fmt.Println("Nothing to delete. The following components were not found:")
		for _, component := range missingComponents {
			fmt.Printf("  ⊘ %s\n", component)
		}
		fmt.Println()
		return nil
	}

	// Show what was found
	logger.Info("Found BionicGPT installation",
		zap.Strings("components", installedComponents),
		zap.Strings("containers", foundContainers),
		zap.Strings("volumes", foundVolumes))

	// CRITICAL FIX P0: Store backups OUTSIDE installation directory
	// Old: /opt/bionicgpt/backups/ (gets deleted with installation dir!)
	// New: ~/.eos/backups/bionicgpt-{timestamp}/ (persists after deletion)
	timestamp := fmt.Sprintf("%d", os.Getpid())
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to /tmp if home directory unavailable
		logger.Warn("Could not determine home directory, using /tmp for backups", zap.Error(err))
		homeDir = "/tmp"
	}
	backupDir := filepath.Join(homeDir, ".eos", "backups", fmt.Sprintf("bionicgpt-%s", timestamp))

	// Confirmation prompt unless force is specified
	if !BionicgptDeleteForce {
		logger.Info("terminal prompt: Confirm deletion")
		fmt.Println()
		fmt.Println("  WARNING: This will permanently delete BionicGPT")
		fmt.Println()
		fmt.Println("The following will be removed:")
		fmt.Println("  • All BionicGPT containers")
		fmt.Println("  • PostgreSQL database with all user data")
		fmt.Println("  • Uploaded documents and embeddings")
		fmt.Println("  • Chat history and team settings")
		fmt.Println("  • Docker volumes:", VolumePostgresData, VolumeDocuments)
		fmt.Println("  • Docker images (BionicGPT app, PostgreSQL, embeddings API, etc.)")
		fmt.Println("  • Installation directory /opt/bionicgpt")
		fmt.Println()

		if !BionicgptDeleteSkipBackup {
			fmt.Println("A backup will be created in:", backupDir)
			fmt.Println()
		} else {
			fmt.Println("  NO BACKUP will be created (--skip-backup specified)")
			fmt.Println()
		}

		confirmed := interaction.PromptYesNo(rc.Ctx, "Type 'yes' (or 'y') to confirm deletion", false)
		if !confirmed {
			logger.Info("Deletion cancelled by user")
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	logger.Info("Deletion confirmed, proceeding")

	// Step 1: Stop containers using docker compose
	logger.Info("Stopping BionicGPT containers")
	if _, err := os.Stat(composeFile); err == nil {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "-f", composeFile, "down"},
			Dir:     installDir,
			Capture: true,
		})
		if err != nil {
			logger.Warn("Failed to stop containers via docker compose",
				zap.Error(err),
				zap.String("output", output))
			if !BionicgptDeleteForce {
				return fmt.Errorf("failed to stop containers: %s", output)
			}
		} else {
			logger.Info("Containers stopped successfully")
		}
	} else {
		logger.Warn("docker-compose.yml not found, skipping compose down",
			zap.String("file", composeFile))
	}

	// Step 2: Backup volumes if not skipped
	var backupPaths []string
	if !BionicgptDeleteSkipBackup {
		logger.Info("Creating backup of BionicGPT data volumes")

		// Create backup directory
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			logger.Error("Failed to create backup directory",
				zap.String("dir", backupDir),
				zap.Error(err))
			if !BionicgptDeleteForce {
				return fmt.Errorf("failed to create backup directory: %w", err)
			}
		}

		// Backup each volume
		volumes := []string{VolumePostgresData, VolumeDocuments}
		for _, volumeName := range volumes {
			logger.Info("Backing up volume", zap.String("volume", volumeName))

			// Check if volume exists
			checkOutput, err := execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args:    []string{"volume", "inspect", volumeName},
				Capture: true,
			})

			if err != nil {
				logger.Warn("Volume does not exist, skipping backup",
					zap.String("volume", volumeName),
					zap.String("output", checkOutput))
				continue
			}

			// Generate backup filename
			timestamp := fmt.Sprintf("%d", os.Getpid())
			backupName := fmt.Sprintf("%s-final-backup-%s.tar.gz", volumeName, timestamp)
			backupPath := filepath.Join(backupDir, backupName)

			logger.Debug("Creating volume backup",
				zap.String("volume", volumeName),
				zap.String("backup_path", backupPath))

			output, err := execute.Run(rc.Ctx, execute.Options{
				Command: "docker",
				Args: []string{
					"run", "--rm",
					"-v", fmt.Sprintf("%s:/data:ro", volumeName),
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
					zap.String("volume", volumeName),
					zap.Error(err),
					zap.String("output", output))
				if !BionicgptDeleteForce {
					return fmt.Errorf("backup of %s failed: %s", volumeName, output)
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
					backupPaths = append(backupPaths, backupPath)
				}
			}
		}
	} else {
		logger.Info("Backup skipped by user (--skip-backup)")
	}

	// Step 3: Remove containers individually
	logger.Info("Removing BionicGPT containers")
	containers := []string{
		ContainerApp,
		ContainerRAGEngine,
		ContainerMigrations,
		ContainerPostgres,
		ContainerEmbeddings,
		ContainerChunking,
	}

	for _, containerName := range containers {
		if err := container.RemoveContainer(rc, containerName); err != nil {
			logger.Warn("Failed to remove container",
				zap.String("container", containerName),
				zap.Error(err))
			if !BionicgptDeleteForce {
				return fmt.Errorf("failed to remove container %s: %w", containerName, err)
			}
		} else {
			logger.Debug("Container removed", zap.String("container", containerName))
		}
	}

	// Step 4: Remove Docker volumes
	logger.Info("Removing Docker volumes")
	volumes := []string{
		VolumePostgresData,
		VolumeDocuments,
	}

	if err := container.RemoveVolumes(rc, volumes); err != nil {
		logger.Warn("Failed to remove volumes", zap.Error(err))
		if !BionicgptDeleteForce {
			return fmt.Errorf("failed to remove volumes: %w", err)
		}
	} else {
		logger.Info("Volumes removed successfully")
	}

	// Step 5: Remove Docker images
	logger.Info("Removing Docker images")
	images := []string{
		fmt.Sprintf("%s:%s", ImageBionicGPT, DefaultBionicGPTVersion),
		fmt.Sprintf("%s:%s", ImageMigrations, DefaultBionicGPTVersion),
		fmt.Sprintf("%s:%s", ImageRAGEngine, DefaultBionicGPTVersion),
		ImageEmbeddings,
		fmt.Sprintf("%s:%s", ImageChunking, VersionChunking),
		ImagePostgreSQL,
	}

	for _, image := range images {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"rmi", image},
			Capture: true,
		})
		if err != nil {
			logger.Debug("Image already removed or doesn't exist",
				zap.String("image", image),
				zap.String("output", output))
		} else {
			logger.Debug("Image removed", zap.String("image", image))
		}
	}

	// Step 6: Remove installation directory
	logger.Info("Removing installation directory", zap.String("dir", installDir))
	if _, err := os.Stat(installDir); err == nil {
		if err := os.RemoveAll(installDir); err != nil {
			logger.Error("Failed to remove installation directory",
				zap.String("dir", installDir),
				zap.Error(err))
			if !BionicgptDeleteForce {
				return fmt.Errorf("failed to remove installation directory: %w", err)
			}
		} else {
			logger.Info("Installation directory removed")
		}
	} else {
		logger.Debug("Installation directory already removed")
	}

	// Step 7: Purge secrets and configs if --purge flag is set
	if BionicgptDeletePurge {
		logger.Info("Purging BionicGPT secrets and configs (--purge flag enabled)")
		if err := purgeServiceData(rc); err != nil {
			logger.Warn("Failed to purge service data", zap.Error(err))
			if !BionicgptDeleteForce {
				return fmt.Errorf("failed to purge service data: %w", err)
			}
			logger.Warn("Continuing despite purge failure (--force)")
		}
	}

	// Summary
	logger.Info("BionicGPT deletion completed successfully")
	fmt.Println()
	fmt.Println("✓ BionicGPT has been completely removed")

	if len(backupPaths) > 0 {
		fmt.Println()
		fmt.Println("✓ Backups created successfully:")
		for _, path := range backupPaths {
			info, err := os.Stat(path)
			if err == nil {
				fmt.Printf("  • %s (%.2f MB)\n", path, float64(info.Size())/(1024*1024))
			} else {
				fmt.Printf("  • %s\n", path)
			}
		}
		fmt.Println()
		fmt.Printf("Backup location: %s\n", backupDir)
		fmt.Println("These backups are safe and will NOT be deleted.")
	}
	fmt.Println()

	return nil
}

var (
	BionicgptDeleteSkipBackup bool
	BionicgptDeleteForce      bool
	BionicgptDeletePurge      bool
)

// purgeServiceData removes BionicGPT secrets from Vault and configs from Consul KV
func purgeServiceData(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Purging BionicGPT service data from Vault and Consul")

	// Use purge package to clean up secrets and configs
	if err := purge.PurgeService(rc, "bionicgpt"); err != nil {
		logger.Error("Failed to purge service data", zap.Error(err))
		return fmt.Errorf("failed to purge bionicgpt service data: %w", err)
	}

	logger.Info("Service data purged successfully")
	fmt.Println("✓ BionicGPT secrets and configs purged from Vault and Consul")

	return nil
}
