// Package bionicgpt provides installation logic for BionicGPT
// following the Assess → Intervene → Evaluate pattern.
package bionicgpt

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	// ASSESS Phase 1: Check Docker availability with informed consent
	// P0: Use human-centric dependency pattern (not hard error)
	logger.Info("Checking Docker availability")

	// First check if Docker is installed
	dockerErr := container.CheckIfDockerInstalled(rc)
	if dockerErr != nil {
		logger.Warn("Docker is not available",
			zap.Error(dockerErr),
			zap.String("note", "Docker is needed for safe container removal and volume backup"))

		logger.Info("")
		logger.Info("════════════════════════════════════════════════════════════════")
		logger.Info("Docker Not Available")
		logger.Info("════════════════════════════════════════════════════════════════")
		logger.Info("")
		logger.Info("BionicGPT uses Docker containers. For safe deletion, Docker is needed to:")
		logger.Info("  • Stop running containers gracefully")
		logger.Info("  • Create backups of Docker volumes")
		logger.Info("  • Remove containers and images cleanly")
		logger.Info("")
		logger.Info("Options:")
		logger.Info("  1. Install Docker and proceed with safe deletion")
		logger.Info("  2. Manual cleanup (no backup, may leave orphaned resources)")
		logger.Info("")

		// Offer to install Docker (informed consent)
		installDocker := interaction.PromptYesNo(rc.Ctx, "Install Docker to proceed with safe deletion", false)

		if installDocker {
			logger.Info("User chose to install Docker")
			if err := container.EnsureDockerInstalled(rc); err != nil {
				logger.Error("Docker installation failed", zap.Error(err))
				// Offer manual cleanup fallback
				logger.Info("")
				logger.Warn("Docker installation failed. You can still do manual cleanup.")
				manualCleanup := interaction.PromptYesNo(rc.Ctx, "Proceed with manual cleanup (no backup)", false)
				if !manualCleanup {
					return fmt.Errorf("deletion cancelled - Docker required for safe deletion")
				}
				return performManualCleanup(rc, DefaultInstallDir)
			}
		} else {
			logger.Info("User declined Docker installation")
			logger.Info("")
			logger.Info("Manual cleanup option:")
			logger.Info("  • Removes installation directory: /opt/bionicgpt")
			logger.Info("  • NO BACKUP will be created")
			logger.Info("  • Docker volumes/containers will NOT be removed")
			logger.Info("  • You can clean up Docker resources later if Docker is installed")
			logger.Info("")

			manualCleanup := interaction.PromptYesNo(rc.Ctx, "Proceed with manual cleanup (no backup)", false)
			if !manualCleanup {
				logger.Info("Deletion cancelled")
				return nil
			}

			return performManualCleanup(rc, DefaultInstallDir)
		}
	}

	// Docker is installed, check if it's running
	if err := container.CheckRunning(rc); err != nil {
		logger.Warn("Docker is installed but not running",
			zap.Error(err))

		logger.Info("")
		logger.Info("Docker daemon is not running. To proceed with safe deletion:")
		logger.Info("  • Start Docker: sudo systemctl start docker")
		logger.Info("  • Check status:  sudo systemctl status docker")
		logger.Info("")

		// Offer to start Docker
		startDocker := interaction.PromptYesNo(rc.Ctx, "Attempt to start Docker daemon", true)
		if startDocker {
			logger.Info("Attempting to start Docker daemon...")
			_, startErr := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"start", "docker"},
			})

			if startErr != nil {
				logger.Error("Failed to start Docker daemon", zap.Error(startErr))
				logger.Info("")
				logger.Info("Manual cleanup option available (no backup)")
				manualCleanup := interaction.PromptYesNo(rc.Ctx, "Proceed with manual cleanup", false)
				if !manualCleanup {
					return fmt.Errorf("deletion cancelled - Docker daemon not running")
				}
				return performManualCleanup(rc, DefaultInstallDir)
			}

			// Verify Docker started
			if err := container.CheckRunning(rc); err != nil {
				logger.Error("Docker daemon failed to start", zap.Error(err))
				return fmt.Errorf("Docker daemon not running - cannot proceed with safe deletion")
			}

			logger.Info("✓ Docker daemon started successfully")
		} else {
			logger.Info("User declined to start Docker")
			manualCleanup := interaction.PromptYesNo(rc.Ctx, "Proceed with manual cleanup (no backup)", false)
			if !manualCleanup {
				return fmt.Errorf("deletion cancelled - Docker daemon required")
			}
			return performManualCleanup(rc, DefaultInstallDir)
		}
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
		if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
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
				// P1 FIX: Validate backup integrity before proceeding
				logger.Info("Validating backup integrity...", zap.String("volume", volumeName))

				info, err := os.Stat(backupPath)
				if err != nil {
					logger.Error("Backup file not found after creation",
						zap.String("path", backupPath),
						zap.Error(err))
					if !BionicgptDeleteForce {
						return fmt.Errorf("backup validation failed: file not found at %s", backupPath)
					}
					logger.Warn("Continuing despite missing backup file (--force)")
					continue
				}

				// Check 1: Non-zero size
				if info.Size() == 0 {
					logger.Error("Backup file is empty (0 bytes)",
						zap.String("path", backupPath))
					if !BionicgptDeleteForce {
						return fmt.Errorf("backup validation failed: empty file at %s", backupPath)
					}
					logger.Warn("Continuing despite empty backup file (--force)")
					continue
				}

				// Check 2: Can read tar header
				logger.Debug("Verifying tar archive integrity")
				validateOutput, validateErr := execute.Run(rc.Ctx, execute.Options{
					Command: "tar",
					Args:    []string{"-tzf", backupPath},
					Capture: true,
					Timeout: 30 * 1000, // 30 seconds
				})

				if validateErr != nil {
					logger.Error("Backup validation failed: cannot read tar archive",
						zap.String("path", backupPath),
						zap.Error(validateErr),
						zap.String("output", validateOutput))
					if !BionicgptDeleteForce {
						return fmt.Errorf("backup validation failed: corrupt tar file at %s: %w", backupPath, validateErr)
					}
					logger.Warn("Continuing despite corrupt backup (--force)")
					continue
				}

				// Check 3: Contains files
				fileCount := strings.Count(validateOutput, "\n")
				if fileCount == 0 {
					logger.Warn("Backup appears empty (no files listed)",
						zap.String("path", backupPath))
					if !BionicgptDeleteForce {
						return fmt.Errorf("backup validation failed: no files in archive at %s", backupPath)
					}
					logger.Warn("Continuing despite empty archive (--force)")
					continue
				}

				sizeMB := float64(info.Size()) / (1024 * 1024)
				logger.Info("✓ Backup validated successfully",
					zap.String("path", backupPath),
					zap.Int64("size_bytes", info.Size()),
					zap.Float64("size_mb", sizeMB),
					zap.Int("file_count", fileCount))

				backupPaths = append(backupPaths, backupPath)
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
	// P1 FIX: Add confirmation for destructive --purge operation
	if BionicgptDeletePurge {
		logger.Info("")
		logger.Info("════════════════════════════════════════════════════════════════")
		logger.Warn("⚠️  DESTRUCTIVE OPERATION: Secret Purge")
		logger.Info("════════════════════════════════════════════════════════════════")
		logger.Info("")
		logger.Info("The --purge flag will PERMANENTLY delete:")
		logger.Info("  • Vault secrets: secret/bionicgpt/*")
		logger.Info("    - postgres_password")
		logger.Info("    - jwt_secret")
		logger.Info("    - litellm_master_key")
		logger.Info("    - azure_api_key (if configured)")
		logger.Info("  • Consul configs: service/bionicgpt/config/*")
		logger.Info("")
		logger.Warn("⚠️  This is IRREVERSIBLE - secrets cannot be recovered!")
		logger.Info("")

		if len(backupPaths) > 0 {
			logger.Info("Backup location:", zap.String("backup_dir", backupDir))
			logger.Warn("Note: Backups do NOT include Vault secrets or Consul configs")
		} else {
			logger.Warn("No backup was created (--skip-backup or backup failed)")
		}

		logger.Info("")

		// Require explicit confirmation unless --force is set
		if !BionicgptDeleteForce {
			confirmed := interaction.PromptYesNo(rc.Ctx,
				"Type 'yes' to confirm PERMANENT deletion of secrets", false)

			if !confirmed {
				logger.Info("Secret purge cancelled by user")
				logger.Info("")
				logger.Info("Secrets remain in Vault and Consul:")
				logger.Info("  • Vault: vault kv list secret/bionicgpt")
				logger.Info("  • Consul: consul kv get -recurse service/bionicgpt/config/")
				logger.Info("")
				logger.Info("To purge secrets later:")
				logger.Info("  eos delete bionicgpt --purge (BionicGPT must already be removed)")
				logger.Info("  OR manually: vault kv metadata delete -mount=secret bionicgpt/")
				logger.Info("")
				// Don't return error - deletion succeeded, just skip purge
				return nil
			}

			logger.Info("User confirmed secret purge - proceeding")
		} else {
			logger.Warn("--force flag set, skipping purge confirmation")
		}

		logger.Info("")
		logger.Info("Purging BionicGPT secrets and configs...")

		if err := purgeServiceData(rc); err != nil {
			logger.Error("Failed to purge service data", zap.Error(err))
			if !BionicgptDeleteForce {
				return fmt.Errorf("failed to purge service data: %w", err)
			}
			logger.Warn("Continuing despite purge failure (--force)")
		}
	}

	// Summary - P0 FIX: Use structured logging instead of fmt.Println
	logger.Info("BionicGPT deletion completed successfully")
	logger.Info("")
	logger.Info("✓ BionicGPT has been completely removed")

	if len(backupPaths) > 0 {
		logger.Info("")
		logger.Info("✓ Backups created successfully:")
		for _, path := range backupPaths {
			info, err := os.Stat(path)
			if err == nil {
				sizeMB := float64(info.Size()) / (1024 * 1024)
				logger.Info("  • Backup file",
					zap.String("path", path),
					zap.Float64("size_mb", sizeMB))
			} else {
				logger.Info("  • Backup file", zap.String("path", path))
			}
		}
		logger.Info("")
		logger.Info("Backup location:", zap.String("dir", backupDir))
		logger.Info("These backups are safe and will NOT be deleted.")
	}
	logger.Info("")

	return nil
}

var (
	BionicgptDeleteSkipBackup bool
	BionicgptDeleteForce      bool
	BionicgptDeletePurge      bool
)

// performManualCleanup removes BionicGPT installation directory without Docker
// This is a fallback when Docker is not available
func performManualCleanup(rc *eos_io.RuntimeContext, installDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Performing manual cleanup (Docker not available)")
	logger.Info("")
	logger.Warn("⚠️  Manual cleanup limitations:")
	logger.Info("  • NO backup will be created")
	logger.Info("  • Docker containers will NOT be removed (if they exist)")
	logger.Info("  • Docker volumes will NOT be removed (if they exist)")
	logger.Info("  • Docker images will NOT be removed (if they exist)")
	logger.Info("")
	logger.Info("Removing installation directory:", zap.String("dir", installDir))

	// Check if directory exists
	if _, err := os.Stat(installDir); os.IsNotExist(err) {
		logger.Info("Installation directory does not exist - nothing to clean up")
		logger.Info("")
		logger.Info("✓ No files to remove")
		logger.Info("")
		logger.Info("Note: If you install Docker later, you can clean up Docker resources with:")
		logger.Info("  docker ps -a --filter name=bionicgpt")
		logger.Info("  docker volume ls --filter name=bionicgpt")
		return nil
	}

	// Remove directory
	if err := os.RemoveAll(installDir); err != nil {
		logger.Error("Failed to remove installation directory",
			zap.String("dir", installDir),
			zap.Error(err))
		return fmt.Errorf("failed to remove installation directory: %w", err)
	}

	logger.Info("✓ Installation directory removed")
	logger.Info("")
	logger.Info("Manual cleanup completed")
	logger.Info("")
	logger.Info("Note: Docker resources may still exist. If you install Docker later, clean up with:")
	logger.Info("  docker rm -f bionicgpt-app bionicgpt-postgres bionicgpt-embeddings")
	logger.Info("  docker volume rm bionicgpt-postgres-data bionicgpt-documents")
	logger.Info("  docker rmi ghcr.io/bionic-gpt/bionicgpt:* ankane/pgvector:*")
	logger.Info("")

	return nil
}

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
	logger.Info("✓ BionicGPT secrets and configs purged from Vault and Consul")

	return nil
}
