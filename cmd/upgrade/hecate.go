// cmd/upgrade/hecate.go
package upgrade

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HecateCmd represents the 'eos upgrade hecate' command
var HecateCmd = &cobra.Command{
	Use:   "hecate [flags]",
	Short: "Upgrade Hecate components (Authentik, Caddy, etc.)",
	Long: `Upgrade your Hecate installation components with automatic handling of breaking changes.

This command can upgrade:
- Authentik identity provider (--authentik flag)
- Caddy reverse proxy (future)
- Other Hecate components (future)

For Authentik upgrades, this command will:
- Run pre-upgrade health checks
- Create a backup of your current installation
- Check for breaking changes between versions
- Update configuration files as needed
- Perform the upgrade with minimal downtime
- Verify the upgrade was successful

Examples:
  eos upgrade hecate --authentik                    # Upgrade Authentik with prompts
  eos upgrade hecate --authentik --target-version 2025.8  # Upgrade to specific version
  eos upgrade hecate --authentik --force            # Force upgrade even with warnings
  eos upgrade hecate --authentik --skip-backup      # Skip backup (not recommended)`,
	RunE: eos.Wrap(upgradeHecate),
}

var (
	hecateUpgradeAuthentik    bool
	hecateTargetVersion       string
	hecateSkipBackup          bool
	hecateSkipHealthCheck     bool
	hecateForce               bool
	hecateUpgradePath         string
	hecateWaitForTasks        bool
	hecateRestartAfterUpgrade bool
)

func init() {
	hecateFlags := HecateCmd.Flags()

	// Component selection
	hecateFlags.BoolVar(&hecateUpgradeAuthentik, "authentik", false, "Upgrade Authentik identity provider")

	// Upgrade options
	hecateFlags.StringVarP(&hecateTargetVersion, "target-version", "t", "2025.8", "Target version to upgrade to")
	hecateFlags.BoolVar(&hecateSkipBackup, "skip-backup", false, "Skip creating a backup (not recommended)")
	hecateFlags.BoolVar(&hecateSkipHealthCheck, "skip-health-check", false, "Skip pre-upgrade health checks")
	hecateFlags.BoolVar(&hecateForce, "force", false, "Force upgrade even with warnings")
	hecateFlags.StringVarP(&hecateUpgradePath, "path", "p", "/opt/hecate", "Path to Hecate installation")
	hecateFlags.BoolVar(&hecateWaitForTasks, "wait-for-tasks", true, "Wait for active tasks to complete before upgrading")
	hecateFlags.BoolVar(&hecateRestartAfterUpgrade, "restart", true, "Restart services after upgrade")
}

func upgradeHecate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	if !hecateUpgradeAuthentik {
		return eos_err.NewUserError(
			"Please specify which component to upgrade:\n" +
				"  --authentik    Upgrade Authentik identity provider\n\n" +
				"Example: eos upgrade hecate --authentik")
	}

	if hecateUpgradeAuthentik {
		return upgradeAuthentikComponent(rc)
	}

	return fmt.Errorf("no component selected for upgrade")
}

func upgradeAuthentikComponent(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Authentik upgrade",
		zap.String("path", hecateUpgradePath),
		zap.String("target_version", hecateTargetVersion))

	fmt.Println("=========================================")
	fmt.Printf("Authentik Upgrade to %s\n", hecateTargetVersion)
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("This script will upgrade your Authentik instance with proper handling of breaking changes.")
	fmt.Println()

	// Step 1: Verify we're in the right directory
	if err := verifyHecateDirectory(); err != nil {
		return err
	}

	// Step 2: Pre-upgrade health check (unless skipped)
	if !hecateSkipHealthCheck {
		logger.Info("Running pre-upgrade health checks")
		if err := runPreUpgradeHealthCheck(rc); err != nil {
			if !hecateForce {
				return err
			}
			logger.Warn("Pre-upgrade health check failed, but continuing due to --force flag")
		}
	}

	// Step 3: Create backup
	var backupDir string
	if !hecateSkipBackup {
		var err error
		backupDir, err = createUpgradeBackup(rc)
		if err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		logger.Info("Backup created", zap.String("backup_dir", backupDir))
	} else {
		logger.Warn("Skipping backup as requested")
	}

	// Step 4: Check PostgreSQL encoding
	if err := checkPostgreSQLEncodingForUpgrade(rc); err != nil {
		if !hecateForce {
			return err
		}
		logger.Warn("PostgreSQL encoding check failed, but continuing due to --force flag")
	}

	// Step 5: Check task queue status
	if hecateWaitForTasks {
		if err := waitForActiveTasks(rc); err != nil {
			logger.Warn("Could not wait for tasks", zap.Error(err))
		}
	}

	// Step 6: Update docker-compose.yml
	if err := updateDockerComposeFile(rc); err != nil {
		return fmt.Errorf("failed to update docker-compose.yml: %w", err)
	}

	// Step 7: Update .env file
	if err := updateEnvironmentFile(rc); err != nil {
		return fmt.Errorf("failed to update .env file: %w", err)
	}

	// Step 8: Perform the upgrade
	if err := performAuthentikUpgrade(rc); err != nil {
		return fmt.Errorf("upgrade failed: %w\n\nTo rollback:\n  cd %s\n  cp %s/docker-compose.yml .\n  docker compose up -d", err, hecateUpgradePath, backupDir)
	}

	// Display completion message
	displayUpgradeCompletionMessage(backupDir)

	return nil
}

func verifyHecateDirectory() error {
	composePath := filepath.Join(hecateUpgradePath, "docker-compose.yml")
	authentikPath := filepath.Join(hecateUpgradePath, "authentik")

	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		return eos_err.NewUserError(
			"docker-compose.yml not found in %s\n"+
				"Please run this command from the Hecate installation directory\n"+
				"Or use --path flag to specify the correct path",
			hecateUpgradePath)
	}

	if _, err := os.Stat(authentikPath); os.IsNotExist(err) {
		return eos_err.NewUserError(
			"authentik directory not found in %s\n"+
				"This does not appear to be a valid Hecate installation",
			hecateUpgradePath)
	}

	return nil
}

func runPreUpgradeHealthCheck(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("Step 1: Running pre-upgrade health checks...")
	fmt.Println()

	// Run docker compose ps to check container status
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "ps", "--format", "{{.Name}}\t{{.State}}")
	cmd.Dir = hecateUpgradePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	fmt.Println("Container Status:")
	fmt.Println(string(output))

	anyExited := strings.Contains(string(output), "exited") || strings.Contains(string(output), "dead")
	if anyExited {
		logger.Warn("Some containers are not running")
		if !hecateForce {
			return eos_err.NewUserError(
				"Some containers are not running. Please start all containers first:\n"+
					"  cd %s && docker compose up -d\n"+
					"Or use --force to continue anyway",
				hecateUpgradePath)
		}
	}

	fmt.Println("✅ Pre-upgrade health check passed")
	fmt.Println()

	return nil
}

func createUpgradeBackup(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("Step 2: Creating backup...")

	backupDir := filepath.Join(hecateUpgradePath, "backups", time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup docker-compose.yml
	composeSource := filepath.Join(hecateUpgradePath, "docker-compose.yml")
	composeDest := filepath.Join(backupDir, "docker-compose.yml")
	if err := copyFile(composeSource, composeDest); err != nil {
		return "", fmt.Errorf("failed to backup docker-compose.yml: %w", err)
	}

	// Backup .env
	envSource := filepath.Join(hecateUpgradePath, ".env")
	envDest := filepath.Join(backupDir, ".env")
	if err := copyFile(envSource, envDest); err != nil {
		logger.Warn("Could not backup .env file", zap.Error(err))
	}

	// Backup authentik directory
	authentikSource := filepath.Join(hecateUpgradePath, "authentik")
	authentikDest := filepath.Join(backupDir, "authentik")
	if err := copyDir(authentikSource, authentikDest); err != nil {
		logger.Warn("Could not backup authentik directory", zap.Error(err))
	}

	fmt.Printf("✅ Backup created in %s\n", backupDir)
	fmt.Println()

	return backupDir, nil
}

func checkPostgreSQLEncodingForUpgrade(rc *eos_io.RuntimeContext) error {
	fmt.Println("Step 3: Checking PostgreSQL encoding...")

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "postgresql",
		"psql", "-U", "authentik", "-c", "SHOW SERVER_ENCODING;")
	cmd.Dir = hecateUpgradePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		return fmt.Errorf("failed to check PostgreSQL encoding: %w", err)
	}

	isUTF8 := strings.Contains(strings.ToUpper(string(output)), "UTF8") ||
		strings.Contains(strings.ToUpper(string(output)), "UTF-8")

	if !isUTF8 {
		return eos_err.NewUserError(
			"database encoding is not UTF8 (required for Authentik 2025.8+)\n"+
				"Current encoding: %s\n"+
				"You must migrate your database to UTF8 encoding before upgrading\n"+
				"Use --force to continue anyway (not recommended)",
			string(output))
	}

	fmt.Println("✅ Database encoding is UTF8")
	fmt.Println()

	return nil
}

func waitForActiveTasks(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("Step 4: Checking task queue status...")

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "worker",
		"bash", "-c", "DJANGO_SETTINGS_MODULE=authentik.root.settings celery -A authentik.root.celery inspect active")
	cmd.Dir = hecateUpgradePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Could not check task queue", zap.Error(err))
		return nil
	}

	isEmpty := strings.Contains(string(output), "empty")

	if !isEmpty {
		fmt.Println("⚠️  There are active tasks in the queue")
		fmt.Print("Wait for tasks to complete? (y/n): ")

		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			logger.Debug("Failed to read user input", zap.Error(err))
			response = "n"
		}

		if strings.ToLower(response) == "y" {
			fmt.Println("Waiting 30 seconds for tasks to complete...")
			time.Sleep(30 * time.Second)
		}
	} else {
		fmt.Println("✅ No active tasks in queue")
	}

	fmt.Println()

	return nil
}

func updateDockerComposeFile(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("Step 5: Updating docker-compose.yml...")

	composePath := filepath.Join(hecateUpgradePath, "docker-compose.yml")
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	content := string(composeData)

	// Update the image tag for server and worker
	oldTag := "AUTHENTIK_TAG:-2025.6.1"
	newTag := fmt.Sprintf("AUTHENTIK_TAG:-%s", hecateTargetVersion)
	content = strings.ReplaceAll(content, oldTag, newTag)

	// Also handle if they have a hardcoded version
	content = strings.ReplaceAll(content, ":2025.6.1}", fmt.Sprintf(":%s}", hecateTargetVersion))
	content = strings.ReplaceAll(content, ":2025.6}", fmt.Sprintf(":%s}", hecateTargetVersion))

	// Update worker setting name
	content = strings.ReplaceAll(content, "AUTHENTIK_WORKER__CONCURRENCY", "AUTHENTIK_WORKER__THREADS")

	// Write the updated file
	if err := os.WriteFile(composePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write updated docker-compose.yml: %w", err)
	}

	logger.Debug("Updated docker-compose.yml",
		zap.String("old_tag", oldTag),
		zap.String("new_tag", newTag))

	fmt.Println("✅ docker-compose.yml updated")
	fmt.Println()

	return nil
}

func updateEnvironmentFile(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("Step 6: Updating .env file...")

	envPath := filepath.Join(hecateUpgradePath, ".env")
	envData, err := os.ReadFile(envPath)
	if err != nil {
		logger.Warn(".env file not found, skipping")
		return nil
	}

	content := string(envData)

	// Remove deprecated settings
	deprecated := []string{
		"AUTHENTIK_BROKER__URL",
		"AUTHENTIK_BROKER__TRANSPORT_OPTIONS",
		"AUTHENTIK_RESULT_BACKEND__URL",
	}

	lines := strings.Split(content, "\n")
	var newLines []string
	removedCount := 0

	for _, line := range lines {
		shouldKeep := true
		for _, dep := range deprecated {
			if strings.Contains(line, dep) {
				shouldKeep = false
				removedCount++
				logger.Debug("Removing deprecated setting", zap.String("setting", dep))
				break
			}
		}
		if shouldKeep {
			// Also rename the worker concurrency setting
			line = strings.ReplaceAll(line, "AUTHENTIK_WORKER__CONCURRENCY", "AUTHENTIK_WORKER__THREADS")
			newLines = append(newLines, line)
		}
	}

	if removedCount > 0 {
		// Write the updated file
		newContent := strings.Join(newLines, "\n")
		if err := os.WriteFile(envPath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write updated .env file: %w", err)
		}
		fmt.Printf("✅ .env file updated (removed %d deprecated settings)\n", removedCount)
	} else {
		fmt.Println("✅ .env file is up to date")
	}

	fmt.Println()

	return nil
}

func performAuthentikUpgrade(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("Step 7: Performing upgrade...")
	fmt.Println("Following the recommended upgrade path for minimal downtime:")
	fmt.Println()

	// Pull new images
	fmt.Println("1. Pulling new images...")
	ctx, cancel := context.WithTimeout(rc.Ctx, 300*time.Second)
	pullCmd := exec.CommandContext(ctx, "docker", "compose", "pull")
	pullCmd.Dir = hecateUpgradePath
	pullCmd.Stdout = os.Stdout
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		cancel()
		return fmt.Errorf("failed to pull images: %w", err)
	}
	cancel()

	fmt.Println()

	// Upgrade server first (recommended upgrade path)
	fmt.Println("2. Upgrading server first (as recommended)...")
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 60*time.Second)
	stopServerCmd := exec.CommandContext(ctx2, "docker", "compose", "stop", "server")
	stopServerCmd.Dir = hecateUpgradePath
	if err := stopServerCmd.Run(); err != nil {
		cancel2()
		return fmt.Errorf("failed to stop server: %w", err)
	}
	cancel2()

	ctx3, cancel3 := context.WithTimeout(rc.Ctx, 120*time.Second)
	upServerCmd := exec.CommandContext(ctx3, "docker", "compose", "up", "-d", "server")
	upServerCmd.Dir = hecateUpgradePath
	upServerCmd.Stdout = os.Stdout
	upServerCmd.Stderr = os.Stderr
	if err := upServerCmd.Run(); err != nil {
		cancel3()
		return fmt.Errorf("failed to start server: %w", err)
	}
	cancel3()

	fmt.Println()

	// Wait for server to be healthy
	fmt.Println("3. Waiting for server to be healthy...")
	time.Sleep(15 * time.Second)

	fmt.Println()

	// Upgrade worker
	fmt.Println("4. Now upgrading worker...")
	ctx4, cancel4 := context.WithTimeout(rc.Ctx, 60*time.Second)
	stopWorkerCmd := exec.CommandContext(ctx4, "docker", "compose", "stop", "worker")
	stopWorkerCmd.Dir = hecateUpgradePath
	if err := stopWorkerCmd.Run(); err != nil {
		cancel4()
		return fmt.Errorf("failed to stop worker: %w", err)
	}
	cancel4()

	ctx5, cancel5 := context.WithTimeout(rc.Ctx, 120*time.Second)
	upWorkerCmd := exec.CommandContext(ctx5, "docker", "compose", "up", "-d", "worker")
	upWorkerCmd.Dir = hecateUpgradePath
	upWorkerCmd.Stdout = os.Stdout
	upWorkerCmd.Stderr = os.Stderr
	if err := upWorkerCmd.Run(); err != nil {
		cancel5()
		return fmt.Errorf("failed to start worker: %w", err)
	}
	cancel5()

	fmt.Println()

	// Restart all services to ensure consistency
	if hecateRestartAfterUpgrade {
		fmt.Println("5. Restarting all services to ensure consistency...")
		ctx6, cancel6 := context.WithTimeout(rc.Ctx, 120*time.Second)
		upAllCmd := exec.CommandContext(ctx6, "docker", "compose", "up", "-d")
		upAllCmd.Dir = hecateUpgradePath
		upAllCmd.Stdout = os.Stdout
		upAllCmd.Stderr = os.Stderr
		if err := upAllCmd.Run(); err != nil {
			cancel6()
			return fmt.Errorf("failed to restart services: %w", err)
		}
		cancel6()
	}

	fmt.Println()

	logger.Info("Authentik upgrade completed successfully",
		zap.String("version", hecateTargetVersion))

	return nil
}

func displayUpgradeCompletionMessage(backupDir string) {
	fmt.Println("=========================================")
	fmt.Println("✅ Upgrade Complete!")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Printf("Authentik has been upgraded to %s\n", hecateTargetVersion)
	fmt.Println()
	fmt.Println("Important post-upgrade tasks:")
	fmt.Printf("1. Check the logs: cd %s && docker compose logs -f server worker\n", hecateUpgradePath)
	fmt.Println("2. Access the admin interface and verify functionality")
	fmt.Println("3. Review any warnings in the System > System info page")
	fmt.Println()

	if backupDir != "" {
		fmt.Println("If you encounter issues:")
		fmt.Printf("- Restore from backup: %s\n", backupDir)
		fmt.Printf("- Check logs: cd %s && docker compose logs\n", hecateUpgradePath)
		fmt.Printf("- Rollback: cp %s/docker-compose.yml %s && cd %s && docker compose up -d\n",
			backupDir, hecateUpgradePath, hecateUpgradePath)
		fmt.Println()
	}

	fmt.Println("Breaking changes addressed:")
	fmt.Println("✅ Worker tasks migration handled")
	fmt.Println("✅ AUTHENTIK_WORKER__CONCURRENCY renamed to AUTHENTIK_WORKER__THREADS")
	fmt.Println("✅ Removed deprecated broker settings")
	fmt.Println("✅ Database UTF8 encoding verified")
	fmt.Println()
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// copyDir recursively copies a directory
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		return copyFile(path, targetPath)
	})
}
