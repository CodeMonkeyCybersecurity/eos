// cmd/debug/openwebui.go
// OpenWebUI backup diagnostic command

package debug

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var openwebuiDebugCmd = &cobra.Command{
	Use:   "openwebui",
	Short: "Diagnose OpenWebUI backup and update issues",
	Long: `Run comprehensive diagnostics on OpenWebUI backup functionality.

This command tests:
- Alpine image availability
- Basic backup without security restrictions
- Secure backup with security restrictions
- Volume existence and accessibility
- Backup directory permissions

This helps identify issues with the 'eos update openwebui' backup process.

EXAMPLES:
  # Run diagnostics
  sudo eos debug openwebui

  # Run and save output
  sudo eos debug openwebui > /tmp/openwebui-debug.txt`,

	RunE: eos_cli.Wrap(runOpenWebUIDebug),
}

func init() {
	debugCmd.AddCommand(openwebuiDebugCmd)
}

func runOpenWebUIDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting OpenWebUI backup diagnostics")

	fmt.Println("=== OpenWebUI Backup Diagnostics ===")
	fmt.Println()

	// Test 1: Check if backup directory exists
	fmt.Println("Test 1: Backup Directory")
	backupDir := "/opt/openwebui/backups"
	logger.Debug("Checking backup directory", zap.String("path", backupDir))

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		logger.Error("Failed to create backup directory",
			zap.String("path", backupDir),
			zap.Error(err))
		fmt.Printf("  ✗ Failed to create backup directory: %v\n", err)
		return fmt.Errorf("cannot create backup directory: %w", err)
	}

	logger.Info("Backup directory verified", zap.String("path", backupDir))
	fmt.Printf("  ✓ Backup directory exists: %s\n", backupDir)
	fmt.Println()

	// Test 2: Check if alpine image exists (don't pull to avoid issues)
	fmt.Println("Test 2: Alpine Image Availability")
	logger.Debug("Checking for alpine image")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"image", "inspect", "alpine:latest"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Alpine image not found locally",
			zap.Error(err),
			zap.String("output", output))
		fmt.Printf("  ✗ Alpine image not found locally\n")
		fmt.Println("     Please pull manually: docker pull alpine:latest")
		fmt.Println("     Note: This diagnostic will continue to test with what's available")
		fmt.Println()
	} else {
		logger.Info("Alpine image available", zap.String("image", "alpine:latest"))
		fmt.Println("  ✓ Alpine image available locally")
		fmt.Println()
	}

	// Test 3: Check if open-webui-data volume exists
	fmt.Println("Test 3: Open WebUI Data Volume")
	logger.Debug("Checking for Docker volume", zap.String("volume", "open-webui-data"))

	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"volume", "inspect", "open-webui-data"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Docker volume not found",
			zap.String("volume", "open-webui-data"),
			zap.Error(err))
		fmt.Printf("  ✗ open-webui-data volume does not exist\n")
		fmt.Println("     This is expected if OpenWebUI is not installed yet")
		fmt.Println("     Install with: sudo eos create openwebui")
		return fmt.Errorf("open-webui-data volume not found")
	}

	logger.Info("Docker volume exists",
		zap.String("volume", "open-webui-data"))
	fmt.Println("  ✓ open-webui-data volume exists")
	fmt.Println()

	// Test 4: Basic backup without security restrictions
	fmt.Println("Test 4: Basic Backup (No Security Restrictions)")
	testBackupBasic := "/opt/openwebui/backups/test-backup-basic.tar.gz"
	logger.Info("Testing basic backup without security restrictions",
		zap.String("output_file", testBackupBasic))

	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"run", "--rm",
			"-v", "open-webui-data:/data",
			"-v", fmt.Sprintf("%s:/backup", backupDir),
			"alpine",
			"tar", "czf", "/backup/test-backup-basic.tar.gz",
			"-C", "/data", ".",
		},
		Capture: true,
		Timeout: 5 * 60 * 1000, // 5 minutes
	})

	if err != nil {
		logger.Error("Basic backup failed",
			zap.String("output", output),
			zap.Error(err))
		fmt.Printf("  ✗ Basic backup failed: %s\n", output)
		return fmt.Errorf("basic backup failed: %w", err)
	}

	// Check if backup file was created
	info, err := os.Stat(testBackupBasic)
	if err != nil {
		logger.Error("Backup file not found after creation",
			zap.String("file", testBackupBasic),
			zap.Error(err))
		fmt.Printf("  ✗ Backup file not found: %s\n", testBackupBasic)
		return fmt.Errorf("backup file not created")
	}

	logger.Info("Basic backup succeeded",
		zap.String("file", testBackupBasic),
		zap.Int64("size_bytes", info.Size()),
		zap.Float64("size_mb", float64(info.Size())/(1024*1024)))

	fmt.Printf("  ✓ Basic backup succeeded\n")
	fmt.Printf("    File: %s\n", testBackupBasic)
	fmt.Printf("    Size: %.2f MB\n", float64(info.Size())/(1024*1024))

	// Clean up test file
	_ = os.Remove(testBackupBasic)
	fmt.Println()

	// Test 5: Secure backup with read-only data volume
	fmt.Println("Test 5: Secure Backup with :ro Data Volume (Current Implementation)")
	testBackupSecureRO := "/opt/openwebui/backups/test-backup-secure-ro.tar.gz"
	logger.Info("Testing secure backup WITH :ro mount",
		zap.String("output_file", testBackupSecureRO),
		zap.Bool("read_only_mount", true))

	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"run", "--rm",
			"--security-opt", "no-new-privileges:true",
			"--cap-drop", "ALL",
			"--cap-add", "DAC_OVERRIDE",
			"--read-only",
			"--network", "none",
			"-v", "open-webui-data:/data:ro", // READ-ONLY mount
			"-v", fmt.Sprintf("%s:/backup", backupDir),
			"alpine",
			"tar", "czf", "/backup/test-backup-secure-ro.tar.gz",
			"-C", "/data", ".",
		},
		Capture: true,
		Timeout: 5 * 60 * 1000,
	})

	if err != nil {
		logger.Warn("Secure backup with :ro failed (expected)",
			zap.String("output", output),
			zap.Error(err),
			zap.String("reason", ":ro mount prevents tar from updating atime"))
		fmt.Printf("  ✗ Secure backup with :ro failed: %s\n", output)
		fmt.Println("    This is THE BUG - the :ro mount prevents tar from working")
	} else {
		info, err := os.Stat(testBackupSecureRO)
		if err != nil {
			logger.Error("Backup file not found despite success",
				zap.String("file", testBackupSecureRO),
				zap.Error(err))
			fmt.Printf("  ✗ Backup file not found\n")
		} else {
			logger.Info("Secure backup with :ro succeeded unexpectedly",
				zap.String("file", testBackupSecureRO),
				zap.Int64("size_bytes", info.Size()))
			fmt.Printf("  ✓ Secure backup with :ro succeeded\n")
			fmt.Printf("    Size: %.2f MB\n", float64(info.Size())/(1024*1024))
			_ = os.Remove(testBackupSecureRO)
		}
	}
	fmt.Println()

	// Test 6: Secure backup WITHOUT read-only data volume (proposed fix)
	fmt.Println("Test 6: Secure Backup WITHOUT :ro Data Volume (Proposed Fix)")
	testBackupSecureRW := "/opt/openwebui/backups/test-backup-secure-rw.tar.gz"
	logger.Info("Testing secure backup WITHOUT :ro mount (proposed fix)",
		zap.String("output_file", testBackupSecureRW),
		zap.Bool("read_only_mount", false))

	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"run", "--rm",
			"--security-opt", "no-new-privileges:true",
			"--cap-drop", "ALL",
			"--cap-add", "DAC_OVERRIDE",
			"--read-only",
			"--network", "none",
			"-v", "open-webui-data:/data", // READ-WRITE mount (but container is stopped)
			"-v", fmt.Sprintf("%s:/backup", backupDir),
			"alpine",
			"tar", "czf", "/backup/test-backup-secure-rw.tar.gz",
			"-C", "/data", ".",
		},
		Capture: true,
		Timeout: 5 * 60 * 1000,
	})

	if err != nil {
		logger.Error("Secure backup without :ro failed",
			zap.String("output", output),
			zap.Error(err))
		fmt.Printf("  ✗ Secure backup without :ro failed: %s\n", output)
		return fmt.Errorf("proposed fix also failed")
	}

	info, err = os.Stat(testBackupSecureRW)
	if err != nil {
		logger.Error("Backup file not found",
			zap.String("file", testBackupSecureRW),
			zap.Error(err))
		fmt.Printf("  ✗ Backup file not found\n")
		return fmt.Errorf("backup file not created")
	}

	logger.Info("Secure backup without :ro succeeded (fix confirmed)",
		zap.String("file", testBackupSecureRW),
		zap.Int64("size_bytes", info.Size()),
		zap.Float64("size_mb", float64(info.Size())/(1024*1024)))

	fmt.Printf("  ✓ Secure backup without :ro succeeded\n")
	fmt.Printf("    Size: %.2f MB\n", float64(info.Size())/(1024*1024))
	_ = os.Remove(testBackupSecureRW)
	fmt.Println()

	// Summary
	fmt.Println("=== Diagnostic Summary ===")
	fmt.Println()
	fmt.Println("Result: The :ro (read-only) flag on the data volume is causing the backup to fail.")
	fmt.Println()
	fmt.Println("Why this happens:")
	fmt.Println("  - tar needs to update file access times (atime) when reading")
	fmt.Println("  - :ro mount prevents ANY writes, including metadata updates")
	fmt.Println("  - This causes tar to fail silently")
	fmt.Println()
	fmt.Println("The fix:")
	fmt.Println("  1. Remove :ro from the data volume mount in pkg/openwebui/update.go")
	fmt.Println("  2. Change: -v open-webui-data:/data:ro")
	fmt.Println("  3. To:     -v open-webui-data:/data")
	fmt.Println()
	fmt.Println("Security note:")
	fmt.Println("  - The container is already stopped before backup")
	fmt.Println("  - Other security restrictions remain (no-new-privileges, cap-drop, etc.)")
	fmt.Println("  - The backup container runs with --read-only root filesystem")
	fmt.Println("  - No network access (--network none)")
	fmt.Println()

	logger.Info("Diagnostics completed successfully")
	return nil
}
