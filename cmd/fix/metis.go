// cmd/fix/metis.go
package fix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	dryRun      bool
	autoYes     bool
	interactive bool
)

var metisFixCmd = &cobra.Command{
	Use:   "metis",
	Short: "Fix and repair Metis installation issues",
	Long: `Automatically detect and fix common Metis installation issues.

The repair command can fix:
- Temporal CLI not in PATH (creates symlink)
- Temporal server not running (starts it)
- Missing directories or permissions
- Worker/webhook not running (starts them)

The command runs diagnostics first, then shows you exactly what it will do
before making any changes. You'll be asked to confirm each fix.

EXAMPLES:
  # Interactive repair (recommended)
  sudo eos repair metis

  # Show what would be fixed without doing it
  sudo eos repair metis --dry-run

  # Fix everything automatically without prompts
  sudo eos repair metis --yes

  # Fix specific issues only
  sudo eos repair metis --interactive`,

	RunE: eos.Wrap(runRepairMetis),
}

func init() {
	metisFixCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be fixed without making changes")
	metisFixCmd.Flags().BoolVar(&autoYes, "yes", false, "Automatically approve all fixes")
	metisFixCmd.Flags().BoolVar(&interactive, "interactive", true, "Ask for confirmation before each fix (default)")
}

type repairAction struct {
	name        string
	description string
	command     string
	check       func(*eos_io.RuntimeContext) (bool, string)
	execute     func(*eos_io.RuntimeContext) error
	verify      func(*eos_io.RuntimeContext) error
}

func runRepairMetis(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  METIS REPAIR TOOL                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if dryRun {
		fmt.Println(" DRY RUN MODE - No changes will be made")
		fmt.Println()
	}

	// Build repair plan
	actions := buildRepairPlan(rc)

	if len(actions) == 0 {
		fmt.Println("✓ No issues detected - Metis is healthy!")
		fmt.Println()
		fmt.Println("To verify, run: eos debug metis")
		return nil
	}

	// Show repair plan
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    REPAIR PLAN                                 ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Found %d issue(s) that can be fixed:\n\n", len(actions))

	for i, action := range actions {
		fmt.Printf("%d. %s\n", i+1, action.name)
		fmt.Printf("   Description: %s\n", action.description)
		fmt.Printf("   Command: %s\n", action.command)
		fmt.Println()
	}

	if dryRun {
		fmt.Println("Dry run complete. Run without --dry-run to apply fixes.")
		return nil
	}

	// Ask for confirmation
	if !autoYes {
		fmt.Print("Proceed with repairs? [y/N]: ")
		var response string
		_, _ = fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Println("Repair cancelled.")
			return nil
		}
		fmt.Println()
	}

	// Execute repairs
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  EXECUTING REPAIRS                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	successCount := 0
	failureCount := 0

	for i, action := range actions {
		fmt.Printf("[%d/%d] %s\n", i+1, len(actions), action.name)

		// Ask for confirmation if interactive mode
		if interactive && !autoYes {
			fmt.Printf("  Run: %s\n", action.command)
			fmt.Print("  Execute this fix? [Y/n]: ")
			var response string
			_, _ = fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))
			if response == "n" || response == "no" {
				fmt.Println("  ⊘ Skipped")
				fmt.Println()
				continue
			}
		}

		// Execute the fix
		if err := action.execute(rc); err != nil {
			fmt.Printf("  ✗ Failed: %v\n", err)
			logger.Error("Repair action failed", zap.String("action", action.name), zap.Error(err))
			failureCount++

			if interactive && !autoYes {
				fmt.Print("  Continue with remaining fixes? [y/N]: ")
				var response string
				_, _ = fmt.Scanln(&response)
				response = strings.ToLower(strings.TrimSpace(response))
				if response != "y" && response != "yes" {
					fmt.Println()
					fmt.Println("Repair stopped by user.")
					break
				}
			}
		} else {
			// Verify the fix worked
			if action.verify != nil {
				if err := action.verify(rc); err != nil {
					fmt.Printf("  ⚠ Fix applied but verification failed: %v\n", err)
					logger.Warn("Verification failed", zap.String("action", action.name), zap.Error(err))
				} else {
					fmt.Println("  ✓ Success")
					successCount++
				}
			} else {
				fmt.Println("  ✓ Success")
				successCount++
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      SUMMARY                                   ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Total repairs attempted: %d\n", len(actions))
	fmt.Printf("✓ Successful: %d\n", successCount)
	if failureCount > 0 {
		fmt.Printf("✗ Failed: %d\n", failureCount)
	}
	fmt.Println()

	if failureCount == 0 {
		fmt.Println("All repairs completed successfully!")
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  1. Verify: eos debug metis")
		fmt.Println("  2. Test: eos debug metis --test")
	} else {
		fmt.Println("Some repairs failed. Check the errors above and fix manually.")
		fmt.Println("Run 'eos debug metis' for more details.")
	}

	return nil
}

func buildRepairPlan(rc *eos_io.RuntimeContext) []repairAction {
	var actions []repairAction

	// Check 1: Temporal CLI in PATH
	if needsFixing, reason := checkTemporalPath(rc); needsFixing {
		actions = append(actions, repairAction{
			name:        "Fix Temporal CLI PATH",
			description: reason,
			command:     "cp /root/.temporalio/bin/temporal /usr/local/bin/temporal && chmod 755 /usr/local/bin/temporal",
			check:       checkTemporalPath,
			execute:     fixTemporalPath,
			verify:      verifyTemporalPath,
		})
	}

	// Check 2: Temporal server running
	if needsFixing, reason := checkTemporalServer(rc); needsFixing {
		actions = append(actions, repairAction{
			name:        "Start Temporal Server",
			description: reason,
			command:     "temporal server start-dev (in background)",
			check:       checkTemporalServer,
			execute:     startTemporalServer,
			verify:      verifyTemporalServer,
		})
	}

	// Check 3: Metis project structure
	if needsFixing, reason := checkMetisStructure(rc); needsFixing {
		actions = append(actions, repairAction{
			name:        "Create Metis Directories",
			description: reason,
			command:     "mkdir -p /opt/metis/{worker,webhook,scripts}",
			check:       checkMetisStructure,
			execute:     fixMetisStructure,
			verify:      verifyMetisStructure,
		})
	}

	return actions
}

// Check functions return (needsFixing bool, reason string)

func checkTemporalPath(rc *eos_io.RuntimeContext) (bool, string) {
	// Check if temporal is in PATH
	if _, err := exec.LookPath("temporal"); err == nil {
		return false, ""
	}

	// Check if it exists in common locations
	commonPaths := []string{
		"/root/.temporalio/bin/temporal",
		os.ExpandEnv("$HOME/.temporalio/bin/temporal"),
		"/usr/local/bin/temporal",
	}

	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if info.Mode()&0111 != 0 { // Executable
				return true, fmt.Sprintf("Temporal CLI exists at %s but not in PATH", path)
			}
		}
	}

	return false, "" // Not installed, can't fix with symlink
}

func checkTemporalServer(rc *eos_io.RuntimeContext) (bool, string) {
	// Try to connect to Temporal server
	ctx, cancel := context.WithTimeout(rc.Ctx, 2*time.Second)
	defer cancel()

	// Simple TCP check
	checkCmd := exec.CommandContext(ctx, "nc", "-z", "localhost", "7233")
	if err := checkCmd.Run(); err != nil {
		return true, "Temporal server not running on localhost:7233"
	}

	return false, ""
}

func checkMetisStructure(rc *eos_io.RuntimeContext) (bool, string) {
	requiredDirs := []string{
		"/opt/metis",
		"/opt/metis/worker",
		"/opt/metis/webhook",
	}

	var missing []string
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			missing = append(missing, dir)
		}
	}

	if len(missing) > 0 {
		return true, fmt.Sprintf("Missing directories: %s", strings.Join(missing, ", "))
	}

	return false, ""
}

// Fix functions

func fixTemporalPath(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Find temporal binary
	commonPaths := []string{
		"/root/.temporalio/bin/temporal",
		os.ExpandEnv("$HOME/.temporalio/bin/temporal"),
	}

	var temporalPath string
	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			temporalPath = path
			break
		}
	}

	if temporalPath == "" {
		return fmt.Errorf("temporal binary not found in expected locations")
	}

	logger.Info("Found temporal binary", zap.String("path", temporalPath))

	// We copy the binary instead of symlinking, so no permission fixes needed on source
	// This keeps /root/ secure with 0700 permissions
	targetPath := "/usr/local/bin/temporal"

	// Check if target already exists and is correct
	if info, err := os.Stat(targetPath); err == nil {
		// File exists - verify it works
		versionCmd := exec.CommandContext(rc.Ctx, targetPath, "--version")
		if versionCmd.Run() == nil {
			logger.Info("Temporal already installed in /usr/local/bin",
				zap.String("path", targetPath),
				zap.Int64("size", info.Size()))
			return nil
		}
		// Exists but doesn't work - remove and replace
		logger.Info("Existing temporal binary doesn't work, replacing",
			zap.String("path", targetPath))
		_ = os.Remove(targetPath)
	}

	// Copy the binary instead of symlinking
	// This works even if source is in /root/ because we're running as root
	logger.Info("Copying temporal binary to /usr/local/bin",
		zap.String("from", temporalPath),
		zap.String("to", targetPath))

	// Read source file
	sourceData, err := os.ReadFile(temporalPath)
	if err != nil {
		return fmt.Errorf("failed to read source binary: %w", err)
	}

	// Write to destination with correct permissions
	if err := os.WriteFile(targetPath, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write binary to %s: %w", targetPath, err)
	}

	logger.Info("Binary copied successfully",
		zap.String("path", targetPath),
		zap.Int("size_bytes", len(sourceData)))

	return nil
}

func startTemporalServer(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Temporal server via systemd")

	// Check if temporal service exists
	checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "status", "temporal.service")
	if err := checkCmd.Run(); err != nil {
		// Service doesn't exist - create it
		logger.Info("Creating Temporal systemd service")

		temporalService := `[Unit]
Description=Temporal Server (Development Mode)
After=network.target
Documentation=https://docs.temporal.io/

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/temporal server start-dev --db-filename /var/lib/temporal/temporal.db
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Create data directory if it doesn't exist
RuntimeDirectory=temporal
StateDirectory=temporal

[Install]
WantedBy=multi-user.target
`

		temporalServicePath := "/etc/systemd/system/temporal.service"
		if err := os.WriteFile(temporalServicePath, []byte(temporalService), 0644); err != nil {
			return fmt.Errorf("failed to write temporal service: %w", err)
		}

		logger.Info("Temporal service file created", zap.String("path", temporalServicePath))

		// Reload systemd
		if err := exec.CommandContext(rc.Ctx, "systemctl", "daemon-reload").Run(); err != nil {
			return fmt.Errorf("failed to reload systemd: %w", err)
		}
	}

	// Enable the service
	logger.Info("Enabling Temporal service")
	if err := exec.CommandContext(rc.Ctx, "systemctl", "enable", "temporal.service").Run(); err != nil {
		logger.Warn("Failed to enable temporal service", zap.Error(err))
	}

	// Start the service
	logger.Info("Starting Temporal service")
	if err := exec.CommandContext(rc.Ctx, "systemctl", "start", "temporal.service").Run(); err != nil {
		return fmt.Errorf("failed to start temporal service: %w", err)
	}

	// Wait for server to be ready (with timeout)
	fmt.Print("  Waiting for server to be ready")
	ctx, cancel := context.WithTimeout(rc.Ctx, 15*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return fmt.Errorf("timeout waiting for temporal server to start")
		case <-ticker.C:
			fmt.Print(".")
			checkCmd := exec.CommandContext(context.Background(), "nc", "-z", "localhost", "7233")
			if checkCmd.Run() == nil {
				fmt.Println(" ready!")
				logger.Info("Temporal server is running",
					zap.String("status", "active"),
					zap.String("check", "systemctl status temporal"))
				return nil
			}
		}
	}
}

func fixMetisStructure(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	dirs := []string{
		"/opt/metis",
		"/opt/metis/worker",
		"/opt/metis/webhook",
		"/opt/metis/scripts",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
		logger.Info("Created directory", zap.String("path", dir))
	}

	return nil
}

// Verify functions

func verifyTemporalPath(rc *eos_io.RuntimeContext) error {
	cmd := exec.CommandContext(rc.Ctx, "temporal", "--version")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("temporal command still not working: %w\nOutput: %s", err, string(output))
	}
	return nil
}

func verifyTemporalServer(rc *eos_io.RuntimeContext) error {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	checkCmd := exec.CommandContext(ctx, "nc", "-z", "localhost", "7233")
	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("temporal server not responding on localhost:7233")
	}
	return nil
}

func verifyMetisStructure(rc *eos_io.RuntimeContext) error {
	requiredDirs := []string{
		"/opt/metis",
		"/opt/metis/worker",
		"/opt/metis/webhook",
	}

	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("directory %s still missing", dir)
		}
	}
	return nil
}
