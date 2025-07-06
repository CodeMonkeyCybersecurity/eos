// pkg/system/cleanup.go
package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PackageCleanup provides system package cleanup capabilities
type PackageCleanup struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// CleanupResult contains the results of a cleanup operation
type CleanupResult struct {
	OrphanedPackages []string
	UnusedKernels    []string
	OrphansRemoved   bool
	AutoremoveRan    bool
	KernelsRemoved   bool
	SpaceFreed       string
}

// NewPackageCleanup creates a new package cleanup instance
func NewPackageCleanup(rc *eos_io.RuntimeContext) *PackageCleanup {
	return &PackageCleanup{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// CheckRoot verifies the script is run with root privileges
func (pc *PackageCleanup) CheckRoot() error {
	if os.Geteuid() != 0 {
		return eos_err.NewExpectedError(pc.rc.Ctx,
			fmt.Errorf("this operation requires root privileges"))
	}
	return nil
}

// EnsureDeborphan installs deborphan if not present
func (pc *PackageCleanup) EnsureDeborphan() error {
	_, span := telemetry.Start(pc.rc.Ctx, "system.EnsureDeborphan")
	defer span.End()

	pc.logger.Info("Checking for deborphan")

	// Check if deborphan is installed
	if _, err := exec.LookPath("deborphan"); err == nil {
		pc.logger.Info("deborphan is already installed")
		return nil
	}

	pc.logger.Info("deborphan not found, installing")

	// Update package lists
	if err := pc.runCommand("apt", "update"); err != nil {
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	// Install deborphan
	if err := pc.runCommand("apt", "install", "-y", "deborphan"); err != nil {
		return fmt.Errorf("failed to install deborphan: %w", err)
	}

	pc.logger.Info("deborphan installed successfully")
	return nil
}

// FindOrphanedPackages identifies orphaned packages using deborphan
func (pc *PackageCleanup) FindOrphanedPackages() ([]string, error) {
	_, span := telemetry.Start(pc.rc.Ctx, "system.FindOrphanedPackages")
	defer span.End()

	pc.logger.Info("Identifying orphaned packages")

	cmd := exec.Command("deborphan")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run deborphan: %w", err)
	}

	if len(output) == 0 {
		pc.logger.Info("No orphaned packages found")
		return []string{}, nil
	}

	// Parse output
	orphans := strings.Fields(strings.TrimSpace(string(output)))
	
	pc.logger.Info("Found orphaned packages",
		zap.Int("count", len(orphans)),
		zap.Strings("packages", orphans))

	return orphans, nil
}

// FindUnusedKernels identifies unused kernel packages
func (pc *PackageCleanup) FindUnusedKernels() ([]string, error) {
	_, span := telemetry.Start(pc.rc.Ctx, "system.FindUnusedKernels")
	defer span.End()

	pc.logger.Info("Checking for unused kernels")

	// Get current kernel version
	cmd := exec.Command("uname", "-r")
	currentKernel, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get current kernel: %w", err)
	}
	currentKernelStr := strings.TrimSpace(string(currentKernel))

	// List installed kernels
	cmd = exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %w", err)
	}

	var unusedKernels []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		line := scanner.Text()
		// Look for linux-image packages
		if strings.Contains(line, "linux-image-") && !strings.Contains(line, currentKernelStr) {
			fields := strings.Fields(line)
			if len(fields) >= 2 && (strings.HasPrefix(fields[0], "ii") || strings.HasPrefix(fields[0], "rc")) {
				unusedKernels = append(unusedKernels, fields[1])
			}
		}
	}

	pc.logger.Info("Found unused kernels",
		zap.Int("count", len(unusedKernels)),
		zap.Strings("kernels", unusedKernels))

	return unusedKernels, nil
}

// RemoveOrphanedPackages removes the specified orphaned packages
func (pc *PackageCleanup) RemoveOrphanedPackages(packages []string) error {
	_, span := telemetry.Start(pc.rc.Ctx, "system.RemoveOrphanedPackages")
	defer span.End()

	if len(packages) == 0 {
		return nil
	}

	pc.logger.Info("Removing orphaned packages",
		zap.Strings("packages", packages))

	args := append([]string{"remove", "-y"}, packages...)
	if err := pc.runCommand("apt", args...); err != nil {
		return fmt.Errorf("failed to remove orphaned packages: %w", err)
	}

	pc.logger.Info("Orphaned packages removed successfully")
	return nil
}

// RunAutoremove runs apt autoremove to clean up unused dependencies
func (pc *PackageCleanup) RunAutoremove() error {
	_, span := telemetry.Start(pc.rc.Ctx, "system.RunAutoremove")
	defer span.End()

	pc.logger.Info("Running apt autoremove")

	if err := pc.runCommand("apt", "autoremove", "-y"); err != nil {
		return fmt.Errorf("failed to run autoremove: %w", err)
	}

	pc.logger.Info("Autoremove completed successfully")
	return nil
}

// RemoveUnusedKernels removes the specified kernel packages
func (pc *PackageCleanup) RemoveUnusedKernels(kernels []string) error {
	_, span := telemetry.Start(pc.rc.Ctx, "system.RemoveUnusedKernels")
	defer span.End()

	if len(kernels) == 0 {
		return nil
	}

	pc.logger.Info("Removing unused kernels",
		zap.Strings("kernels", kernels))

	args := append([]string{"remove", "-y"}, kernels...)
	if err := pc.runCommand("apt", args...); err != nil {
		return fmt.Errorf("failed to remove unused kernels: %w", err)
	}

	pc.logger.Info("Unused kernels removed successfully")
	return nil
}

// PerformFullCleanup performs a complete system cleanup
func (pc *PackageCleanup) PerformFullCleanup(interactive bool) (*CleanupResult, error) {
	_, span := telemetry.Start(pc.rc.Ctx, "system.PerformFullCleanup")
	defer span.End()

	pc.logger.Info("Starting full system cleanup", zap.Bool("interactive", interactive))

	result := &CleanupResult{}

	// Check root privileges
	if err := pc.CheckRoot(); err != nil {
		return nil, err
	}

	// Ensure deborphan is available
	if err := pc.EnsureDeborphan(); err != nil {
		return nil, fmt.Errorf("failed to ensure deborphan: %w", err)
	}

	// Update package information
	pc.logger.Info("Updating package information")
	if err := pc.runCommand("apt", "update"); err != nil {
		pc.logger.Warn("Failed to update package lists", zap.Error(err))
	}

	// Find orphaned packages
	orphans, err := pc.FindOrphanedPackages()
	if err != nil {
		pc.logger.Warn("Failed to find orphaned packages", zap.Error(err))
	} else {
		result.OrphanedPackages = orphans
		
		if len(orphans) > 0 {
			if interactive {
				if pc.promptYesNo(fmt.Sprintf("Remove %d orphaned packages?", len(orphans))) {
					if err := pc.RemoveOrphanedPackages(orphans); err != nil {
						pc.logger.Error("Failed to remove orphaned packages", zap.Error(err))
					} else {
						result.OrphansRemoved = true
					}
				}
			} else {
				if err := pc.RemoveOrphanedPackages(orphans); err != nil {
					pc.logger.Error("Failed to remove orphaned packages", zap.Error(err))
				} else {
					result.OrphansRemoved = true
				}
			}
		}
	}

	// Run autoremove
	if interactive {
		if pc.promptYesNo("Run apt autoremove to clean up unused dependencies?") {
			if err := pc.RunAutoremove(); err != nil {
				pc.logger.Error("Failed to run autoremove", zap.Error(err))
			} else {
				result.AutoremoveRan = true
			}
		}
	} else {
		if err := pc.RunAutoremove(); err != nil {
			pc.logger.Error("Failed to run autoremove", zap.Error(err))
		} else {
			result.AutoremoveRan = true
		}
	}

	// Find unused kernels
	kernels, err := pc.FindUnusedKernels()
	if err != nil {
		pc.logger.Warn("Failed to find unused kernels", zap.Error(err))
	} else {
		result.UnusedKernels = kernels
		
		if len(kernels) > 0 {
			if interactive {
				if pc.promptYesNo(fmt.Sprintf("Remove %d unused kernels?", len(kernels))) {
					if err := pc.RemoveUnusedKernels(kernels); err != nil {
						pc.logger.Error("Failed to remove unused kernels", zap.Error(err))
					} else {
						result.KernelsRemoved = true
					}
				}
			} else {
				// Be more cautious with kernels in non-interactive mode
				pc.logger.Info("Skipping kernel removal in non-interactive mode for safety")
			}
		}
	}

	pc.logger.Info("System cleanup completed")
	return result, nil
}

// runCommand executes a system command
func (pc *PackageCleanup) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	
	pc.logger.Debug("Executing command",
		zap.String("command", name),
		zap.Strings("args", args))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %s %v: %w", name, args, err)
	}

	return nil
}

// promptYesNo prompts the user for a yes/no answer
func (pc *PackageCleanup) promptYesNo(prompt string) bool {
	fmt.Printf("%s (y/n): ", prompt)
	
	var response string
	fmt.Scanln(&response)
	
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// FormatResult creates a human-readable cleanup report
func (result *CleanupResult) FormatResult() string {
	var buf strings.Builder

	buf.WriteString("🧹 System Cleanup Results\n")
	buf.WriteString("=========================\n\n")

	if len(result.OrphanedPackages) > 0 {
		buf.WriteString(fmt.Sprintf("📦 Orphaned packages found: %d\n", len(result.OrphanedPackages)))
		if result.OrphansRemoved {
			buf.WriteString("✅ Orphaned packages removed\n")
		} else {
			buf.WriteString("⏭️  Orphaned packages not removed\n")
		}
	} else {
		buf.WriteString("📦 No orphaned packages found\n")
	}

	if result.AutoremoveRan {
		buf.WriteString("✅ Autoremove completed\n")
	} else {
		buf.WriteString("⏭️  Autoremove skipped\n")
	}

	if len(result.UnusedKernels) > 0 {
		buf.WriteString(fmt.Sprintf("🐧 Unused kernels found: %d\n", len(result.UnusedKernels)))
		if result.KernelsRemoved {
			buf.WriteString("✅ Unused kernels removed\n")
		} else {
			buf.WriteString("⏭️  Unused kernels not removed\n")
		}
	} else {
		buf.WriteString("🐧 No unused kernels found\n")
	}

	buf.WriteString("\n✅ System cleanup completed!\n")

	return buf.String()
}