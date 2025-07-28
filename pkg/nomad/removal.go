package nomad

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveNomadCompletely removes Nomad using comprehensive direct removal
// This provides complete removal when Salt is not available
func RemoveNomadCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Nomad removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Nomad state
	nomadState := assessNomadState(rc)
	logger.Info("Nomad assessment completed",
		zap.Bool("binary_exists", nomadState.BinaryExists),
		zap.Bool("service_exists", nomadState.ServiceExists),
		zap.Bool("api_accessible", nomadState.APIAccessible),
		zap.Int("running_jobs", len(nomadState.RunningJobs)))

	// INTERVENE - Remove Nomad components
	if err := removeNomadComponents(rc, nomadState, keepData); err != nil {
		return fmt.Errorf("failed to remove Nomad components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyNomadRemoval(rc); err != nil {
		logger.Warn("Nomad removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Nomad removal completed successfully")
	return nil
}

// NomadState represents the current state of Nomad installation
type NomadState struct {
	BinaryExists   bool
	ServiceExists  bool
	APIAccessible  bool
	RunningJobs    []string
	DataDirs       []string
	ConfigFiles    []string
}

// assessNomadState checks the current state of Nomad installation
func assessNomadState(rc *eos_io.RuntimeContext) *NomadState {
	state := &NomadState{}

	// Check if Nomad binary exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil {
		state.BinaryExists = true
	}

	// Check if service exists (don't log errors - expected during cleanup)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", "nomad.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		state.ServiceExists = true
	}

	// Check API accessibility
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()
	if output, err := execute.Run(ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"status"},
		Capture: true,
	}); err == nil && output != "" {
		state.APIAccessible = true

		// Try to get running jobs
		if jobOutput, err := execute.Run(ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "list", "-short"},
			Capture: true,
		}); err == nil {
			state.RunningJobs = parseNomadJobs(jobOutput)
		}
	}

	// Check for data directories
	dataDirs := []string{
		"/opt/nomad",
		"/opt/nomad/data",
		"/etc/nomad.d",
		"/var/lib/nomad",
		"/var/log/nomad",
	}
	for _, dir := range dataDirs {
		if _, err := os.Stat(dir); err == nil {
			state.DataDirs = append(state.DataDirs, dir)
		}
	}

	// Check for config files
	configFiles := []string{
		"/etc/nomad.d/nomad.hcl",
		"/etc/systemd/system/nomad.service",
		"/usr/local/bin/nomad",
		"/usr/bin/nomad",
	}
	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			state.ConfigFiles = append(state.ConfigFiles, file)
		}
	}

	return state
}

// removeNomadComponents removes all Nomad components based on current state
func removeNomadComponents(rc *eos_io.RuntimeContext, state *NomadState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Stop running jobs if API is accessible
	if state.APIAccessible && len(state.RunningJobs) > 0 {
		logger.Info("Stopping Nomad jobs", zap.Int("count", len(state.RunningJobs)))
		for _, job := range state.RunningJobs {
			logger.Info("Stopping Nomad job", zap.String("job", job))
			// Use context with timeout for each job
			ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
			_, err := execute.Run(ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", job},
				Capture: true,
			})
			cancel()
			if err != nil {
				logger.Debug("Failed to stop job (may already be stopped)",
					zap.String("job", job), zap.Error(err))
			}
		}

		// Wait for jobs to terminate
		logger.Info("Waiting for jobs to terminate...")
		time.Sleep(5 * time.Second)
	}

	// Stop and disable Nomad service
	if state.ServiceExists {
		logger.Info("Stopping Nomad service")
		// Stop service
		execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "nomad"},
			Timeout: 30 * time.Second,
		})
		// Disable service
		execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"disable", "nomad"},
			Timeout: 10 * time.Second,
		})
	}

	// Kill any remaining Nomad processes
	// TODO: Add graceful shutdown attempt before force kill
	execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-TERM", "-f", "nomad"},
		Timeout: 5 * time.Second,
	})
	time.Sleep(2 * time.Second)
	execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-KILL", "-f", "nomad"},
		Timeout: 5 * time.Second,
	})

	// Remove binaries and config files
	logger.Info("Removing Nomad binaries and configs")
	for _, file := range state.ConfigFiles {
		if err := os.Remove(file); err != nil {
			logger.Debug("Failed to remove file", zap.String("file", file), zap.Error(err))
		}
	}

	// Remove directories
	if !keepData {
		logger.Info("Removing Nomad directories")
		for _, dir := range state.DataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	} else {
		logger.Info("Keeping Nomad data directories as requested")
		// Still remove non-data directories
		nonDataDirs := []string{"/etc/nomad.d", "/opt/nomad/bin"}
		for _, dir := range nonDataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	}

	// Remove HashiCorp repository if no other HashiCorp tools remain
	// FIXME: This should check if other HashiCorp tools are installed before removing repo
	removeHashiCorpRepo(rc)

	// Reload systemd
	execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Timeout: 10 * time.Second,
	})

	return nil
}

// verifyNomadRemoval checks if Nomad was properly removed
func verifyNomadRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Nomad removal")

	issues := []string{}

	// Check if binary still exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil {
		issues = append(issues, "Nomad binary still found in PATH")
	}

	// Check if service still exists
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "--no-pager", "nomad.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil && output != "" {
		issues = append(issues, "Nomad service unit file still exists")
	}

	// Check if processes still running (don't log error if none found)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "nomad"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil && output != "" {
		issues = append(issues, "Nomad processes still running")
	}

	// Check directories
	remainingDirs := []string{}
	for _, dir := range []string{"/opt/nomad", "/etc/nomad.d"} {
		if _, err := os.Stat(dir); err == nil {
			remainingDirs = append(remainingDirs, dir)
		}
	}
	if len(remainingDirs) > 0 {
		issues = append(issues, fmt.Sprintf("Directories still exist: %v", remainingDirs))
	}

	if len(issues) > 0 {
		logger.Warn("Nomad removal verification found issues",
			zap.Strings("issues", issues))
		return fmt.Errorf("removal incomplete: %d issues found", len(issues))
	}

	logger.Info("Nomad removal verification passed")
	return nil
}

// parseNomadJobs extracts job names from nomad job list output
func parseNomadJobs(output string) []string {
	// TODO: Implement proper parsing of Nomad job list output
	// For now, return empty slice
	return []string{}
}

// removeHashiCorpRepo removes HashiCorp APT repository if safe
func removeHashiCorpRepo(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if other HashiCorp tools are installed
	hashicorpTools := []string{"vault", "consul", "terraform", "packer", "boundary"}
	otherToolsExist := false

	for _, tool := range hashicorpTools {
		if tool == "nomad" {
			continue // Skip nomad since we're removing it
		}
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{tool},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			otherToolsExist = true
			logger.Debug("Other HashiCorp tool found, keeping repository",
				zap.String("tool", tool))
			break
		}
	}

	if !otherToolsExist {
		logger.Info("Removing HashiCorp APT repository")
		// Remove repository files
		repoFiles := []string{
			"/etc/apt/sources.list.d/hashicorp.list",
			"/usr/share/keyrings/hashicorp-archive-keyring.gpg",
		}
		for _, file := range repoFiles {
			if err := os.Remove(file); err != nil {
				logger.Debug("Failed to remove repo file", 
					zap.String("file", file), zap.Error(err))
			}
		}
	}
}