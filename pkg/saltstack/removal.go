package saltstack

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveSaltCompletely removes SaltStack using comprehensive direct removal
func RemoveSaltCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive SaltStack removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Salt state
	saltState := assessSaltState(rc)
	logger.Info("Salt assessment completed",
		zap.Bool("master_exists", saltState.MasterExists),
		zap.Bool("minion_exists", saltState.MinionExists),
		zap.Bool("api_accessible", saltState.APIAccessible),
		zap.Int("states", len(saltState.States)))

	// INTERVENE - Remove Salt components
	if err := removeSaltComponents(rc, saltState, keepData); err != nil {
		return fmt.Errorf("failed to remove Salt components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifySaltRemoval(rc); err != nil {
		logger.Warn("Salt removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("SaltStack removal completed successfully")
	return nil
}

// SaltState represents the current state of Salt installation
type SaltState struct {
	MasterExists   bool
	MinionExists   bool
	APIAccessible  bool
	States         []string
	Pillars        []string
	DataDirs       []string
	ConfigFiles    []string
	InstalledPkgs  []string
}

// assessSaltState checks the current state of Salt installation
func assessSaltState(rc *eos_io.RuntimeContext) *SaltState {
	state := &SaltState{}

	// Check if Salt binaries exist
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-master"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil {
		state.MasterExists = true
	}

	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-minion"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil {
		state.MinionExists = true
	}

	// Check if Salt API is accessible (for masterless mode)
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()
	if output, err := execute.Run(ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "test.ping"},
		Capture: true,
	}); err == nil && output != "" {
		state.APIAccessible = true

		// Get states
		if statesOutput, err := execute.Run(ctx, execute.Options{
			Command: "salt-call",
			Args:    []string{"--local", "state.show_top"},
			Capture: true,
		}); err == nil {
			state.States = parseSaltStates(statesOutput)
		}
	}

	// Check for installed packages
	packages := []string{"salt-master", "salt-minion", "salt-common", "salt-api", "salt-cloud", "salt-ssh", "salt-syndic"}
	for _, pkg := range packages {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-l", pkg},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			state.InstalledPkgs = append(state.InstalledPkgs, pkg)
		}
	}

	// Check for data directories
	dataDirs := []string{
		"/srv/salt",
		"/srv/pillar",
		"/etc/salt",
		"/var/log/salt",
		"/var/cache/salt",
		"/var/run/salt",
		"/opt/saltstack",
	}
	for _, dir := range dataDirs {
		if _, err := os.Stat(dir); err == nil {
			state.DataDirs = append(state.DataDirs, dir)
		}
	}

	// Check for config files
	configFiles := []string{
		"/etc/salt/master",
		"/etc/salt/minion",
		"/etc/salt/master.d",
		"/etc/salt/minion.d",
		"/etc/systemd/system/salt-master.service",
		"/etc/systemd/system/salt-minion.service",
		"/usr/bin/salt",
		"/usr/bin/salt-call",
		"/usr/bin/salt-key",
		"/usr/bin/salt-run",
		"/usr/bin/salt-master",
		"/usr/bin/salt-minion",
	}
	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			state.ConfigFiles = append(state.ConfigFiles, file)
		}
	}

	return state
}

// removeSaltComponents removes all Salt components based on current state
func removeSaltComponents(rc *eos_io.RuntimeContext, state *SaltState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Stop Salt services
	services := []string{"salt-master", "salt-minion", "salt-api", "salt-syndic"}
	for _, service := range services {
		// Check if service exists first
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"list-unit-files", "--no-pager", service + ".service"},
			Capture: true,
			Timeout: 5 * time.Second,
		}); err == nil && output != "" {
			logger.Info("Stopping Salt service", zap.String("service", service))
			// Stop service
			execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"stop", service},
				Timeout: 30 * time.Second,
			})
			// Disable service
			execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"disable", service},
				Timeout: 10 * time.Second,
			})
		}
	}

	// Kill any remaining Salt processes
	saltProcesses := []string{"salt-master", "salt-minion", "salt-api", "salt-syndic", "salt-cloud", "salt-ssh"}
	for _, proc := range saltProcesses {
		execute.Run(rc.Ctx, execute.Options{
			Command: "pkill",
			Args:    []string{"-TERM", "-f", proc},
			Timeout: 5 * time.Second,
		})
	}
	time.Sleep(2 * time.Second)
	for _, proc := range saltProcesses {
		execute.Run(rc.Ctx, execute.Options{
			Command: "pkill",
			Args:    []string{"-KILL", "-f", proc},
			Timeout: 5 * time.Second,
		})
	}

	// Remove Salt packages
	if len(state.InstalledPkgs) > 0 {
		logger.Info("Removing Salt packages", zap.Strings("packages", state.InstalledPkgs))
		args := append([]string{"remove", "--purge", "-y"}, state.InstalledPkgs...)
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    args,
			Capture: true,
			Timeout: 120 * time.Second,
		})
		if err != nil {
			logger.Warn("Failed to remove some Salt packages", 
				zap.Error(err), 
				zap.String("output", output))
		}
		
		// Clean up package cache
		execute.Run(rc.Ctx, execute.Options{
			Command: "apt-get",
			Args:    []string{"autoremove", "-y"},
			Timeout: 60 * time.Second,
		})
	}

	// Remove binaries and config files
	logger.Info("Removing Salt binaries and configs")
	for _, file := range state.ConfigFiles {
		// Skip directories for now
		if info, err := os.Stat(file); err == nil && info.IsDir() {
			continue
		}
		if err := os.Remove(file); err != nil {
			logger.Debug("Failed to remove file", zap.String("file", file), zap.Error(err))
		}
	}

	// Remove directories
	if !keepData {
		logger.Info("Removing Salt directories")
		for _, dir := range state.DataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	} else {
		logger.Info("Keeping Salt data directories as requested")
		// Still remove non-data directories
		nonDataDirs := []string{"/etc/salt", "/opt/saltstack"}
		for _, dir := range nonDataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Debug("Failed to remove directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	}

	// Remove Salt repository
	logger.Info("Removing Salt APT repository")
	repoFiles := []string{
		"/etc/apt/sources.list.d/salt.list",
		"/etc/apt/sources.list.d/saltstack.list",
		"/usr/share/keyrings/salt-archive-keyring.gpg",
	}
	for _, file := range repoFiles {
		if err := os.Remove(file); err != nil {
			logger.Debug("Failed to remove repo file", 
				zap.String("file", file), zap.Error(err))
		}
	}

	// Update APT cache after removing repository
	execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
		Timeout: 60 * time.Second,
	})

	// Remove salt user and group if they exist
	logger.Info("Removing salt user and group")
	execute.Run(rc.Ctx, execute.Options{
		Command: "userdel",
		Args:    []string{"salt"},
		Timeout: 5 * time.Second,
	})
	execute.Run(rc.Ctx, execute.Options{
		Command: "groupdel",
		Args:    []string{"salt"},
		Timeout: 5 * time.Second,
	})

	// Reload systemd
	execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Timeout: 10 * time.Second,
	})

	return nil
}

// verifySaltRemoval checks if Salt was properly removed
func verifySaltRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Salt removal")

	issues := []string{}

	// Check if binaries still exist
	saltBinaries := []string{"salt", "salt-call", "salt-key", "salt-master", "salt-minion"}
	for _, binary := range saltBinaries {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{binary},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			issues = append(issues, fmt.Sprintf("%s binary still found in PATH", binary))
		}
	}

	// Check if services still exist
	services := []string{"salt-master", "salt-minion", "salt-api", "salt-syndic"}
	for _, service := range services {
		if output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"list-unit-files", "--no-pager", service + ".service"},
			Capture: true,
			Timeout: 5 * time.Second,
		}); err == nil && output != "" {
			issues = append(issues, fmt.Sprintf("%s service unit file still exists", service))
		}
	}

	// Check if processes still running
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "salt"},
		Capture: true,
		Timeout: 2 * time.Second,
	}); err == nil && output != "" {
		issues = append(issues, "Salt processes still running")
	}

	// Check directories
	remainingDirs := []string{}
	for _, dir := range []string{"/srv/salt", "/etc/salt", "/opt/saltstack"} {
		if _, err := os.Stat(dir); err == nil {
			remainingDirs = append(remainingDirs, dir)
		}
	}
	if len(remainingDirs) > 0 {
		issues = append(issues, fmt.Sprintf("Directories still exist: %v", remainingDirs))
	}

	// Check if packages still installed
	for _, pkg := range []string{"salt-common", "salt-master", "salt-minion"} {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "dpkg",
			Args:    []string{"-l", pkg},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			issues = append(issues, fmt.Sprintf("Package %s still installed", pkg))
		}
	}

	if len(issues) > 0 {
		logger.Warn("Salt removal verification found issues",
			zap.Strings("issues", issues))
		return fmt.Errorf("removal incomplete: %d issues found", len(issues))
	}

	logger.Info("Salt removal verification passed")
	return nil
}

// parseSaltStates extracts state names from salt state.show_top output
func parseSaltStates(output string) []string {
	states := []string{}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") {
			state := strings.TrimPrefix(line, "- ")
			states = append(states, state)
		}
	}
	return states
}