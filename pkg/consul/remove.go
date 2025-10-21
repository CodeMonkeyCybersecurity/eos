// pkg/consul/remove.go

package consul

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveConsul performs complete removal of Consul from the system
func RemoveConsul(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul removal process")

	// ASSESS - Check current state
	clusterInfo, err := assessConsulState(rc)
	if err != nil {
		logger.Info("Consul assessment completed", zap.Error(err))
	}

	// INTERVENE - Perform removal steps

	// 1. Gracefully leave cluster if part of one
	if clusterInfo != nil && clusterInfo.IsInCluster {
		logger.Info("Detected Consul cluster membership - attempting graceful leave",
			zap.Int("cluster_members", clusterInfo.MemberCount))
		if err := gracefullyLeaveCluster(rc); err != nil {
			logger.Warn("Failed to gracefully leave cluster - continuing with forced removal",
				zap.Error(err),
				zap.String("remediation", "Other cluster members may need manual intervention"))
		}
	}

	// 2. Stop the service
	if err := stopConsulService(rc); err != nil {
		logger.Warn("Failed to stop Consul service", zap.Error(err))
		// Continue with removal even if stop fails
	}

	// 3. Remove package
	if err := removeConsulPackage(rc); err != nil {
		return fmt.Errorf("failed to remove Consul package: %w", err)
	}

	// 4. Cleanup all files
	if err := cleanupConsulFiles(rc); err != nil {
		return fmt.Errorf("failed to cleanup Consul files: %w", err)
	}

	// 5. Remove CA files and Consul KV entries (if created by Vault)
	if err := cleanupCAFiles(rc); err != nil {
		logger.Warn("Failed to cleanup CA files (may not exist)", zap.Error(err))
		// Not critical if CA wasn't used
	}

	// 6. Remove systemd timers (if created by Vault cert renewal)
	if err := cleanupSystemdTimers(rc); err != nil {
		logger.Warn("Failed to cleanup systemd timers (may not exist)", zap.Error(err))
		// Not critical if timers weren't created
	}

	// 7. Remove consul user
	if err := removeConsulUser(rc); err != nil {
		logger.Warn("Failed to remove Consul user", zap.Error(err))
		// Not critical, continue
	}

	// EVALUATE - Verify removal
	if err := verifyConsulRemoval(rc); err != nil {
		return fmt.Errorf("Consul removal verification failed: %w", err)
	}

	logger.Info("Consul removal completed successfully")
	return nil
}

// ClusterInfo holds information about Consul cluster membership
type ClusterInfo struct {
	IsInCluster bool
	MemberCount int
	IsServer    bool
	IsLeader    bool
}

func assessConsulState(rc *eos_io.RuntimeContext) (*ClusterInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing current Consul installation state")

	clusterInfo := &ClusterInfo{
		IsInCluster: false,
		MemberCount: 0,
		IsServer:    false,
		IsLeader:    false,
	}

	// Check if Consul binary exists
	if _, err := exec.LookPath("consul"); err != nil {
		logger.Info("Consul binary not found in PATH")
		return clusterInfo, nil
	}
	logger.Info("Consul binary found")

	// Check if service is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Info("Consul service is not active")
		return clusterInfo, nil
	}
	logger.Info("Consul service is currently active",
		zap.String("status", strings.TrimSpace(output)))

	// Try to get cluster membership info
	client, err := api.NewClient(api.DefaultConfig())
	if err == nil {
		members, err := client.Agent().Members(false)
		if err == nil && len(members) > 0 {
			clusterInfo.IsInCluster = len(members) > 1 // More than just this node
			clusterInfo.MemberCount = len(members)

			// Check if this node is a server
			nodeName, err := client.Agent().NodeName()
			if err == nil {
				for _, member := range members {
					if member.Name == nodeName {
						if tags, ok := member.Tags["role"]; ok && tags == "consul" {
							clusterInfo.IsServer = true
						}
					}
				}
			}

			logger.Info("Detected Consul cluster configuration",
				zap.Int("total_members", clusterInfo.MemberCount),
				zap.Bool("is_server", clusterInfo.IsServer),
				zap.Bool("in_cluster", clusterInfo.IsInCluster))
		}
	}

	// Check for existing data directories
	dataDirs := []string{
		"/etc/consul.d",
		"/var/lib/consul",
		"/var/log/consul",
		"/var/lib/consul/raft", // Explicitly check for Raft data
	}

	for _, dir := range dataDirs {
		if info, err := os.Stat(dir); err == nil {
			logger.Info("Found Consul directory",
				zap.String("path", dir),
				zap.Bool("is_dir", info.IsDir()))
		}
	}

	return clusterInfo, nil
}

func gracefullyLeaveCluster(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting graceful cluster leave")

	// Use consul leave command for graceful departure
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"leave"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})

	if err != nil {
		return fmt.Errorf("graceful leave failed: %s\n"+
			"Remediation: Other cluster members may show this node as failed\n"+
			"  Run 'consul force-leave <node-name>' on remaining cluster members if needed",
			output)
	}

	logger.Info("Successfully left Consul cluster gracefully")
	return nil
}

func stopConsulService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Stopping Consul service")

	// Stop the service
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Warn("Failed to stop Consul service",
			zap.Error(err),
			zap.String("output", output),
			zap.String("remediation", "Try manually: sudo systemctl stop consul"))
	}

	// Disable the service
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"disable", "consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Warn("Failed to disable Consul service",
			zap.Error(err),
			zap.String("output", output))
	}

	// Kill any remaining consul processes - be very specific to avoid killing wrong processes
	// Only target actual consul agent processes, not other tools
	logger.Debug("Checking for remaining Consul agent processes")
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-9", "-f", "consul agent"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Debug("No Consul agent processes to kill (expected if clean shutdown)",
			zap.String("output", output))
	} else {
		logger.Info("Killed remaining Consul agent processes")
	}

	return nil
}

func removeConsulPackage(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Removing Consul package")

	// Try to remove via apt
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"remove", "--purge", "-y", "consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Debug("Package removal output (package may not be installed via apt)",
			zap.String("output", output))
		// Package might not be installed via apt, continue
	} else {
		logger.Info("Successfully removed Consul package via apt-get")
	}

	// Remove the binary if it still exists
	consulPaths := []string{
		"/usr/bin/consul",
		"/usr/local/bin/consul",
	}

	for _, path := range consulPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove Consul binary",
				zap.String("path", path),
				zap.Error(err),
				zap.String("remediation", fmt.Sprintf("Try manually: sudo rm -f %s", path)))
		} else if err == nil {
			logger.Info("Removed Consul binary", zap.String("path", path))
		}
	}

	return nil
}

func cleanupConsulFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Cleaning up Consul files and directories")

	// Directories to remove - includes Raft data, snapshots, and lock files
	dirsToRemove := []string{
		"/etc/consul.d",
		"/etc/consul",
		"/var/lib/consul",
		"/var/lib/consul/raft",      // P0: Explicitly remove Raft data
		"/var/lib/consul/snapshots", // Remove auto-snapshots
		"/var/log/consul",
		"/var/lock/consul", // Remove lock files
		"/opt/consul",
	}

	for _, dir := range dirsToRemove {
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove directory",
				zap.String("path", dir),
				zap.Error(err),
				zap.String("remediation", fmt.Sprintf("Try manually: sudo rm -rf %s", dir)))
		} else if err == nil {
			logger.Info("Removed directory", zap.String("path", dir))
		}
	}

	// Remove systemd service files
	serviceFiles := []string{
		"/etc/systemd/system/consul.service",
		"/lib/systemd/system/consul.service",
	}

	for _, file := range serviceFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove service file",
				zap.String("path", file),
				zap.Error(err))
		} else if err == nil {
			logger.Info("Removed service file", zap.String("path", file))
		}
	}

	// Reload systemd
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Warn("Failed to reload systemd",
			zap.Error(err),
			zap.String("output", output))
	}

	// Clean up any consul-related files in home directories
	if err := cleanupHomeDirectories(rc); err != nil {
		logger.Warn("Failed to cleanup home directories", zap.Error(err))
	}

	return nil
}

func cleanupHomeDirectories(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Common locations for consul configs in home directories
	homePatterns := []string{
		"/root/.consul",
		"/root/.consul.d",
		"/home/*/.consul",
		"/home/*/.consul.d",
	}

	for _, pattern := range homePatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, match := range matches {
			if err := os.RemoveAll(match); err != nil {
				logger.Warn("Failed to remove user consul directory",
					zap.String("path", match),
					zap.Error(err))
			} else {
				logger.Info("Removed user consul directory", zap.String("path", match))
			}
		}
	}

	return nil
}

// P0 FIX: cleanupCAFiles removes internal CA files created during Vault installation
func cleanupCAFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Cleaning up internal CA files (if they exist)")

	// Remove CA files from filesystem
	caFiles := []string{
		"/opt/vault/ca/ca.crt",
		"/opt/vault/ca/ca.key",
		"/opt/vault/ca",
		"/usr/local/share/ca-certificates/code-monkey-internal-ca.crt",
	}

	for _, file := range caFiles {
		if err := os.RemoveAll(file); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove CA file",
				zap.String("path", file),
				zap.Error(err))
		} else if err == nil {
			logger.Info("Removed CA file", zap.String("path", file))
		}
	}

	// Update system trust store if CA certificate was removed
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "update-ca-certificates",
		Args:    []string{},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Warn("Failed to update CA certificates",
			zap.Error(err),
			zap.String("output", output))
	} else {
		logger.Info("Updated system CA certificate store")
	}

	// Remove CA entries from Consul KV (if Consul is still accessible)
	// This will fail if Consul is already stopped, which is fine
	client, err := api.NewClient(api.DefaultConfig())
	if err == nil {
		kvKeys := []string{
			"eos/ca/", // Delete entire CA tree for all datacenters
		}

		for _, key := range kvKeys {
			_, err := client.KV().DeleteTree(key, nil)
			if err != nil {
				logger.Debug("Failed to delete CA from Consul KV (expected if Consul stopped)",
					zap.String("key", key),
					zap.Error(err))
			} else {
				logger.Info("Removed CA data from Consul KV", zap.String("key", key))
			}
		}
	}

	return nil
}

// P0 FIX: cleanupSystemdTimers removes cert renewal timers created during Vault installation
func cleanupSystemdTimers(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Cleaning up systemd cert renewal timers (if they exist)")

	// Stop and disable the timer first
	timerFiles := []string{
		"vault-cert-renewal.timer",
		"vault-cert-renewal.service",
	}

	for _, unit := range timerFiles {
		// Stop the unit
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", unit},
			Capture: true,
			Logger:  logger.ZapLogger(),
		})
		if err != nil {
			logger.Debug("Failed to stop systemd unit (may not exist)",
				zap.String("unit", unit),
				zap.String("output", output))
		}

		// Disable the unit
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"disable", unit},
			Capture: true,
			Logger:  logger.ZapLogger(),
		})
		if err != nil {
			logger.Debug("Failed to disable systemd unit (may not exist)",
				zap.String("unit", unit),
				zap.String("output", output))
		}
	}

	// Remove systemd unit files
	unitFilePaths := []string{
		"/etc/systemd/system/vault-cert-renewal.timer",
		"/etc/systemd/system/vault-cert-renewal.service",
	}

	for _, path := range unitFilePaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove systemd unit file",
				zap.String("path", path),
				zap.Error(err))
		} else if err == nil {
			logger.Info("Removed systemd unit file", zap.String("path", path))
		}
	}

	// Reload systemd daemon
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Warn("Failed to reload systemd daemon",
			zap.Error(err),
			zap.String("output", output))
	} else {
		logger.Info("Reloaded systemd daemon")
	}

	return nil
}

func removeConsulUser(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Removing Consul user and group")

	// Remove the consul user (this will also remove the primary group)
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "userdel",
		Args:    []string{"-r", "consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Debug("Failed to remove consul user (may not exist)",
			zap.Error(err),
			zap.String("output", output))
		// User might not exist, not critical
	} else {
		logger.Info("Successfully removed consul user")
	}

	// Ensure the group is also removed
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "groupdel",
		Args:    []string{"consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err != nil {
		logger.Debug("Failed to remove consul group (may not exist or already removed with user)",
			zap.Error(err),
			zap.String("output", output))
		// Group might not exist or be removed with user, not critical
	} else {
		logger.Info("Successfully removed consul group")
	}

	return nil
}

func verifyConsulRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying Consul removal")

	issues := []string{}

	// Check if binary still exists
	if _, err := exec.LookPath("consul"); err == nil {
		issues = append(issues, "Consul binary still exists in PATH")
	}

	// Check if service still exists
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "consul.service"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err == nil && strings.Contains(output, "consul.service") {
		issues = append(issues, "Consul service file still exists")
	}

	// Check if cert renewal timers still exist (P0)
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-unit-files", "vault-cert-renewal.*"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err == nil && strings.Contains(output, "vault-cert-renewal") {
		issues = append(issues, "Vault cert renewal timer still exists")
	}

	// Check if directories still exist
	dirsToCheck := []string{
		"/etc/consul.d",
		"/var/lib/consul",
		"/var/log/consul",
		"/var/lib/consul/raft", // P0: Verify Raft data removed
		"/opt/vault/ca",        // P0: Verify CA files removed
	}

	for _, dir := range dirsToCheck {
		if _, err := os.Stat(dir); err == nil {
			issues = append(issues, fmt.Sprintf("Directory still exists: %s", dir))
		}
	}

	// Check if CA certificate still in system trust store (P0)
	if _, err := os.Stat("/usr/local/share/ca-certificates/code-monkey-internal-ca.crt"); err == nil {
		issues = append(issues, "Internal CA certificate still in system trust store")
	}

	// Check if user still exists
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "id",
		Args:    []string{"consul"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err == nil {
		issues = append(issues, "Consul user still exists")
	}

	// Check for lingering processes
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "consul agent"},
		Capture: true,
		Logger:  logger.ZapLogger(),
	})
	if err == nil && strings.TrimSpace(output) != "" {
		issues = append(issues, "Consul agent processes still running")
	}

	if len(issues) > 0 {
		logger.Warn("Consul removal verification found issues",
			zap.Strings("issues", issues))
		return fmt.Errorf("removal incomplete: %d issues found\n"+
			"Remediation:\n"+
			"  1. Check issues above\n"+
			"  2. Manually clean up remaining items\n"+
			"  3. Run 'eos delete consul --force' to retry",
			len(issues))
	}

	logger.Info("Consul removal verified - all components successfully removed")
	return nil
}
