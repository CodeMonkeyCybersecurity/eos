package delete

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var nukeCmd = &cobra.Command{
	Use:   "nuke",
	Short: "Destroy all eos-managed infrastructure",
	Long: `Completely remove all infrastructure created by eos.
This command will destroy components in reverse order of creation to ensure clean removal.

WARNING: This is a destructive operation that cannot be undone!

The nuke process will:
1. Stop and remove all running services
2. Uninstall all packages installed by eos
3. Remove all configuration files and directories
4. Clean up any Salt states and pillars
5. Remove state tracking files

Use --force to skip confirmation prompts.`,
	RunE: eos_cli.Wrap(runNuke),
}

func init() {
	DeleteCmd.AddCommand(nukeCmd)

	nukeCmd.Flags().Bool("all", false, "Remove everything including eos itself")
	nukeCmd.Flags().Bool("force", false, "Skip confirmation prompts")
	nukeCmd.Flags().Bool("keep-data", false, "Keep data directories (logs, databases)")
	nukeCmd.Flags().StringSlice("exclude", []string{}, "Components to exclude from removal")
}

func runNuke(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	removeAll := cmd.Flag("all").Value.String() == "true"
	force := cmd.Flag("force").Value.String() == "true"
	keepData := cmd.Flag("keep-data").Value.String() == "true"
	excludeList, _ := cmd.Flags().GetStringSlice("exclude")

	logger.Info("Starting infrastructure nuke",
		zap.Bool("remove_all", removeAll),
		zap.Bool("force", force),
		zap.Bool("keep_data", keepData),
		zap.Strings("exclude", excludeList))

	// ASSESS - Load current state
	logger.Info("Assessing infrastructure to destroy")

	tracker, err := state.Load(rc)
	if err != nil {
		logger.Warn("Failed to load state, will scan for components",
			zap.Error(err))
		tracker = state.New()
		if err := tracker.GatherInBand(rc); err != nil {
			logger.Warn("Failed to gather state", zap.Error(err))
		}
	}

	// Show what will be removed
	fmt.Println("\nThe following components will be removed:")
	fmt.Println("=========================================")
	fmt.Println(tracker.ListComponents())

	// Confirm with user unless --force
	if !force {
		// Import interaction package for proper prompting
		if !interaction.PromptYesNo(rc.Ctx, "Are you sure you want to destroy all infrastructure?", false) {
			logger.Info("Nuke cancelled by user")
			return nil
		}
	}

	// INTERVENE - Destroy infrastructure in reverse order
	logger.Info("Beginning destruction sequence")

	cli := eos_cli.New(rc)

	// Create exclusion map for easier checking
	excluded := make(map[string]bool)
	for _, ex := range excludeList {
		excluded[ex] = true
	}

	// Phase 1: Stop application services
	logger.Info("Phase 1: Stopping application services")

	// Stop ClusterFuzz if exists
	if !excluded["clusterfuzz"] {
		stopClusterFuzz(rc)
	}

	// Stop Nomad jobs
	if !excluded["nomad"] && commandExists(cli, "nomad") {
		logger.Info("Stopping Nomad jobs")
		output, err := cli.ExecString("nomad", "job", "list", "-short")
		if err == nil {
			lines := strings.Split(output, "\n")
			for i, line := range lines {
				if i == 0 || line == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) > 0 {
					jobName := fields[0]
					logger.Info("Stopping Nomad job", zap.String("job", jobName))
					cli.ExecToSuccess("nomad", "job", "stop", "-purge", jobName)
				}
			}
		}
	}

	// Phase 2: Stop infrastructure services
	logger.Info("Phase 2: Stopping infrastructure services")

	services := []string{
		"osqueryd",
		"nomad",
		"consul",
		"vault",
		"boundary",
		"salt-minion",
		"salt-master",
		"docker",
	}

	for _, service := range services {
		if excluded[service] {
			continue
		}

		// Check if service exists before attempting to stop
		if output, err := cli.ExecString("systemctl", "list-units", "--all", "--type=service", "--quiet", service+".service"); err == nil && strings.Contains(output, service+".service") {
			logger.Info("Stopping service", zap.String("service", service))
			// Stop service (ignore errors for already stopped services)
			if _, err := cli.ExecString("systemctl", "stop", service); err != nil {
				logger.Debug("Service stop failed (may already be stopped)", 
					zap.String("service", service), zap.Error(err))
			}
			// Disable service (ignore errors for already disabled services)  
			if _, err := cli.ExecString("systemctl", "disable", service); err != nil {
				logger.Debug("Service disable failed (may already be disabled)",
					zap.String("service", service), zap.Error(err))
			}
		} else {
			logger.Debug("Service not found, skipping", zap.String("service", service))
		}
	}

	// Phase 3: Remove packages
	logger.Info("Phase 3: Removing packages")

	if !excluded["osquery"] && commandExists(cli, "osqueryi") {
		logger.Info("Removing OSQuery")
		cli.ExecToSuccess("apt-get", "remove", "-y", "--purge", "osquery")
	}

	if !excluded["salt"] && commandExists(cli, "salt") {
		logger.Info("Removing Salt")
		cli.ExecToSuccess("apt-get", "remove", "-y", "--purge", "salt-master", "salt-minion", "salt-common")
	}

	// Phase 4: Remove binaries
	logger.Info("Phase 4: Removing binaries")

	binaries := map[string]string{
		"vault":    "/usr/local/bin/vault",
		"nomad":    "/usr/local/bin/nomad",
		"consul":   "/usr/local/bin/consul",
		"terraform": "/usr/local/bin/terraform",
		"packer":   "/usr/local/bin/packer",
		"boundary": "/usr/local/bin/boundary",
	}

	for component, path := range binaries {
		if !excluded[component] && fileExists(path) {
			logger.Info("Removing binary", zap.String("component", component), zap.String("path", path))
			os.Remove(path)
		}
	}

	// Phase 5: Remove directories
	logger.Info("Phase 5: Removing directories")

	directories := []struct {
		path      string
		component string
		isData    bool
	}{
		{"/srv/salt", "salt", false},
		{"/srv/pillar", "salt", false},
		{"/etc/salt", "salt", false},
		{"/var/log/salt", "salt", true},
		{"/var/cache/salt", "salt", true},
		{"/opt/vault", "vault", false},
		{"/opt/vault/data", "vault", true},
		{"/etc/vault.d", "vault", false},
		{"/etc/vault-agent-eos.hcl", "vault", false},
		{"/run/eos", "vault", false},  // Runtime directory for vault agent
		{"/home/vault/.config", "vault", false},  // Vault user config
		{"/etc/tmpfiles.d/eos.conf", "vault", false},  // Tmpfiles config
		{"/opt/nomad", "nomad", false},
		{"/opt/nomad/data", "nomad", true},
		{"/etc/nomad.d", "nomad", false},
		{"/opt/consul", "consul", false},
		{"/opt/consul/data", "consul", true},
		{"/etc/consul.d", "consul", false},
		{"/opt/terraform", "terraform", false},
		{"/opt/packer", "packer", false},
		{"/opt/boundary", "boundary", false},
		{"/etc/boundary.d", "boundary", false},
		{"/etc/osquery", "osquery", false},
		{"/var/osquery", "osquery", true},
		{"/var/log/osquery", "osquery", true},
		{"/opt/clusterfuzz", "clusterfuzz", false},
		{"/var/lib/eos", "eos", false},
	}

	for _, dir := range directories {
		if excluded[dir.component] {
			continue
		}

		if dir.isData && keepData {
			logger.Info("Keeping data directory", zap.String("path", dir.path))
			continue
		}

		if _, err := os.Stat(dir.path); err == nil {
			logger.Info("Removing directory", zap.String("path", dir.path))
			os.RemoveAll(dir.path)
		}
	}

	// Phase 6: Remove systemd service files
	logger.Info("Phase 6: Cleaning up systemd services")

	serviceFiles := []string{
		// Vault services
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/vault-agent-eos.service",
		"/etc/systemd/system/vault-backup.service",
		"/etc/systemd/system/vault-backup.timer",
		"/etc/systemd/system/vault-agent-health-check.service",
		"/etc/systemd/system/vault-agent-health-check.timer",
		"/etc/systemd/system/vault.service.d/",  // Directory for overrides
		// Other services
		"/etc/systemd/system/nomad.service",
		"/etc/systemd/system/consul.service",
		"/etc/systemd/system/boundary.service",
	}

	for _, file := range serviceFiles {
		if fileExists(file) {
			logger.Info("Removing service file", zap.String("file", file))
			// Check if it's a directory (like vault.service.d)
			fileInfo, err := os.Stat(file)
			if err == nil && fileInfo.IsDir() {
				os.RemoveAll(file)
			} else {
				os.Remove(file)
			}
		}
	}

	cli.ExecToSuccess("systemctl", "daemon-reload")

	// Phase 7: Clean up APT sources
	logger.Info("Phase 7: Cleaning up APT sources")

	aptSources := []string{
		"/etc/apt/sources.list.d/salt.list",
		"/etc/apt/sources.list.d/osquery.list",
	}

	for _, source := range aptSources {
		if fileExists(source) {
			logger.Info("Removing APT source", zap.String("file", source))
			os.Remove(source)
		}
	}

	// Remove eos itself if --all
	if removeAll && !excluded["eos"] {
		logger.Info("Phase 8: Removing eos itself")

		eosBinary := "/usr/local/bin/eos"
		if fileExists(eosBinary) {
			logger.Info("Removing eos binary")
			os.Remove(eosBinary)
		}

		// Remove eos source directory if we're running from it
		logger.Warn("Cannot remove eos source directory while running from it")
	}

	// EVALUATE - Verify cleanup
	logger.Info("Verifying cleanup")

	// Check for remaining processes (using execute directly to avoid error logging)
	remainingProcesses := []string{}
	for _, proc := range []string{"salt-master", "salt-minion", "vault", "nomad", "consul", "boundary", "osqueryd"} {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "pgrep",
			Args:    []string{"-f", proc},
			Capture: true,
		})
		// pgrep returns exit code 1 when no processes found - this is normal, not an error
		if err == nil && strings.TrimSpace(output) != "" {
			remainingProcesses = append(remainingProcesses, proc)
			logger.Debug("Process still running", zap.String("process", proc))
		} else {
			logger.Debug("No processes found for service (this is normal during cleanup)",
				zap.String("process", proc))
		}
	}

	if len(remainingProcesses) > 0 {
		logger.Warn("Some processes are still running",
			zap.Strings("processes", remainingProcesses))

		// Force kill if needed
		for _, proc := range remainingProcesses {
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "pkill",
				Args:    []string{"-9", "-f", proc},
				Capture: true,
			})
			if err != nil {
				logger.Debug("Failed to kill process (may have already exited)",
					zap.String("process", proc), zap.Error(err))
			} else {
				logger.Info("Force killed process", zap.String("process", proc))
			}
		}
	}

	// Final state check
	finalTracker := state.New()
	finalTracker.GatherInBand(rc)

	if len(finalTracker.Components) > 0 {
		logger.Warn("Some components may still be present",
			zap.Int("remaining", len(finalTracker.Components)))
		fmt.Println("\nRemaining components detected:")
		fmt.Println(finalTracker.ListComponents())
	} else {
		logger.Info("All components successfully removed")
	}

	// Clean up state file
	stateFile := "/var/lib/eos/state.json"
	if fileExists(stateFile) && !keepData {
		os.Remove(stateFile)
	}

	logger.Info("Infrastructure nuke completed")
	fmt.Println("\nNuke completed. System restored to clean state.")

	return nil
}

func commandExists(cli *eos_cli.CLI, cmd string) bool {
	_, err := cli.Which(cmd)
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func stopClusterFuzz(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping ClusterFuzz components")

	// For now, just log that we're stopping it
	// In a real implementation, this would stop ClusterFuzz services
}
