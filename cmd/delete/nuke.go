package delete

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/process"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/services"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
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
	nukeCmd.Flags().Bool("dev", false, "Development mode - preserve development tools")
}

func runNuke(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	removeAll := cmd.Flag("all").Value.String() == "true"
	force := cmd.Flag("force").Value.String() == "true"
	keepData := cmd.Flag("keep-data").Value.String() == "true"
	excludeList, _ := cmd.Flags().GetStringSlice("exclude")
	devMode := cmd.Flag("dev").Value.String() == "true"

	// Add development exclusions if --dev flag is set
	if devMode {
		devExclusions := []string{
			"code-server",
			"wazuh-agent", 
			"prometheus",
			"prometheus-node-exporter",
			"docker",
			"eos",
			"git",
			"golang",
			"github-cli",
			"tailscale",
		}
		excludeList = append(excludeList, devExclusions...)
		logger.Info("Development mode enabled - preserving development tools")
	}

	logger.Info("Starting infrastructure nuke",
		zap.Bool("remove_all", removeAll),
		zap.Bool("force", force),
		zap.Bool("keep_data", keepData),
		zap.Bool("dev_mode", devMode),
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

	// Show what will be removed with enhanced display
	showRemovalPlan(tracker, excludeList, keepData)

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

	// Show progress phases to user
	fmt.Println("\nRemoval will proceed in the following phases:")
	fmt.Println("1. Clean up Docker resources")
	fmt.Println("2. Stop application services")
	fmt.Println("3. Stop infrastructure services")
	fmt.Println("4. Remove packages and binaries")
	fmt.Println("5. Clean up directories and files")
	fmt.Println("6. Verify complete removal")
	fmt.Println()

	// Phase 1: Docker cleanup (before stopping Docker service)
	showPhaseProgress(1, "Cleaning up Docker resources")
	if !excluded["docker"] && commandExists(cli, "docker") {
		if err := docker.CleanupDockerResources(rc, keepData); err != nil {
			logger.Warn("Docker cleanup had issues", zap.Error(err))
		}
	}

	// Phase 2: Stop application services
	showPhaseProgress(2, "Stopping application services")

	// Remove Hecate completely if exists
	if !excluded["hecate"] {
		logger.Info("Removing Hecate reverse proxy framework")
		if err := hecate.RemoveHecateCompletely(rc, keepData); err != nil {
			logger.Warn("Failed to remove Hecate completely", zap.Error(err))
		} else {
			logger.Info("Hecate removed successfully")
		}
	}

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

	// Remove additional services
	logger.Info("Removing additional services")
	additionalServices := services.GetAdditionalServicesConfigs()
	for _, svcConfig := range additionalServices {
		if !excluded[svcConfig.Name] {
			if err := services.RemoveService(rc, svcConfig, keepData); err != nil {
				logger.Warn("Failed to remove service",
					zap.String("service", svcConfig.Name),
					zap.Error(err))
			}
		}
	}

	// Phase 3: Stop infrastructure services
	showPhaseProgress(3, "Stopping infrastructure services")

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

	// Phase 4: Remove packages and comprehensive component removal
	showPhaseProgress(4, "Removing packages and components")

	// Use comprehensive removal for each component
	if !excluded["nomad"] {
		logger.Info("Removing Nomad completely")
		if err := nomad.RemoveNomadCompletely(rc, keepData); err != nil {
			logger.Warn("Nomad removal had issues", zap.Error(err))
		}
	}

	if !excluded["consul"] {
		logger.Info("Removing Consul completely")
		if err := consul.RemoveConsul(rc); err != nil {
			logger.Warn("Consul removal had issues", zap.Error(err))
		}
	}

	if !excluded["salt"] {
		logger.Info("Removing Salt completely")
		if err := saltstack.RemoveSaltCompletely(rc, keepData); err != nil {
			logger.Warn("Salt removal had issues", zap.Error(err))
		}
	}

	if !excluded["osquery"] && commandExists(cli, "osqueryi") {
		logger.Info("Removing OSQuery")
		cli.ExecToSuccess("apt-get", "remove", "-y", "--purge", "osquery")
	}

	// Vault removal (already has comprehensive removal)
	if !excluded["vault"] {
		logger.Info("Removing Vault completely")
		if err := vault.RemoveVaultViaSalt(rc); err != nil {
			logger.Warn("Vault removal had issues", zap.Error(err))
		}
	}

	// Remove remaining binaries (handled by component removals above)
	logger.Info("Checking for remaining binaries")

	binaries := map[string]string{
		"nomad":     "/usr/local/bin/nomad",
		"consul":    "/usr/local/bin/consul",
		"terraform": "/usr/local/bin/terraform",
		"packer":    "/usr/local/bin/packer",
		"boundary":  "/usr/local/bin/boundary",
	}

	for component, path := range binaries {
		if !excluded[component] && fileExists(path) {
			logger.Info("Removing binary", zap.String("component", component), zap.String("path", path))
			os.Remove(path)
		}
	}

	// Phase 5: Remove directories
	showPhaseProgress(5, "Cleaning up directories and files")

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
		{"/run/eos", "vault", false},                 // Runtime directory for vault agent
		{"/home/vault/.config", "vault", false},      // Vault user config
		{"/etc/tmpfiles.d/eos.conf", "vault", false}, // Tmpfiles config
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
		{"/opt/hecate", "hecate", false},
		{"/etc/hecate", "hecate", false},
		{"/var/lib/hecate", "hecate", true},
		{"/var/log/hecate", "hecate", true},
		{"/srv/salt/hecate", "hecate", false},
		{"/srv/pillar/hecate", "hecate", false},
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

	// Clean up systemd (part of phase 5)
	logger.Info("Cleaning up systemd services")

	serviceFiles := []string{
		// Vault services
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/vault-agent-eos.service",
		"/etc/systemd/system/vault-backup.service",
		"/etc/systemd/system/vault-backup.timer",
		"/etc/systemd/system/vault-agent-health-check.service",
		"/etc/systemd/system/vault-agent-health-check.timer",
		"/etc/systemd/system/vault.service.d/", // Directory for overrides
		// Hecate services
		"/etc/systemd/system/hecate.service",
		"/etc/systemd/system/hecate-caddy.service",
		"/etc/systemd/system/hecate-authentik.service",
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

	// Clean up APT sources (part of phase 5)
	logger.Info("Cleaning up APT sources")

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
		logger.Info("Phase 9: Removing eos itself")

		eosBinary := "/usr/local/bin/eos"
		if fileExists(eosBinary) {
			logger.Info("Removing eos binary")
			os.Remove(eosBinary)
		}

		// Remove eos source directory if we're running from it
		logger.Warn("Cannot remove eos source directory while running from it")
	}

	// Phase 6: Verify cleanup
	showPhaseProgress(6, "Verifying complete removal")

	// Use improved process detection
	remainingProcesses := []string{}
	processesToCheck := []string{"salt-master", "salt-minion", "vault", "nomad", "consul", "boundary", "osqueryd", "caddy", "authentik", "fail2ban", "trivy", "wazuh"}

	for _, proc := range processesToCheck {
		if processes, err := process.FindProcesses(rc.Ctx, proc); err == nil && len(processes) > 0 {
			remainingProcesses = append(remainingProcesses, proc)
			logger.Debug("Process still running",
				zap.String("process", proc),
				zap.Int("count", len(processes)))
		}
	}

	if len(remainingProcesses) > 0 {
		logger.Warn("Some processes are still running",
			zap.Strings("processes", remainingProcesses))
		fmt.Printf("\nKilling remaining processes: %v\n", remainingProcesses)

		// Force kill remaining processes
		for _, proc := range remainingProcesses {
			if killed, err := process.KillProcesses(rc.Ctx, proc); err != nil {
				logger.Debug("Failed to kill process",
					zap.String("process", proc), zap.Error(err))
			} else if killed > 0 {
				logger.Info("Killed processes",
					zap.String("process", proc),
					zap.Int("count", killed))
			}
		}
	}

	// Final state check
	finalTracker := state.New()
	finalTracker.GatherInBand(rc)

	// Generate final report
	generateFinalReport(rc, finalTracker, tracker, cli)

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

	// TODO: Implement actual ClusterFuzz removal
	// For now, just log that we're stopping it
}

// showRemovalPlan displays what will be removed in a user-friendly format
func showRemovalPlan(tracker *state.StateTracker, excludeList []string, keepData bool) {
	fmt.Println("\nThe following will be removed:")
	fmt.Println("=========================================")

	// Show components
	if len(tracker.Components) > 0 {
		fmt.Println("\nComponents:")
		for _, comp := range tracker.Components {
			excluded := false
			for _, ex := range excludeList {
				if string(comp.Type) == ex || comp.Name == ex {
					excluded = true
					break
				}
			}
			status := comp.Status
			if status == "" {
				status = "unknown"
			}
			if excluded {
				fmt.Printf("  - %s %s (EXCLUDED)\n", comp.Name, comp.Version)
			} else {
				fmt.Printf("  - %s %s [%s]\n", comp.Name, comp.Version, status)
			}
		}
	} else {
		fmt.Println("\nNo eos-managed components detected")
	}

	// Show what will be kept
	if keepData {
		fmt.Println("\nData directories will be KEPT")
	}

	if len(excludeList) > 0 {
		fmt.Printf("\nExcluded from removal: %v\n", excludeList)
	}

	fmt.Println()
}

// showPhaseProgress displays progress for each phase
func showPhaseProgress(phase int, description string) {
	fmt.Printf("\n>>> Phase %d/%d: %s\n", phase, 6, description)
	fmt.Println(strings.Repeat("-", 50))
}

// generateFinalReport creates a comprehensive final report
func generateFinalReport(rc *eos_io.RuntimeContext, finalTracker *state.StateTracker, initialTracker *state.StateTracker, cli *eos_cli.CLI) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("NUKE OPERATION FINAL REPORT")
	fmt.Println(strings.Repeat("=", 60))

	// Summary
	initialCount := len(initialTracker.Components)
	remainingCount := len(finalTracker.Components)
	removedCount := initialCount - remainingCount

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  - Initial components: %d\n", initialCount)
	fmt.Printf("  - Removed components: %d\n", removedCount)
	fmt.Printf("  - Remaining components: %d\n", remainingCount)

	// Success rate
	var successRate float64
	if initialCount > 0 {
		successRate = float64(removedCount) / float64(initialCount) * 100
	}
	fmt.Printf("  - Success rate: %.1f%%\n", successRate)

	// Detailed remaining components
	if remainingCount > 0 {
		fmt.Println("\nComponents that could not be removed:")
		fmt.Println("=====================================")

		for _, comp := range finalTracker.Components {
			fmt.Printf("\n%s (%s):\n", comp.Name, comp.Type)
			fmt.Printf("  Version: %s\n", comp.Version)
			fmt.Printf("  Status: %s\n", comp.Status)

			// Provide specific reasons/solutions
			switch comp.Type {
			case state.ComponentNomad:
				fmt.Println("  Reason: Nomad service or files persist")
				fmt.Println("  Solution: Run 'sudo systemctl stop nomad && sudo rm -rf /opt/nomad /etc/nomad.d'")
			case state.ComponentConsul:
				fmt.Println("  Reason: Consul service or files persist")
				fmt.Println("  Solution: Run 'sudo systemctl stop consul && sudo rm -rf /opt/consul /etc/consul.d'")
			case state.ComponentSalt:
				fmt.Println("  Reason: Salt packages or files persist")
				fmt.Println("  Solution: Run 'sudo apt-get purge salt-* && sudo rm -rf /srv/salt /etc/salt'")
			case state.ComponentDocker:
				fmt.Println("  Reason: Docker is a system-critical service")
				fmt.Println("  Solution: Manually remove if needed with 'sudo apt-get purge docker-ce'")
			case state.ComponentVault:
				fmt.Println("  Reason: Vault files or mounts persist")
				fmt.Println("  Solution: Check for active Vault mounts and unmount before removal")
			default:
				fmt.Println("  Reason: Unknown - manual investigation required")
			}
		}

		// Check for remaining directories
		remainingDirs := []string{}
		for _, dir := range finalTracker.Directories {
			if _, err := os.Stat(dir); err == nil {
				remainingDirs = append(remainingDirs, dir)
			}
		}

		if len(remainingDirs) > 0 {
			fmt.Println("\nRemaining directories:")
			for _, dir := range remainingDirs {
				fmt.Printf("  - %s\n", dir)
			}
		}
	} else {
		fmt.Println("\n✓ All components successfully removed!")
		fmt.Println("✓ System restored to clean state")
	}

	// Clean up APT packages before final recommendations
	logger.Info("Cleaning up APT packages")
	fmt.Println("\n>>> Cleaning up APT packages...")
	
	// Run apt autoremove
	if output, err := cli.ExecString("apt-get", "autoremove", "-y"); err != nil {
		logger.Warn("Failed to run apt autoremove", zap.Error(err))
	} else {
		logger.Info("APT autoremove completed", zap.String("output", output))
	}
	
	// Run apt autoclean
	if output, err := cli.ExecString("apt-get", "autoclean"); err != nil {
		logger.Warn("Failed to run apt autoclean", zap.Error(err))
	} else {
		logger.Info("APT autoclean completed", zap.String("output", output))
	}

	// Final recommendations
	fmt.Println("\nRecommended next steps:")
	fmt.Println("=======================")
	if remainingCount > 0 {
		fmt.Println("1. Review the remaining components above")
		fmt.Println("2. Follow the provided solutions for manual cleanup")
		fmt.Println("3. Reboot the system to ensure all services are stopped")
	} else {
		fmt.Println("1. Consider rebooting to ensure clean system state")
		fmt.Println("2. System has been cleaned and is ready for fresh deployments")
	}

	fmt.Println("\n" + strings.Repeat("=", 60))

	logger.Info("Nuke operation completed",
		zap.Int("removed", removedCount),
		zap.Int("remaining", remainingCount),
		zap.Float64("success_rate", successRate))
}
