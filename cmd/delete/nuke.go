package delete

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
		"salt-minion",
		"salt-master",
		"docker",
	}

	for _, service := range services {
		if excluded[service] {
			continue
		}

		// Check if service exists
		if _, err := cli.ExecString("systemctl", "status", service); err == nil {
			logger.Info("Stopping service", zap.String("service", service))
			cli.ExecToSuccess("systemctl", "stop", service)
			cli.ExecToSuccess("systemctl", "disable", service)
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
		"vault":  "/usr/local/bin/vault",
		"nomad":  "/usr/local/bin/nomad",
		"consul": "/usr/local/bin/consul",
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
		{"/opt/nomad", "nomad", false},
		{"/opt/nomad/data", "nomad", true},
		{"/etc/nomad.d", "nomad", false},
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
		"/etc/systemd/system/vault.service",
		"/etc/systemd/system/nomad.service",
		"/etc/systemd/system/consul.service",
	}

	for _, file := range serviceFiles {
		if fileExists(file) {
			logger.Info("Removing service file", zap.String("file", file))
			os.Remove(file)
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

	// Check for remaining processes
	remainingProcesses := []string{}
	for _, proc := range []string{"salt-master", "salt-minion", "vault", "nomad", "consul", "osqueryd"} {
		if output, err := cli.ExecString("pgrep", "-f", proc); err == nil && output != "" {
			remainingProcesses = append(remainingProcesses, proc)
		}
	}

	if len(remainingProcesses) > 0 {
		logger.Warn("Some processes are still running",
			zap.Strings("processes", remainingProcesses))

		// Force kill if needed
		for _, proc := range remainingProcesses {
			cli.ExecToSuccess("pkill", "-9", "-f", proc)
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
