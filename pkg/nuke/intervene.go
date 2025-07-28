package nuke

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/services"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExecuteRemoval executes the infrastructure removal plan
func ExecuteRemoval(rc *eos_io.RuntimeContext, config *Config, plan *RemovalPlan) ([]PhaseResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Verify we can proceed with removal
	logger.Info("Preparing to execute infrastructure removal")
	
	cli := eos_cli.New(rc)
	excluded := make(map[string]bool)
	for _, ex := range config.ExcludeList {
		excluded[ex] = true
	}

	var results []PhaseResult

	// INTERVENE - Execute removal phases
	logger.Info("Beginning infrastructure destruction sequence")

	// Phase 1: Clean up Docker resources
	phase1 := executePhase1DockerCleanup(rc, cli, excluded, config.KeepData)
	results = append(results, phase1)
	if !phase1.Success {
		logger.Error("Phase 1 failed", zap.Error(phase1.Error))
	}

	// Phase 2: Stop application services
	phase2 := executePhase2ApplicationServices(rc, excluded, config.KeepData)
	results = append(results, phase2)
	if !phase2.Success {
		logger.Error("Phase 2 failed", zap.Error(phase2.Error))
	}

	// Phase 3: Stop infrastructure services
	phase3 := executePhase3InfrastructureServices(rc, cli, plan.Services)
	results = append(results, phase3)
	if !phase3.Success {
		logger.Error("Phase 3 failed", zap.Error(phase3.Error))
	}

	// Phase 4: Remove packages and binaries
	phase4 := executePhase4PackagesAndBinaries(rc, excluded, config.KeepData)
	results = append(results, phase4)
	if !phase4.Success {
		logger.Error("Phase 4 failed", zap.Error(phase4.Error))
	}

	// Phase 5: Clean up directories and files
	phase5 := executePhase5DirectoriesAndFiles(rc, cli, plan.Directories, config.DevMode)
	results = append(results, phase5)
	if !phase5.Success {
		logger.Error("Phase 5 failed", zap.Error(phase5.Error))
	}

	// Phase 6 will be handled in evaluation
	logger.Info("Infrastructure removal phases completed")

	return results, nil
}

// executePhase1DockerCleanup cleans up Docker resources
func executePhase1DockerCleanup(rc *eos_io.RuntimeContext, cli *eos_cli.CLI, excluded map[string]bool, keepData bool) PhaseResult {
	logger := otelzap.Ctx(rc.Ctx)
	
	result := PhaseResult{
		Phase:       1,
		Description: "Clean up Docker resources",
		Details:     make(map[string]interface{}),
	}

	logger.Info("Phase 1: Cleaning up Docker resources")

	if excluded["docker"] {
		logger.Info("Docker excluded from removal")
		result.Success = true
		result.Details["skipped"] = "docker excluded"
		return result
	}

	if !commandExists(cli, "docker") {
		logger.Info("Docker not found, skipping cleanup")
		result.Success = true
		result.Details["skipped"] = "docker not found"
		return result
	}

	if err := docker.CleanupDockerResources(rc, keepData); err != nil {
		logger.Warn("Docker cleanup had issues", zap.Error(err))
		result.Error = err
		result.Details["error"] = err.Error()
	} else {
		result.Success = true
		result.Details["completed"] = "docker resources cleaned"
	}

	return result
}

// executePhase2ApplicationServices stops application services
func executePhase2ApplicationServices(rc *eos_io.RuntimeContext, excluded map[string]bool, keepData bool) PhaseResult {
	logger := otelzap.Ctx(rc.Ctx)
	
	result := PhaseResult{
		Phase:       2,
		Description: "Stop application services",
		Details:     make(map[string]interface{}),
	}

	logger.Info("Phase 2: Stopping application services")

	var errors []string

	// Hecate will be handled through the standard service removal process

	// ClusterFuzz will be handled through the standard service removal process

	// Stop Nomad jobs (this is needed before the comprehensive removal in Phase 4)
	if !excluded["nomad"] {
		if err := stopNomadJobs(rc); err != nil {
			logger.Warn("Failed to stop some Nomad jobs", zap.Error(err))
			errors = append(errors, fmt.Sprintf("nomad jobs: %v", err))
		}
	}

	// TODO: MIGRATE - Additional services removal uses generic service lifecycle manager
	// MIGRATE: This already delegates to pkg/services/removal.go:RemoveService
	// Status: ALREADY MIGRATED - This uses the generic service lifecycle pattern
	// Remove additional services
	if err := removeAdditionalServices(rc, excluded, keepData); err != nil {
		logger.Warn("Failed to remove some additional services", zap.Error(err))
		errors = append(errors, fmt.Sprintf("additional services: %v", err))
	}

	if len(errors) > 0 {
		result.Error = fmt.Errorf("phase 2 had issues: %s", strings.Join(errors, "; "))
		result.Details["errors"] = errors
	} else {
		result.Success = true
		result.Details["completed"] = "application services stopped"
	}

	return result
}

// executePhase3InfrastructureServices stops infrastructure services
func executePhase3InfrastructureServices(rc *eos_io.RuntimeContext, cli *eos_cli.CLI, services []ServiceConfig) PhaseResult {
	logger := otelzap.Ctx(rc.Ctx)
	
	result := PhaseResult{
		Phase:       3,
		Description: "Stop infrastructure services",
		Details:     make(map[string]interface{}),
	}

	logger.Info("Phase 3: Stopping infrastructure services")

	var stopped []string
	var failed []string

	for _, svc := range services {
		if err := stopService(rc, cli, svc.Name); err != nil {
			logger.Debug("Service stop failed", 
				zap.String("service", svc.Name), 
				zap.Error(err))
			failed = append(failed, svc.Name)
		} else {
			stopped = append(stopped, svc.Name)
		}
	}

	result.Details["stopped"] = stopped
	result.Details["failed"] = failed

	if len(failed) > 0 {
		result.Error = fmt.Errorf("failed to stop %d services: %v", len(failed), failed)
	} else {
		result.Success = true
	}

	logger.Info("Infrastructure services phase completed",
		zap.Int("stopped", len(stopped)),
		zap.Int("failed", len(failed)))

	return result
}

// executePhase4PackagesAndBinaries removes packages and binaries
func executePhase4PackagesAndBinaries(rc *eos_io.RuntimeContext, excluded map[string]bool, keepData bool) PhaseResult {
	logger := otelzap.Ctx(rc.Ctx)
	
	result := PhaseResult{
		Phase:       4,
		Description: "Remove packages and binaries",
		Details:     make(map[string]interface{}),
	}

	logger.Info("Phase 4: Removing packages and components")

	var errors []string

	// TODO: MIGRATE - Use comprehensive removal for each component
	// MIGRATE: This should delegate to pkg/nomad/removal.go:RemoveNomadCompletely
	// Status: ALREADY MIGRATED - This is the correct pattern
	if !excluded["nomad"] {
		logger.Info("Removing Nomad completely")
		if err := nomad.RemoveNomadCompletely(rc, keepData); err != nil {
			logger.Warn("Nomad removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("nomad: %v", err))
		}
	}

	// TODO: MIGRATE - Consul removal already properly delegated
	// MIGRATE: This should delegate to pkg/consul/remove.go:RemoveConsul
	// Status: ALREADY MIGRATED - This is the correct pattern
	if !excluded["consul"] {
		logger.Info("Removing Consul completely")
		if err := consul.RemoveConsul(rc); err != nil {
			logger.Warn("Consul removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("consul: %v", err))
		}
	}

	// TODO: MIGRATE - Salt removal already properly delegated
	// MIGRATE: This should delegate to pkg/saltstack/removal.go:RemoveSaltCompletely
	// Status: ALREADY MIGRATED - This is the correct pattern
	if !excluded["salt"] {
		logger.Info("Removing Salt completely")
		if err := saltstack.RemoveSaltCompletely(rc, keepData); err != nil {
			logger.Warn("Salt removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("salt: %v", err))
		}
	}

	// TODO: MIGRATE - Vault removal already properly delegated
	// MIGRATE: This should delegate to pkg/vault/salt_removal.go:RemoveVaultViaSalt
	// Status: ALREADY MIGRATED - This is the correct pattern
	if !excluded["vault"] {
		logger.Info("Removing Vault completely")
		if err := vault.RemoveVaultViaSalt(rc); err != nil {
			logger.Warn("Vault removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("vault: %v", err))
		}
	}

	// Remove osquery using the new lifecycle manager
	if !excluded["osquery"] {
		logger.Info("Removing osquery completely")
		if err := osquery.RemoveOsqueryCompletely(rc, keepData); err != nil {
			logger.Warn("Osquery removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("osquery: %v", err))
		}
	}

	// Remove boundary using the new lifecycle manager
	if !excluded["boundary"] {
		logger.Info("Removing Boundary completely")
		if err := boundary.RemoveBoundaryCompletely(rc, keepData); err != nil {
			logger.Warn("Boundary removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("boundary: %v", err))
		}
	}

	// Remove Docker completely (not just cleanup)
	if !excluded["docker"] {
		logger.Info("Removing Docker completely")
		if err := docker.RemoveDockerCompletely(rc, keepData); err != nil {
			logger.Warn("Docker removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("docker: %v", err))
		}
	}

	// Remove Terraform
	if !excluded["terraform"] {
		logger.Info("Removing Terraform completely")
		if err := terraform.RemoveTerraformCompletely(rc, keepData); err != nil {
			logger.Warn("Terraform removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("terraform: %v", err))
		}
	}

	// Remove Packer
	if !excluded["packer"] {
		logger.Info("Removing Packer completely")
		if err := packer.RemovePackerCompletely(rc, keepData); err != nil {
			logger.Warn("Packer removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("packer: %v", err))
		}
	}

	// Remove Eos resources (but not the binary itself)
	if !excluded["eos"] {
		logger.Info("Removing Eos resources")
		if err := eos.RemoveEosResources(rc, keepData); err != nil {
			logger.Warn("Eos resources removal had issues", zap.Error(err))
			errors = append(errors, fmt.Sprintf("eos: %v", err))
		}
	}

	// Remove remaining binaries - this function is now empty since all binaries
	// are handled by their respective lifecycle managers
	removedBinaries := removeBinaries(rc, excluded)
	result.Details["removed_binaries"] = removedBinaries

	if len(errors) > 0 {
		result.Error = fmt.Errorf("phase 4 had issues: %s", strings.Join(errors, "; "))
		result.Details["errors"] = errors
	} else {
		result.Success = true
		result.Details["completed"] = "packages and binaries removed"
	}

	return result
}

// executePhase5DirectoriesAndFiles cleans up directories and files
func executePhase5DirectoriesAndFiles(rc *eos_io.RuntimeContext, cli *eos_cli.CLI, directories []DirectoryConfig, devMode bool) PhaseResult {
	logger := otelzap.Ctx(rc.Ctx)
	
	result := PhaseResult{
		Phase:       5,
		Description: "Clean up directories and files",
		Details:     make(map[string]interface{}),
	}

	logger.Info("Phase 5: Cleaning up directories and files")

	var removed []string
	var skipped []string

	for _, dir := range directories {
		// Skip /opt/* directories in dev mode
		if devMode && strings.HasPrefix(dir.Path, "/opt/") {
			logger.Info("Skipping directory in dev mode", zap.String("path", dir.Path))
			skipped = append(skipped, dir.Path)
			continue
		}

		if _, err := os.Stat(dir.Path); err == nil {
			logger.Info("Removing directory",
				zap.String("path", dir.Path),
				zap.String("description", dir.Description))
			
			if err := os.RemoveAll(dir.Path); err != nil {
				logger.Error("Failed to remove directory",
					zap.String("path", dir.Path),
					zap.Error(err))
			} else {
				removed = append(removed, dir.Path)
			}
		}
	}

	// Clean up systemd services
	cleanupSystemdServices(rc)

	// Clean up APT sources
	cleanupAPTSources(rc)

	// Clean up APT packages
	cleanupAPTPackages(rc, cli)

	result.Success = true
	result.Details["removed"] = removed
	result.Details["skipped"] = skipped

	logger.Info("Directories and files cleanup completed",
		zap.Int("removed", len(removed)),
		zap.Int("skipped", len(skipped)))

	return result
}

// Helper functions

func commandExists(cli *eos_cli.CLI, cmd string) bool {
	_, err := cli.Which(cmd)
	return err == nil
}


func stopNomadJobs(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	cli := eos_cli.New(rc)

	// Check if nomad binary exists before trying to use it
	if _, err := exec.LookPath("nomad"); err != nil {
		logger.Info("Nomad binary not found, skipping job cleanup", zap.Error(err))
		return nil
	}

	output, err := cli.ExecString("nomad", "job", "list", "-short")
	if err != nil {
		return fmt.Errorf("failed to list nomad jobs: %w", err)
	}

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

	return nil
}

func removeAdditionalServices(rc *eos_io.RuntimeContext, excluded map[string]bool, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
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

	return nil
}

func stopService(rc *eos_io.RuntimeContext, cli *eos_cli.CLI, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if service exists
	output, err := cli.ExecString("systemctl", "list-units", "--all", "--type=service", "--quiet", serviceName+".service")
	if err != nil || !strings.Contains(output, serviceName+".service") {
		logger.Debug("Service not found", zap.String("service", serviceName))
		return nil
	}

	logger.Info("Stopping service", zap.String("service", serviceName))

	// Stop service
	if _, err := cli.ExecString("systemctl", "stop", serviceName); err != nil {
		logger.Debug("Service stop failed", zap.String("service", serviceName), zap.Error(err))
	}

	// Disable service
	if _, err := cli.ExecString("systemctl", "disable", serviceName); err != nil {
		logger.Debug("Service disable failed", zap.String("service", serviceName), zap.Error(err))
	}

	return nil
}

// removeBinaries is now mostly obsolete as all components handle their own binaries
// This function remains for backward compatibility but should be removed in future
func removeBinaries(rc *eos_io.RuntimeContext, excluded map[string]bool) []string {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for any remaining binaries")

	// All binaries are now handled by their respective lifecycle managers
	// This function is kept for backward compatibility but returns empty
	return []string{}
}

// cleanupSystemdServices is now obsolete as all components handle their own systemd files
// This function remains for backward compatibility but does minimal work
func cleanupSystemdServices(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Systemd cleanup delegated to component lifecycle managers")
	
	// All systemd files are now handled by their respective lifecycle managers
	// Just reload systemd to ensure any removed services are cleaned up
	cli := eos_cli.New(rc)
	cli.ExecToSuccess("systemctl", "daemon-reload")
}

// cleanupAPTSources is now obsolete as all components handle their own APT sources
// This function remains for backward compatibility but does minimal work
func cleanupAPTSources(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("APT source cleanup delegated to component lifecycle managers")
	
	// All APT sources are now handled by their respective lifecycle managers
	// Components like osquery, saltstack, etc. handle their own APT sources
}

// TODO: MIGRATE DUPLICATE LOGIC - This function duplicates APT package cleanup
// FIXME: This should delegate to a shared system package lifecycle manager:
// - Create pkg/system/package_lifecycle.go for system-wide cleanup
// - This is generic cleanup that can remain centralized but should be in system package
// CURRENT STATUS: Acceptable centralized logic but wrong location
func cleanupAPTPackages(rc *eos_io.RuntimeContext, cli *eos_cli.CLI) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Cleaning up APT packages")

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
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}