package nuke

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/process"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EvaluateRemoval verifies the infrastructure removal was successful
func EvaluateRemoval(rc *eos_io.RuntimeContext, config *Config, initialPlan *RemovalPlan, phaseResults []PhaseResult) (*NukeResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if we can evaluate the removal
	logger.Info("Evaluating infrastructure removal results")

	// INTERVENE - Perform verification checks
	result := &NukeResult{}

	// Load final state
	finalTracker, err := loadFinalState(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to load final state: %w", err)
	}

	// Calculate results
	initialCount := len(initialPlan.Components)
	finalCount := len(finalTracker.Components)
	removedCount := initialCount - finalCount

	result.InitialComponents = initialCount
	result.RemainingComponents = finalCount
	result.RemovedComponents = removedCount

	if initialCount > 0 {
		result.SuccessRate = float64(removedCount) / float64(initialCount) * 100
	}

	// Check for remaining processes
	remainingProcesses := checkRemainingProcesses(rc)
	if len(remainingProcesses) > 0 {
		logger.Warn("Some processes are still running", zap.Strings("processes", remainingProcesses))
		result.RemainingItems = append(result.RemainingItems, remainingProcesses...)

		// Only kill processes that aren't excluded
		processesToKill := []string{}
		for _, proc := range remainingProcesses {
			// Check if this process is excluded (e.g., code-server, tailscaled in dev mode)
			isExcluded := false
			for _, excluded := range config.ExcludeList {
				if strings.Contains(proc, excluded) {
					isExcluded = true
					break
				}
			}
			if !isExcluded {
				processesToKill = append(processesToKill, proc)
			}
		}

		if len(processesToKill) > 0 {
			// Force kill remaining non-excluded processes
			killRemainingProcesses(rc, processesToKill)
		}
	}

	// Check for remaining components
	if finalCount > 0 {
		for _, comp := range finalTracker.Components {
			result.RemainingItems = append(result.RemainingItems, fmt.Sprintf("component:%s", comp.Name))
		}
	}

	// Log structured results
	logger.Info("Infrastructure removal evaluation completed",
		zap.Int("initial_components", result.InitialComponents),
		zap.Int("removed_components", result.RemovedComponents),
		zap.Int("remaining_components", result.RemainingComponents),
		zap.Float64("success_rate", result.SuccessRate),
		zap.Strings("remaining_items", result.RemainingItems))

	// Clean up state file if configured
	cleanupStateFile(rc, config.KeepData)

	// EVALUATE - Determine overall success
	if len(result.RemainingItems) == 0 {
		logger.Info("Infrastructure removal completed successfully")
	} else {
		logger.Warn("Infrastructure removal completed with remaining items",
			zap.Int("remaining_count", len(result.RemainingItems)))
	}

	return result, nil
}

// ShowRemovalPlan displays what will be removed (replacing fmt.Print violations)
func ShowRemovalPlan(rc *eos_io.RuntimeContext, plan *RemovalPlan) {
	logger := otelzap.Ctx(rc.Ctx)

	// Log the removal plan using structured logging
	logger.Info("Infrastructure removal plan")

	if len(plan.Components) > 0 {
		var componentDetails []string
		for _, comp := range plan.Components {
			status := comp.Status
			if status == "" {
				status = "unknown"
			}
			componentDetails = append(componentDetails, fmt.Sprintf("%s %s [%s]", comp.Name, comp.Version, status))
		}
		logger.Info("Components to be removed", zap.Strings("components", componentDetails))
	} else {
		logger.Info("No eos-managed components detected for removal")
	}

	if plan.DataPreserved {
		logger.Info("Data directories will be preserved")
	}

	if len(plan.ExcludedItems) > 0 {
		logger.Info("Items excluded from removal", zap.Strings("excluded", plan.ExcludedItems))
	}

	if plan.DevModeActive {
		logger.Info("Development mode protections active",
			zap.String("protection_1", "All /opt/* directories will be preserved"),
			zap.String("protection_2", "Development tools will not be removed"))
	}
}

// GenerateRemovalReport creates a comprehensive final report (replacing fmt.Print violations)
func GenerateRemovalReport(rc *eos_io.RuntimeContext, result *NukeResult, phaseResults []PhaseResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Log structured final report
	logger.Info("Infrastructure nuke operation final report",
		zap.String("report_type", "FINAL_REPORT"))

	// Summary information
	logger.Info("Nuke operation summary",
		zap.Int("initial_components", result.InitialComponents),
		zap.Int("removed_components", result.RemovedComponents),
		zap.Int("remaining_components", result.RemainingComponents),
		zap.Float64("success_rate", result.SuccessRate))

	// Phase results
	for _, phase := range phaseResults {
		if phase.Success {
			logger.Info("Phase completed successfully",
				zap.Int("phase", phase.Phase),
				zap.String("description", phase.Description),
				zap.Any("details", phase.Details))
		} else {
			logger.Error("Phase completed with errors",
				zap.Int("phase", phase.Phase),
				zap.String("description", phase.Description),
				zap.Error(phase.Error),
				zap.Any("details", phase.Details))
		}
	}

	// Remaining components analysis
	if result.RemainingComponents > 0 {
		logger.Warn("Components that could not be removed",
			zap.Strings("remaining_items", result.RemainingItems))

		// Provide solutions for common remaining components
		for _, item := range result.RemainingItems {
			if strings.HasPrefix(item, "component:") {
				componentName := strings.TrimPrefix(item, "component:")
				solution := getRemovalSolution(componentName)
				logger.Info("Manual removal solution available",
					zap.String("component", componentName),
					zap.String("solution", solution))
			}
		}
	} else {
		logger.Info("All components successfully removed",
			zap.String("status", "system restored to clean state"))
	}

	// Final recommendations
	if result.RemainingComponents > 0 {
		logger.Info("Recommended next steps",
			zap.String("step_1", "Review the remaining components above"),
			zap.String("step_2", "Follow the provided solutions for manual cleanup"),
			zap.String("step_3", "Reboot the system to ensure all services are stopped"))
	} else {
		logger.Info("Recommended next steps",
			zap.String("step_1", "Consider rebooting to ensure clean system state"),
			zap.String("step_2", "System has been cleaned and is ready for fresh deployments"))
	}

	logger.Info("Nuke operation report completed",
		zap.Int("removed", result.RemovedComponents),
		zap.Int("remaining", result.RemainingComponents),
		zap.Float64("success_rate", result.SuccessRate))
}

// Helper functions for evaluation

func loadFinalState(rc *eos_io.RuntimeContext) (*state.StateTracker, error) {
	finalTracker := state.New()
	if err := finalTracker.GatherOutOfBand(rc); err != nil {
		return nil, fmt.Errorf("failed to gather final state: %w", err)
	}
	return finalTracker, nil
}

func checkRemainingProcesses(rc *eos_io.RuntimeContext) []string {
	logger := otelzap.Ctx(rc.Ctx)

	processesToCheck := []string{
		"vault", "nomad", "consul", "boundary",
		"osqueryd", "caddy", "authentik", "fail2ban", "trivy", "wazuh", "eos",
		"code-server", "prometheus", "node_exporter", "grafana-server", "nginx",
		"glances", "tailscaled",
	}

	var remainingProcesses []string
	for _, proc := range processesToCheck {
		if processes, err := process.FindProcesses(rc.Ctx, proc); err == nil && len(processes) > 0 {
			remainingProcesses = append(remainingProcesses, proc)
			logger.Debug("Process still running",
				zap.String("process", proc),
				zap.Int("count", len(processes)))
		}
	}

	return remainingProcesses
}

func killRemainingProcesses(rc *eos_io.RuntimeContext, remainingProcesses []string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Killing remaining processes", zap.Strings("processes", remainingProcesses))

	for _, proc := range remainingProcesses {
		if killed, err := process.KillProcesses(rc.Ctx, proc); err != nil {
			logger.Debug("Failed to kill process",
				zap.String("process", proc),
				zap.Error(err))
		} else if killed > 0 {
			logger.Info("Killed processes",
				zap.String("process", proc),
				zap.Int("count", killed))
		}
	}
}

func cleanupStateFile(rc *eos_io.RuntimeContext, keepData bool) {
	logger := otelzap.Ctx(rc.Ctx)

	stateFile := "/var/lib/eos/state.json"
	if fileExists(stateFile) && !keepData {
		logger.Info("Removing state file", zap.String("file", stateFile))
		if err := os.Remove(stateFile); err != nil {
			logger.Warn("Failed to remove state file", zap.Error(err))
		}
	}
}

func getRemovalSolution(componentName string) string {
	solutions := map[string]string{
		"nomad":  "Run 'sudo systemctl stop nomad && sudo rm -rf /opt/nomad /etc/nomad.d'",
		"consul": "Run 'sudo systemctl stop consul && sudo rm -rf /opt/consul /etc/consul.d'",
		"":       "Run 'sudo apt-get purge -* && sudo rm -rf /srv/ /etc/'",
		"docker": "Manually remove if needed with 'sudo apt-get purge docker-ce'",
		"vault":  "Check for active Vault mounts and unmount before removal",
	}

	if solution, exists := solutions[componentName]; exists {
		return solution
	}
	return "Manual investigation required"
}
