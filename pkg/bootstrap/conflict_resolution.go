// pkg/bootstrap/conflict_resolution.go
//
// User-friendly conflict resolution system that provides clear options
// and handles port conflicts and service integration intelligently.

package bootstrap

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConflictResolutionChoice represents user choices for resolving conflicts
type ConflictResolutionChoice string

const (
	ChoiceIntegrate     ConflictResolutionChoice = "integrate"
	ChoiceCleanSlate    ConflictResolutionChoice = "clean_slate"
	ChoiceAdvanced      ConflictResolutionChoice = "advanced"
	ChoiceCancel        ConflictResolutionChoice = "cancel"
	ChoiceStopConflicts ConflictResolutionChoice = "stop_conflicts"
)

// ConflictResolutionOptions represents the options for resolving conflicts
type ConflictResolutionOptions struct {
	Choice         ConflictResolutionChoice
	ServicesToStop []string
	ServicesToKeep []string
	BackupConfigs  bool
	Force          bool
}

// PromptConflictResolution presents user-friendly options for resolving conflicts
func PromptConflictResolution(rc *eos_io.RuntimeContext, state *BootstrapState) (*ConflictResolutionOptions, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Display current state
	logger.Info("🔍 Detected existing infrastructure components:")

	runningServices := []string{}
	for name, component := range state.Components {
		if component.Running && component.Healthy {
			status := "✓"
			details := fmt.Sprintf("%s %s", status, name)
			if component.Version != "" {
				details += fmt.Sprintf(" (v%s)", component.Version)
			}
			if component.Port > 0 {
				details += fmt.Sprintf(" - port %d", component.Port)
			}
			if component.IsEosManaged {
				details += " [EOS managed]"
			}

			logger.Info("  " + details)
			runningServices = append(runningServices, name)
		}
	}

	if len(state.PortConflicts) > 0 {
		logger.Info("")
		logger.Info("⚠️  Port conflicts detected:")
		for _, conflict := range state.PortConflicts {
			status := "🔴"
			if conflict.IsEosService {
				status = "⚠️"
			}
			logger.Info(fmt.Sprintf("  %s Port %d: %s (PID %d)",
				status, conflict.Port, conflict.ServiceName, conflict.ProcessID))
		}
	}

	logger.Info("")

	// Determine what options to present based on state
	if state.IsEosInstall && state.CanReuseServices {
		return promptExistingEosInstall(rc, state)
	} else if len(runningServices) > 0 {
		return promptConflictingServices(rc, state)
	} else {
		// No conflicts, proceed with normal installation
		return &ConflictResolutionOptions{
			Choice: ChoiceIntegrate,
		}, nil
	}
}

// promptExistingEosInstall handles the case where EOS is already installed
func promptExistingEosInstall(rc *eos_io.RuntimeContext, state *BootstrapState) (*ConflictResolutionOptions, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("✅ Found existing EOS installation")
	logger.Info("")
	logger.Info("What would you like to do?")
	logger.Info("  1) 🔄 Use existing services (recommended)")
	logger.Info("  2) 🧹 Clean slate - reconfigure all services")
	logger.Info("  3) 🔧 Advanced - choose which services to reconfigure")
	logger.Info("  4) ❌ Cancel")
	logger.Info("")

	response, err := eos_io.PromptInput(rc, "Choose an option [1-4]: ", "conflict_resolution")
	if err != nil {
		return nil, err
	}

	choice := strings.TrimSpace(response)
	switch choice {
	case "1", "use", "existing":
		logger.Info("Using existing services")
		return &ConflictResolutionOptions{
			Choice: ChoiceIntegrate,
		}, nil

	case "2", "clean", "slate":
		logger.Info("Proceeding with clean slate installation")
		return &ConflictResolutionOptions{
			Choice:        ChoiceCleanSlate,
			BackupConfigs: true,
		}, nil

	case "3", "advanced":
		return promptAdvancedOptions(rc, state)

	case "4", "cancel":
		logger.Info("Bootstrap cancelled by user")
		return &ConflictResolutionOptions{
			Choice: ChoiceCancel,
		}, nil

	default:
		logger.Info("Invalid option, using existing services (default)")
		return &ConflictResolutionOptions{
			Choice: ChoiceIntegrate,
		}, nil
	}
}

// promptConflictingServices handles the case where there are conflicting services
func promptConflictingServices(rc *eos_io.RuntimeContext, state *BootstrapState) (*ConflictResolutionOptions, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("⚠️  Port conflicts detected!")
	logger.Info("")

	// Add quick fix suggestion early
	addQuickFixSuggestion(rc, state.PortConflicts)

	// Identify which services can be stopped and provide detailed analysis
	stoppableServices := []string{}
	eosServices := []string{}
	criticalServices := []string{}

	for _, conflict := range state.PortConflicts {
		logger.Debug("Analyzing port conflict",
			zap.Int("port", conflict.Port),
			zap.String("service_name", conflict.ServiceName),
			zap.String("process_name", conflict.ProcessName),
			zap.Int("pid", conflict.ProcessID),
			zap.Bool("can_stop", conflict.CanStop),
			zap.Bool("is_eos", conflict.IsEosService))

		if conflict.IsEosService {
			eosServices = append(eosServices, conflict.ServiceName)
		} else if conflict.CanStop {
			stoppableServices = append(stoppableServices, conflict.ServiceName)
		} else {
			criticalServices = append(criticalServices, conflict.ServiceName)
		}
	}

	if len(stoppableServices) > 0 {
		logger.Info("✅ The following services can be automatically stopped:")
		for _, service := range stoppableServices {
			logger.Info("  • " + service)
		}
		logger.Info("")
	}

	if len(eosServices) > 0 {
		logger.Info("🔧 The following EOS services are running:")
		for _, service := range eosServices {
			logger.Info("  • " + service + " (EOS managed)")
		}
		logger.Info("")
	}

	if len(criticalServices) > 0 {
		logger.Info("⚠️  The following services cannot be automatically stopped:")
		for _, service := range criticalServices {
			logger.Info("  • " + service + " (requires manual intervention)")
		}
		logger.Info("")
	}

	logger.Info("What would you like to do?")

	optionNum := 1
	if len(stoppableServices) > 0 {
		logger.Info(fmt.Sprintf("  %d) 🛑 Stop conflicting services and continue", optionNum))
		optionNum++
	}

	logger.Info(fmt.Sprintf("  %d) 🧹 Clean slate - stop and reconfigure all services", optionNum))
	optionNum++

	if len(eosServices) > 0 {
		logger.Info(fmt.Sprintf("  %d) 🔄 Keep existing EOS services", optionNum))
		optionNum++
	}

	logger.Info(fmt.Sprintf("  %d) 🔧 Advanced - manual service selection", optionNum))
	optionNum++

	logger.Info(fmt.Sprintf("  %d) ❌ Cancel", optionNum))
	logger.Info("")

	response, err := eos_io.PromptInput(rc, fmt.Sprintf("Choose an option [1-%d]: ", optionNum), "conflict_resolution")
	if err != nil {
		return nil, err
	}

	choice := strings.TrimSpace(response)

	// Map user choice to action
	currentOption := 1

	// Option 1: Stop conflicting services (if available)
	if len(stoppableServices) > 0 {
		if choice == fmt.Sprintf("%d", currentOption) || choice == "stop" {
			logger.Info("Stopping conflicting services")
			return &ConflictResolutionOptions{
				Choice:         ChoiceStopConflicts,
				ServicesToStop: stoppableServices,
			}, nil
		}
		currentOption++
	}

	// Option: Clean slate
	if choice == fmt.Sprintf("%d", currentOption) || choice == "clean" {
		logger.Info("Proceeding with clean slate installation")
		allServices := append(stoppableServices, eosServices...)
		return &ConflictResolutionOptions{
			Choice:         ChoiceCleanSlate,
			ServicesToStop: allServices,
			BackupConfigs:  true,
		}, nil
	}
	currentOption++

	// Option: Keep existing EOS services (if available)
	if len(eosServices) > 0 {
		if choice == fmt.Sprintf("%d", currentOption) || choice == "keep" {
			logger.Info("Keeping existing EOS services")
			return &ConflictResolutionOptions{
				Choice:         ChoiceIntegrate,
				ServicesToStop: stoppableServices,
				ServicesToKeep: eosServices,
			}, nil
		}
		currentOption++
	}

	// Option: Advanced
	if choice == fmt.Sprintf("%d", currentOption) || choice == "advanced" {
		return promptAdvancedOptions(rc, state)
	}
	currentOption++

	// Option: Cancel
	if choice == fmt.Sprintf("%d", currentOption) || choice == "cancel" {
		logger.Info("Bootstrap cancelled by user")
		return &ConflictResolutionOptions{
			Choice: ChoiceCancel,
		}, nil
	}

	// Default: Try to stop conflicting services
	logger.Info("Invalid option, stopping conflicting services (default)")
	return &ConflictResolutionOptions{
		Choice:         ChoiceStopConflicts,
		ServicesToStop: stoppableServices,
	}, nil
}

// promptAdvancedOptions provides advanced service selection
func promptAdvancedOptions(rc *eos_io.RuntimeContext, state *BootstrapState) (*ConflictResolutionOptions, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("🔧 Advanced service management")
	logger.Info("")
	logger.Info("Services detected:")

	serviceList := []string{}
	for name, component := range state.Components {
		if component.Running {
			status := "✓"
			if component.IsEosManaged {
				status += " [EOS]"
			}
			if !component.Healthy {
				status += " [Unhealthy]"
			}

			logger.Info(fmt.Sprintf("  %s %s", status, name))
			serviceList = append(serviceList, name)
		}
	}

	logger.Info("")
	logger.Info("Enter services to STOP (comma-separated), or 'all' for clean slate:")
	logger.Info("Example: vault,consul  or  all")
	logger.Info("")

	response, err := eos_io.PromptInput(rc, "Services to stop: ", "services_to_stop")
	if err != nil {
		return nil, err
	}

	response = strings.TrimSpace(response)

	if response == "" {
		logger.Info("No services selected to stop")
		return &ConflictResolutionOptions{
			Choice: ChoiceIntegrate,
		}, nil
	}

	if response == "all" {
		logger.Info("Stopping all services")
		return &ConflictResolutionOptions{
			Choice:         ChoiceCleanSlate,
			ServicesToStop: serviceList,
			BackupConfigs:  true,
		}, nil
	}

	// Parse comma-separated service list
	servicesToStop := []string{}
	for _, service := range strings.Split(response, ",") {
		service = strings.TrimSpace(service)
		if service != "" {
			servicesToStop = append(servicesToStop, service)
		}
	}

	logger.Info("Services selected for stopping:", zap.Strings("services", servicesToStop))

	return &ConflictResolutionOptions{
		Choice:         ChoiceStopConflicts,
		ServicesToStop: servicesToStop,
		BackupConfigs:  true,
	}, nil
}

// ExecuteConflictResolution executes the chosen conflict resolution
func ExecuteConflictResolution(rc *eos_io.RuntimeContext, options *ConflictResolutionOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	switch options.Choice {
	case ChoiceCancel:
		return fmt.Errorf("bootstrap cancelled by user")

	case ChoiceIntegrate:
		logger.Info("Integrating with existing services")
		return nil // No action needed

	case ChoiceCleanSlate:
		return executeCleanSlate(rc, options)

	case ChoiceStopConflicts:
		return executeStopConflicts(rc, options)

	case ChoiceAdvanced:
		return executeAdvancedResolution(rc, options)

	default:
		return fmt.Errorf("unknown conflict resolution choice: %s", options.Choice)
	}
}

// executeCleanSlate stops all services and prepares for fresh installation
func executeCleanSlate(rc *eos_io.RuntimeContext, options *ConflictResolutionOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing clean slate installation")

	// Backup configurations if requested
	if options.BackupConfigs {
		if err := backupExistingConfigurations(rc); err != nil {
			logger.Warn("Failed to backup configurations", zap.Error(err))
			// Continue anyway
		}
	}

	// Stop all services
	for _, service := range options.ServicesToStop {
		if err := stopService(rc, service); err != nil {
			logger.Warn("Failed to stop service",
				zap.String("service", service),
				zap.Error(err))
			// Continue with other services
		}
	}

	// Clean up service data directories
	if err := cleanupServiceData(rc, options.ServicesToStop); err != nil {
		logger.Warn("Failed to cleanup service data", zap.Error(err))
		// Continue anyway
	}

	logger.Info("Clean slate preparation completed")
	return nil
}

// executeStopConflicts stops only conflicting services
func executeStopConflicts(rc *eos_io.RuntimeContext, options *ConflictResolutionOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping conflicting services")
	logger.Debug("Services to stop", zap.Strings("services", options.ServicesToStop))

	// Backup configurations if requested
	if options.BackupConfigs {
		if err := backupExistingConfigurations(rc); err != nil {
			logger.Warn("Failed to backup configurations", zap.Error(err))
		}
	}

	// Stop specified services
	for _, service := range options.ServicesToStop {
		logger.Debug("Attempting to stop service",
			zap.String("service", service))
		if err := stopService(rc, service); err != nil {
			logger.Warn("Failed to stop service",
				zap.String("service", service),
				zap.Error(err))
			// Continue with other services
		}
	}

	logger.Info("Conflicting services stopped")
	return nil
}

// executeAdvancedResolution handles advanced conflict resolution
func executeAdvancedResolution(rc *eos_io.RuntimeContext, options *ConflictResolutionOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Executing advanced conflict resolution")

	// This would be implemented based on specific advanced options
	// For now, treat it like stop conflicts
	return executeStopConflicts(rc, options)
}

// stopService stops a service using the robust service manager
func stopService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping service", zap.String("service", serviceName))

	// Create service manager
	sm := NewServiceManager(rc)

	// Get all services to find the one we want to stop
	services, err := sm.DetectServices()
	if err != nil {
		logger.Warn("Failed to detect services, using fallback method", zap.Error(err))
		return stopServiceFallback(rc, serviceName)
	}

	// Find the service to stop
	var targetService *Service
	for _, service := range services {
		if service.Name == serviceName ||
			strings.Contains(service.ProcessName, serviceName) ||
			strings.Contains(service.ProcessPath, serviceName) {
			targetService = &service
			break
		}
	}

	if targetService == nil {
		logger.Warn("Service not found in detected services, using fallback",
			zap.String("service", serviceName))
		return stopServiceFallback(rc, serviceName)
	}

	// Use the service manager to stop the service
	err = sm.StopService(*targetService)
	if err != nil {
		logger.Error("Service manager failed to stop service",
			zap.String("service", serviceName),
			zap.Error(err))

		// If the service manager fails, provide detailed help
		logger.Info("💡 Service stopping failed. Let me help you fix this...")
		showServiceStoppingHelp(rc, *targetService, err)

		// Try diagnostic mode
		logger.Info("🔍 Running diagnostic analysis...")
		for _, port := range targetService.Ports {
			sm.DiagnosePortConflict(port)
		}

		return fmt.Errorf("failed to stop service %s. See diagnostic information above for manual resolution", serviceName)
	}

	// Wait a moment for the service to fully stop
	time.Sleep(2 * time.Second)

	// Verify it stopped by checking if ports are free
	for _, port := range targetService.Ports {
		if stillInUse := isPortInUse(rc, port); stillInUse {
			logger.Warn("Port still in use after stopping service",
				zap.String("service", serviceName),
				zap.Int("port", port))

			// Run diagnostics
			sm.DiagnosePortConflict(port)

			return fmt.Errorf("service %s appears to still be using port %d after stop", serviceName, port)
		}
	}

	logger.Info("Service stopped successfully",
		zap.String("service", serviceName))

	return nil
}

// stopServiceFallback provides fallback service stopping when service manager fails
func stopServiceFallback(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Using fallback method to stop service", zap.String("service", serviceName))

	// Try multiple service name variations
	serviceVariations := []string{
		serviceName,
		serviceName + ".service",
	}

	// Add specific mappings for common issues
	if strings.Contains(serviceName, "/opt//") {
		serviceVariations = append(serviceVariations, "-master", "-api")
	}

	for _, variation := range serviceVariations {
		logger.Debug("Trying service variation", zap.String("variation", variation))

		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", variation},
			Capture: true,
		})

		if err == nil {
			logger.Info("Successfully stopped service with variation",
				zap.String("original", serviceName),
				zap.String("variation", variation))
			return nil
		}

		logger.Debug("Service variation failed",
			zap.String("variation", variation),
			zap.Error(err),
			zap.String("output", output))
	}

	return fmt.Errorf("failed to stop service %s using all variations", serviceName)
}

// isPortInUse checks if a port is currently in use
func isPortInUse(rc *eos_io.RuntimeContext, port int) bool {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp", fmt.Sprintf("sport = :%d", port)},
		Capture: true,
	})

	return err == nil && len(strings.TrimSpace(output)) > 1
}

// backupExistingConfigurations backs up existing service configurations
func backupExistingConfigurations(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Backing up existing configurations")

	backupDir := fmt.Sprintf("/var/backups/eos-bootstrap-%d", time.Now().Unix())

	// Create backup directory
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "mkdir",
		Args:    []string{"-p", backupDir},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup common configuration directories
	configDirs := []string{
		"/etc/",
		"/etc/vault",
		"/etc/consul",
		"/etc/nomad",
		"/etc/eos",
	}

	for _, dir := range configDirs {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "cp",
			Args:    []string{"-r", dir, backupDir},
			Capture: true,
		}); err != nil {
			logger.Debug("Could not backup directory",
				zap.String("dir", dir),
				zap.Error(err))
			// Continue with other directories
		}
	}

	logger.Info("Configuration backup completed", zap.String("backup_dir", backupDir))
	return nil
}

// cleanupServiceData removes service data directories
func cleanupServiceData(rc *eos_io.RuntimeContext, services []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Cleaning up service data directories")

	// Define data directories for each service
	serviceDataDirs := map[string][]string{
		"vault":  {"/opt/vault/data", "/var/log/vault"},
		"consul": {"/opt/consul/data", "/var/log/consul"},
		"nomad":  {"/opt/nomad/data", "/var/log/nomad"},
	}

	for _, service := range services {
		if dirs, exists := serviceDataDirs[service]; exists {
			for _, dir := range dirs {
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "rm",
					Args:    []string{"-rf", dir},
					Capture: true,
				}); err != nil {
					logger.Warn("Failed to remove data directory",
						zap.String("service", service),
						zap.String("dir", dir),
						zap.Error(err))
				}
			}
		}
	}

	return nil
}

// PromptGuidedBootstrap provides a guided bootstrap experience for beginners
func PromptGuidedBootstrap(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("╔══════════════════════════════════════╗")
	logger.Info("║        Welcome to EOS! 🌅           ║")
	logger.Info("║   Let's set up your infrastructure   ║")
	logger.Info("║            step by step.             ║")
	logger.Info("╚══════════════════════════════════════╝")
	logger.Info("")

	logger.Info("Step 1: Checking your system...")

	// Perform system detection
	state, err := DetectBootstrapState(rc)
	if err != nil {
		return fmt.Errorf("failed to detect system state: %w", err)
	}

	// Show system information
	logger.Info("✓ System information gathered")
	if state.IsEosInstall {
		logger.Info("✓ Existing EOS installation detected")
	}

	if len(state.Components) > 0 {
		logger.Info("✓ Found existing services")
	}

	logger.Info("")
	logger.Info("Step 2: Checking for conflicts...")

	if len(state.PortConflicts) > 0 {
		logger.Info("⚠️  Found some services already running")
		logger.Info("")
		logger.Info("Don't worry! This is common. Would you like me to:")
		logger.Info("→ Set up alongside existing services (recommended)")
		logger.Info("→ Start fresh (I'll handle everything)")
		logger.Info("")

		response, err := eos_io.PromptInput(rc, "Just press ENTER for recommended option: ", "guided_choice")
		if err != nil {
			return err
		}

		if strings.ToLower(strings.TrimSpace(response)) == "fresh" {
			logger.Info("Starting fresh installation")
			return ExecuteConflictResolution(rc, &ConflictResolutionOptions{
				Choice:        ChoiceCleanSlate,
				BackupConfigs: true,
			})
		} else {
			logger.Info("Integrating with existing services")
			return ExecuteConflictResolution(rc, &ConflictResolutionOptions{
				Choice: ChoiceIntegrate,
			})
		}
	} else {
		logger.Info("✓ No conflicts detected")
		logger.Info("✓ Ready to proceed with installation")
	}

	return nil
}

// showServiceStoppingHelp provides detailed help when service stopping fails
func showServiceStoppingHelp(rc *eos_io.RuntimeContext, service Service, stopError error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("╔══════════════════════════════════════╗")
	logger.Info("║        Service Stopping Help         ║")
	logger.Info("╚══════════════════════════════════════╝")

	logger.Info("Service Details:")
	logger.Info(fmt.Sprintf("  Name: %s", service.Name))
	logger.Info(fmt.Sprintf("  Status: %s", service.Status))
	logger.Info(fmt.Sprintf("  PID: %d", service.PID))
	if service.ProcessPath != "" {
		logger.Info(fmt.Sprintf("  Command: %s", service.ProcessPath))
	}
	if len(service.Ports) > 0 {
		portStrs := make([]string, len(service.Ports))
		for i, port := range service.Ports {
			portStrs[i] = fmt.Sprintf("%d", port)
		}
		logger.Info(fmt.Sprintf("  Ports: %s", strings.Join(portStrs, ", ")))
	}

	logger.Info("")
	logger.Info("Error Details:")
	logger.Info(fmt.Sprintf("  %s", stopError.Error()))

	logger.Info("")
	logger.Info("🛠️  Manual Fix Options:")

	// Option 1: Try systemctl variations
	logger.Info("1) Try stopping with different service names:")
	serviceVariations := []string{service.Name, service.Name + ".service"}
	if strings.Contains(service.ProcessPath, "") {
		serviceVariations = append(serviceVariations, "-master", "-api")
	}

	for _, variation := range serviceVariations {
		logger.Info(fmt.Sprintf("   sudo systemctl stop %s", variation))
	}

	// Option 2: Kill by PID
	if service.PID > 0 {
		logger.Info("")
		logger.Info("2) Stop by process ID:")
		logger.Info(fmt.Sprintf("   sudo kill -TERM %d", service.PID))
		logger.Info(fmt.Sprintf("   # If that doesn't work: sudo kill -KILL %d", service.PID))
	}

	// Option 3: Kill by port
	if len(service.Ports) > 0 {
		logger.Info("")
		logger.Info("3) Stop by killing processes using the ports:")
		for _, port := range service.Ports {
			logger.Info(fmt.Sprintf("   sudo lsof -ti:%d | xargs kill -9", port))
		}
	}

	// Option 4: Check for dependencies
	logger.Info("")
	logger.Info("4) Check for service dependencies:")
	logger.Info(fmt.Sprintf("   systemctl list-dependencies %s", service.Name))
	logger.Info(fmt.Sprintf("   systemctl status %s", service.Name))

	// Option 5: Force bootstrap
	logger.Info("")
	logger.Info("5) Force bootstrap anyway:")
	logger.Info("   sudo eos bootstrap --force")

	logger.Info("")
	logger.Info("After manually stopping the service, you can retry with:")
	logger.Info("   sudo eos bootstrap")
}

// addQuickFixSuggestion adds a quick fix suggestion to the conflict resolution
func addQuickFixSuggestion(rc *eos_io.RuntimeContext, conflicts []PortConflict) {
	logger := otelzap.Ctx(rc.Ctx)

	if len(conflicts) == 0 {
		return
	}

	logger.Info("")
	logger.Info("💡 Quick Fix Suggestion:")

	// Build a command to stop all conflicting services
	servicesToStop := []string{}
	serviceMap := make(map[string]bool)

	for _, conflict := range conflicts {
		if conflict.CanStop && conflict.ServiceName != "unknown" && !serviceMap[conflict.ServiceName] {
			servicesToStop = append(servicesToStop, conflict.ServiceName)
			serviceMap[conflict.ServiceName] = true
		}
	}

	if len(servicesToStop) > 0 {
		logger.Info("Run this command to stop conflicting services:")
		logger.Info(fmt.Sprintf("   sudo systemctl stop %s", strings.Join(servicesToStop, " ")))
		logger.Info("   sudo eos bootstrap")
		logger.Info("")
		logger.Info("Or use the automatic option:")
		logger.Info("   sudo eos bootstrap --stop-conflicting")
	} else {
		logger.Info("Manual intervention required for these services.")
		logger.Info("Try: sudo eos bootstrap --force")
	}
}
