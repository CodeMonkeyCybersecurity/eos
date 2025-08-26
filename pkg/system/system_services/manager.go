package system_services

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceManager handles systemd service operations
type ServiceManager struct {
	config *ServiceConfig
}

// NewServiceManager creates a new service manager
func NewServiceManager(config *ServiceConfig) *ServiceManager {
	if config == nil {
		config = DefaultServiceConfig()
	}

	return &ServiceManager{
		config: config,
	}
}

// ListServices lists systemd services based on filter options
func (sm *ServiceManager) ListServices(rc *eos_io.RuntimeContext, filter *ServiceFilterOptions) (*ServiceListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing systemd services",
		zap.Bool("show_all", sm.config.ShowAll),
		zap.Any("filter", filter))

	// Build systemctl command
	args := []string{"list-units", "--type=service"}
	if sm.config.ShowAll {
		args = append(args, "--all")
	}
	args = append(args, "--no-pager", "--plain")

	cmd := exec.CommandContext(rc.Ctx, "systemctl", args...)
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list services", zap.Error(err))
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	services, err := sm.parseServiceList(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse service list: %w", err)
	}

	// Apply filters
	if filter != nil {
		services = sm.applyFilters(services, filter)
	}

	result := &ServiceListResult{
		Services:  services,
		Count:     len(services),
		Timestamp: time.Now(),
	}

	if filter != nil && filter.Pattern != "" {
		result.Filter = filter.Pattern
	}

	logger.Info("Found services", zap.Int("count", len(services)))
	return result, nil
}

// GetServiceStatus gets detailed status for a specific service
func (sm *ServiceManager) GetServiceStatus(rc *eos_io.RuntimeContext, serviceName string) (*ServiceInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Getting service status", zap.String("service", serviceName))

	cmd := exec.CommandContext(rc.Ctx, "systemctl", "show", serviceName, "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get service status", zap.String("service", serviceName), zap.Error(err))
		return nil, fmt.Errorf("failed to get service status for %s: %w", serviceName, err)
	}

	service, err := sm.parseServiceShow(string(output), serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service status: %w", err)
	}

	return service, nil
}

// StartService starts and optionally enables a service
func (sm *ServiceManager) StartService(rc *eos_io.RuntimeContext, serviceName string, enable bool) (*ServiceOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting service",
		zap.String("service", serviceName),
		zap.Bool("enable", enable),
		zap.Bool("dry_run", sm.config.DryRun))

	operation := &ServiceOperation{
		Service:   serviceName,
		Operation: "start",
		Timestamp: time.Now(),
		DryRun:    sm.config.DryRun,
	}

	if enable {
		operation.Operation = "start_and_enable"
	}

	if sm.config.DryRun {
		operation.Success = true
		if enable {
			operation.Message = fmt.Sprintf("Would start and enable service: %s", serviceName)
		} else {
			operation.Message = fmt.Sprintf("Would start service: %s", serviceName)
		}
		logger.Info("Dry run: would start service", zap.String("service", serviceName))
		return operation, nil
	}

	// Start the service
	var cmd *exec.Cmd
	if sm.config.Sudo {
		cmd = exec.CommandContext(rc.Ctx, "sudo", "systemctl", "start", serviceName)
	} else {
		cmd = exec.CommandContext(rc.Ctx, "systemctl", "start", serviceName)
	}

	if err := cmd.Run(); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to start service: %v", err)
		logger.Error("Failed to start service", zap.String("service", serviceName), zap.Error(err))
		return operation, fmt.Errorf("failed to start service %s: %w", serviceName, err)
	}

	// Enable the service if requested
	if enable {
		if sm.config.Sudo {
			cmd = exec.CommandContext(rc.Ctx, "sudo", "systemctl", "enable", serviceName)
		} else {
			cmd = exec.CommandContext(rc.Ctx, "systemctl", "enable", serviceName)
		}

		if err := cmd.Run(); err != nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Started service but failed to enable: %v", err)
			logger.Warn("Service started but failed to enable", zap.String("service", serviceName), zap.Error(err))
			return operation, nil // Don't return error since start succeeded
		}
	}

	operation.Success = true
	if enable {
		operation.Message = fmt.Sprintf("Successfully started and enabled service: %s", serviceName)
	} else {
		operation.Message = fmt.Sprintf("Successfully started service: %s", serviceName)
	}

	logger.Info("Service operation completed",
		zap.String("service", serviceName),
		zap.String("operation", operation.Operation))

	return operation, nil
}

// StopService stops and optionally disables a service
func (sm *ServiceManager) StopService(rc *eos_io.RuntimeContext, serviceName string, disable bool) (*ServiceOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping service",
		zap.String("service", serviceName),
		zap.Bool("disable", disable),
		zap.Bool("dry_run", sm.config.DryRun))

	operation := &ServiceOperation{
		Service:   serviceName,
		Operation: "stop",
		Timestamp: time.Now(),
		DryRun:    sm.config.DryRun,
	}

	if disable {
		operation.Operation = "stop_and_disable"
	}

	if sm.config.DryRun {
		operation.Success = true
		if disable {
			operation.Message = fmt.Sprintf("Would stop and disable service: %s", serviceName)
		} else {
			operation.Message = fmt.Sprintf("Would stop service: %s", serviceName)
		}
		logger.Info("Dry run: would stop service", zap.String("service", serviceName))
		return operation, nil
	}

	// Stop the service
	var cmd *exec.Cmd
	if sm.config.Sudo {
		cmd = exec.CommandContext(rc.Ctx, "sudo", "systemctl", "stop", serviceName)
	} else {
		cmd = exec.CommandContext(rc.Ctx, "systemctl", "stop", serviceName)
	}

	if err := cmd.Run(); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to stop service: %v", err)
		logger.Error("Failed to stop service", zap.String("service", serviceName), zap.Error(err))
		return operation, fmt.Errorf("failed to stop service %s: %w", serviceName, err)
	}

	// Disable the service if requested
	if disable {
		if sm.config.Sudo {
			cmd = exec.CommandContext(rc.Ctx, "sudo", "systemctl", "disable", serviceName)
		} else {
			cmd = exec.CommandContext(rc.Ctx, "systemctl", "disable", serviceName)
		}

		if err := cmd.Run(); err != nil {
			operation.Success = false
			operation.Message = fmt.Sprintf("Stopped service but failed to disable: %v", err)
			logger.Warn("Service stopped but failed to disable", zap.String("service", serviceName), zap.Error(err))
			return operation, nil // Don't return error since stop succeeded
		}
	}

	operation.Success = true
	if disable {
		operation.Message = fmt.Sprintf("Successfully stopped and disabled service: %s", serviceName)
	} else {
		operation.Message = fmt.Sprintf("Successfully stopped service: %s", serviceName)
	}

	logger.Info("Service operation completed",
		zap.String("service", serviceName),
		zap.String("operation", operation.Operation))

	return operation, nil
}

// RestartService restarts a service
func (sm *ServiceManager) RestartService(rc *eos_io.RuntimeContext, serviceName string) (*ServiceOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting service",
		zap.String("service", serviceName),
		zap.Bool("dry_run", sm.config.DryRun))

	operation := &ServiceOperation{
		Service:   serviceName,
		Operation: "restart",
		Timestamp: time.Now(),
		DryRun:    sm.config.DryRun,
	}

	if sm.config.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would restart service: %s", serviceName)
		logger.Info("Dry run: would restart service", zap.String("service", serviceName))
		return operation, nil
	}

	var cmd *exec.Cmd
	if sm.config.Sudo {
		cmd = exec.CommandContext(rc.Ctx, "sudo", "systemctl", "restart", serviceName)
	} else {
		cmd = exec.CommandContext(rc.Ctx, "systemctl", "restart", serviceName)
	}

	if err := cmd.Run(); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to restart service: %v", err)
		logger.Error("Failed to restart service", zap.String("service", serviceName), zap.Error(err))
		return operation, fmt.Errorf("failed to restart service %s: %w", serviceName, err)
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully restarted service: %s", serviceName)

	logger.Info("Service restarted successfully", zap.String("service", serviceName))
	return operation, nil
}

// ViewLogs displays logs for a service
func (sm *ServiceManager) ViewLogs(rc *eos_io.RuntimeContext, serviceName string, options *LogsOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Viewing service logs",
		zap.String("service", serviceName),
		zap.Any("options", options))

	// Build journalctl command
	args := []string{"-u", serviceName}

	if options != nil {
		if options.Follow {
			args = append(args, "-f")
		}
		if options.Lines > 0 {
			args = append(args, "-n", strconv.Itoa(options.Lines))
		}
		if options.Since != "" {
			args = append(args, "--since", options.Since)
		}
		if options.Until != "" {
			args = append(args, "--until", options.Until)
		}
		if options.Priority != "" {
			args = append(args, "-p", options.Priority)
		}
		if options.Reverse {
			args = append(args, "-r")
		}
		if options.NoHostname {
			args = append(args, "--no-hostname")
		}
	}

	cmd := exec.CommandContext(rc.Ctx, "journalctl", args...)

	if options != nil && options.Follow {
		// For following logs, we need to handle the output differently
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		logger.Info("Starting to follow logs (press Ctrl+C to stop)")
		return cmd.Run()
	} else {
		// For static logs, capture and display
		output, err := cmd.Output()
		if err != nil {
			logger.Error("Failed to get service logs", zap.String("service", serviceName), zap.Error(err))
			return fmt.Errorf("failed to get logs for service %s: %w", serviceName, err)
		}

		// Filter output if grep pattern provided
		if options != nil && options.Grep != "" {
			output = sm.filterLogs(string(output), options.Grep)
		}

		fmt.Print(string(output))
		return nil
	}
}

// Helper methods

func (sm *ServiceManager) parseServiceList(output string) ([]ServiceInfo, error) {
	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header line
	if scanner.Scan() {
		// Skip the header
	}

	// Regex to parse systemctl list-units output
	// Example: ssh.service                    loaded active running OpenBSD Secure Shell server
	serviceRegex := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := serviceRegex.FindStringSubmatch(line)
		if len(matches) != 6 {
			continue
		}

		service := ServiceInfo{
			Name:        matches[1],
			LoadState:   matches[2],
			ActiveState: matches[3],
			SubState:    matches[4],
			Description: matches[5],
		}

		// Set simplified states
		service.Running = (service.ActiveState == "active")
		service.State = ServiceState(service.ActiveState)

		services = append(services, service)
	}

	return services, nil
}

func (sm *ServiceManager) parseServiceShow(output string, serviceName string) (*ServiceInfo, error) {
	service := &ServiceInfo{
		Name: serviceName,
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Description":
				service.Description = value
			case "LoadState":
				service.LoadState = value
			case "ActiveState":
				service.ActiveState = value
				service.State = ServiceState(value)
				service.Running = (value == "active")
			case "SubState":
				service.SubState = value
			case "UnitFileState":
				service.Enabled = (value == "enabled")
				service.UnitFile = value
			}
		}
	}

	return service, nil
}

func (sm *ServiceManager) applyFilters(services []ServiceInfo, filter *ServiceFilterOptions) []ServiceInfo {
	var filtered []ServiceInfo

	for _, service := range services {
		// Filter by state
		if len(filter.State) > 0 {
			stateMatch := false
			for _, state := range filter.State {
				if service.State == state {
					stateMatch = true
					break
				}
			}
			if !stateMatch {
				continue
			}
		}

		// Filter by enabled status
		if filter.Enabled != nil && service.Enabled != *filter.Enabled {
			continue
		}

		// Filter by running status
		if filter.Running != nil && service.Running != *filter.Running {
			continue
		}

		// Filter by pattern
		if filter.Pattern != "" {
			matched, _ := regexp.MatchString(filter.Pattern, service.Name)
			if !matched {
				continue
			}
		}

		filtered = append(filtered, service)
	}

	return filtered
}

func (sm *ServiceManager) filterLogs(logs string, grepPattern string) []byte {
	var result strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(logs))

	regex, err := regexp.Compile(grepPattern)
	if err != nil {
		// If regex compilation fails, fall back to simple string matching
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, grepPattern) {
				result.WriteString(line + "\n")
			}
		}
	} else {
		for scanner.Scan() {
			line := scanner.Text()
			if regex.MatchString(line) {
				result.WriteString(line + "\n")
			}
		}
	}

	return []byte(result.String())
}
