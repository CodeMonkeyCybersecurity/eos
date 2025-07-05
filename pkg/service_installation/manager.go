// pkg/service_installation/manager.go
package service_installation

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceInstallationManager provides service installation functionality
type ServiceInstallationManager struct {
	configurations map[ServiceType]*ServiceConfiguration
}

// NewServiceInstallationManager creates a new ServiceInstallationManager instance
func NewServiceInstallationManager() *ServiceInstallationManager {
	sim := &ServiceInstallationManager{
		configurations: make(map[ServiceType]*ServiceConfiguration),
	}
	sim.initializeServiceConfigurations()
	return sim
}

// InstallService installs a service based on the provided options
func (sim *ServiceInstallationManager) InstallService(rc *eos_io.RuntimeContext, options *ServiceInstallOptions) (*InstallationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	start := time.Now()
	result := &InstallationResult{
		Service:   string(options.Type),
		Method:    options.Method,
		Timestamp: start,
		Steps:     make([]InstallationStep, 0),
	}

	logger.Info("Starting service installation",
		zap.String("service", string(options.Type)),
		zap.String("method", string(options.Method)),
		zap.Bool("dry_run", options.DryRun))

	// Get service configuration
	config, exists := sim.configurations[options.Type]
	if !exists {
		return nil, fmt.Errorf("unsupported service type: %s", options.Type)
	}

	// Apply defaults from configuration
	sim.applyDefaults(options, config)

	// Pre-installation checks (skip for dry run)
	if !options.DryRun {
		if err := sim.performPreInstallationChecks(rc, options, config, result); err != nil {
			result.Success = false
			result.Error = err.Error()
			result.Duration = time.Since(start)
			return result, err
		}
	}

	// Perform installation based on service type
	switch options.Type {
	case ServiceTypeGrafana:
		err := sim.installGrafana(rc, options, result)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		}
	case ServiceTypeMattermost:
		err := sim.installMattermost(rc, options, result)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		}
	case ServiceTypeLxd:
		err := sim.installLxd(rc, options, result)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		}
	case ServiceTypeCaddy:
		err := sim.installCaddy(rc, options, result)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		}
	default:
		return nil, fmt.Errorf("installation not implemented for service: %s", options.Type)
	}

	// Post-installation validation (skip for dry run)
	if result.Success && !options.SkipHealthCheck && !options.DryRun {
		sim.performPostInstallationChecks(rc, options, result)
	}

	result.Duration = time.Since(start)
	
	if result.Success {
		logger.Info("Service installation completed successfully",
			zap.String("service", string(options.Type)),
			zap.Duration("duration", result.Duration))
	} else {
		logger.Error("Service installation failed",
			zap.String("service", string(options.Type)),
			zap.String("error", result.Error),
			zap.Duration("duration", result.Duration))
	}

	return result, nil
}

// GetServiceStatus retrieves the status of an installed service
func (sim *ServiceInstallationManager) GetServiceStatus(rc *eos_io.RuntimeContext, serviceType ServiceType) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Getting service status", zap.String("service", string(serviceType)))

	status := &ServiceStatus{
		Name:      string(serviceType),
		Type:      serviceType,
		Status:    "unknown",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	switch serviceType {
	case ServiceTypeGrafana:
		return sim.getGrafanaStatus(rc, status)
	case ServiceTypeMattermost:
		return sim.getMattermostStatus(rc, status)
	case ServiceTypeLxd:
		return sim.getLxdStatus(rc, status)
	case ServiceTypeCaddy:
		return sim.getCaddyStatus(rc, status)
	default:
		return nil, fmt.Errorf("status check not implemented for service: %s", serviceType)
	}
}

// PerformHealthCheck performs a health check on a service
func (sim *ServiceInstallationManager) PerformHealthCheck(rc *eos_io.RuntimeContext, serviceType ServiceType, endpoint string) (*HealthCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	start := time.Now()
	result := &HealthCheckResult{
		Endpoint:  endpoint,
		Timestamp: start,
		Checks:    make([]HealthCheck, 0),
	}

	logger.Info("Performing health check", 
		zap.String("service", string(serviceType)),
		zap.String("endpoint", endpoint))

	// HTTP health check
	if endpoint != "" {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(endpoint)
		if err != nil {
			result.Error = err.Error()
			result.Checks = append(result.Checks, HealthCheck{
				Name:    "HTTP Check",
				Status:  "FAILED",
				Message: err.Error(),
			})
		} else {
			defer resp.Body.Close()
			result.StatusCode = resp.StatusCode
			result.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 400
			
			status := "PASSED"
			message := fmt.Sprintf("HTTP %d", resp.StatusCode)
			if !result.Healthy {
				status = "FAILED"
			}
			
			result.Checks = append(result.Checks, HealthCheck{
				Name:    "HTTP Check",
				Status:  status,
				Message: message,
			})
		}
	}

	// Process check
	processCheck := sim.checkServiceProcess(serviceType)
	result.Checks = append(result.Checks, processCheck)

	// Port check
	config, exists := sim.configurations[serviceType]
	if exists && config.DefaultPort > 0 {
		portCheck := sim.checkServicePort(config.DefaultPort)
		result.Checks = append(result.Checks, portCheck)
	}

	result.ResponseTime = time.Since(start)
	
	// Determine overall health
	if result.Healthy {
		for _, check := range result.Checks {
			if check.Status == "FAILED" {
				result.Healthy = false
				break
			}
		}
	}

	logger.Info("Health check completed",
		zap.String("service", string(serviceType)),
		zap.Bool("healthy", result.Healthy),
		zap.Duration("response_time", result.ResponseTime))

	return result, nil
}

// Helper methods

func (sim *ServiceInstallationManager) initializeServiceConfigurations() {
	// Grafana configuration
	sim.configurations[ServiceTypeGrafana] = &ServiceConfiguration{
		Type:          ServiceTypeGrafana,
		DefaultPort:   3000,
		DefaultMethod: MethodDocker,
		Dependencies:  []string{"docker"},
		HealthCheck: &HealthCheckConfig{
			Enabled:     true,
			Endpoint:    "/api/health",
			Timeout:     10 * time.Second,
			Interval:    30 * time.Second,
			Retries:     3,
			StartPeriod: 60 * time.Second,
		},
	}

	// Mattermost configuration
	sim.configurations[ServiceTypeMattermost] = &ServiceConfiguration{
		Type:          ServiceTypeMattermost,
		DefaultPort:   8065,
		DefaultMethod: MethodCompose,
		Dependencies:  []string{"docker", "docker-compose"},
		HealthCheck: &HealthCheckConfig{
			Enabled:     true,
			Endpoint:    "/api/v4/system/ping",
			Timeout:     10 * time.Second,
			Interval:    30 * time.Second,
			Retries:     3,
			StartPeriod: 120 * time.Second,
		},
	}

	// LXD configuration
	sim.configurations[ServiceTypeLxd] = &ServiceConfiguration{
		Type:          ServiceTypeLxd,
		DefaultPort:   0, // No default port
		DefaultMethod: MethodSnap,
		Dependencies:  []string{"snap"},
	}

	// Caddy configuration
	sim.configurations[ServiceTypeCaddy] = &ServiceConfiguration{
		Type:          ServiceTypeCaddy,
		DefaultPort:   80,
		DefaultMethod: MethodRepository,
		Dependencies:  []string{"curl", "gpg"},
	}
}

func (sim *ServiceInstallationManager) applyDefaults(options *ServiceInstallOptions, config *ServiceConfiguration) {
	if options.Port == 0 {
		options.Port = config.DefaultPort
	}
	if options.Method == "" {
		options.Method = config.DefaultMethod
	}
	if options.Version == "" {
		options.Version = "latest"
	}
}

func (sim *ServiceInstallationManager) performPreInstallationChecks(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, config *ServiceConfiguration, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check dependencies
	step := InstallationStep{
		Name:        "Dependency Check",
		Description: "Checking required dependencies",
		Status:      "running",
	}
	stepStart := time.Now()

	for _, dep := range config.Dependencies {
		if err := sim.checkDependency(dep); err != nil {
			step.Status = "failed"
			step.Error = fmt.Sprintf("Missing dependency: %s", dep)
			step.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, step)
			return fmt.Errorf("dependency check failed: %w", err)
		}
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	// Check port availability
	if options.Port > 0 {
		portStep := InstallationStep{
			Name:        "Port Check",
			Description: fmt.Sprintf("Checking port %d availability", options.Port),
			Status:      "running",
		}
		portStepStart := time.Now()

		if !sim.isPortAvailable(options.Port) {
			portStep.Status = "failed"
			portStep.Error = fmt.Sprintf("Port %d is already in use", options.Port)
			portStep.Duration = time.Since(portStepStart)
			result.Steps = append(result.Steps, portStep)
			
			if !options.Force {
				return fmt.Errorf("port %d is already in use", options.Port)
			}
			logger.Warn("Port is in use but continuing due to force flag", zap.Int("port", options.Port))
		}

		portStep.Status = "completed"
		portStep.Duration = time.Since(portStepStart)
		result.Steps = append(result.Steps, portStep)
	}

	logger.Info("Pre-installation checks completed successfully")
	return nil
}

func (sim *ServiceInstallationManager) performPostInstallationChecks(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) {
	logger := otelzap.Ctx(rc.Ctx)

	step := InstallationStep{
		Name:        "Health Check",
		Description: "Performing post-installation health check",
		Status:      "running",
	}
	stepStart := time.Now()

	// Build health check endpoint
	endpoint := ""
	if options.Port > 0 {
		config := sim.configurations[options.Type]
		if config != nil && config.HealthCheck != nil && config.HealthCheck.Endpoint != "" {
			endpoint = fmt.Sprintf("http://localhost:%d%s", options.Port, config.HealthCheck.Endpoint)
		}
	}

	// Perform health check with retries
	var lastErr error
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i*5) * time.Second)
		}

		healthResult, err := sim.PerformHealthCheck(rc, options.Type, endpoint)
		if err == nil && healthResult.Healthy {
			step.Status = "completed"
			step.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, step)
			result.Endpoints = append(result.Endpoints, endpoint)
			logger.Info("Post-installation health check passed")
			return
		}
		lastErr = err
	}

	step.Status = "failed"
	if lastErr != nil {
		step.Error = lastErr.Error()
	} else {
		step.Error = "Health check failed after retries"
	}
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	logger.Warn("Post-installation health check failed", zap.Error(lastErr))
}

func (sim *ServiceInstallationManager) checkDependency(dependency string) error {
	_, err := exec.LookPath(dependency)
	return err
}

func (sim *ServiceInstallationManager) isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

func (sim *ServiceInstallationManager) checkServiceProcess(serviceType ServiceType) HealthCheck {
	check := HealthCheck{
		Name: "Process Check",
	}

	var processName string
	switch serviceType {
	case ServiceTypeGrafana:
		processName = "grafana"
	case ServiceTypeMattermost:
		processName = "mattermost"
	case ServiceTypeLxd:
		processName = "lxd"
	case ServiceTypeCaddy:
		processName = "caddy"
	default:
		check.Status = "SKIPPED"
		check.Message = "Process check not configured"
		return check
	}

	cmd := exec.Command("pgrep", "-f", processName)
	if err := cmd.Run(); err != nil {
		check.Status = "FAILED"
		check.Message = fmt.Sprintf("Process '%s' not found", processName)
	} else {
		check.Status = "PASSED"
		check.Message = fmt.Sprintf("Process '%s' is running", processName)
	}

	return check
}

func (sim *ServiceInstallationManager) checkServicePort(port int) HealthCheck {
	check := HealthCheck{
		Name: "Port Check",
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 5*time.Second)
	if err != nil {
		check.Status = "FAILED"
		check.Message = fmt.Sprintf("Port %d is not accessible", port)
	} else {
		conn.Close()
		check.Status = "PASSED"
		check.Message = fmt.Sprintf("Port %d is accessible", port)
	}

	return check
}

func (sim *ServiceInstallationManager) runCommand(rc *eos_io.RuntimeContext, step string, command string, args ...string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Executing command", 
		zap.String("step", step),
		zap.String("command", command),
		zap.Strings("args", args))

	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		logger.Error("Command failed", 
			zap.String("step", step),
			zap.String("command", command),
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("command failed: %w", err)
	}

	logger.Info("Command completed successfully", 
		zap.String("step", step),
		zap.String("output", string(output)))

	return nil
}

func (sim *ServiceInstallationManager) createFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func (sim *ServiceInstallationManager) ensureDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// Stub method implementations for services not yet implemented

func (sim *ServiceInstallationManager) installMattermost(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	return fmt.Errorf("mattermost installation not yet implemented")
}

func (sim *ServiceInstallationManager) installLxd(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	return fmt.Errorf("lxd installation not yet implemented")
}

func (sim *ServiceInstallationManager) getMattermostStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	return status, fmt.Errorf("mattermost status check not yet implemented")
}

func (sim *ServiceInstallationManager) getLxdStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	return status, fmt.Errorf("lxd status check not yet implemented")
}