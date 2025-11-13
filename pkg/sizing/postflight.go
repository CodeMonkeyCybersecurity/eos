package sizing

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PostflightValidation verifies that deployed services are running within expected resource limits
func PostflightValidation(rc *eos_io.RuntimeContext, services []ServiceType) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting postflight resource validation",
		zap.Any("services", services))

	// ASSESS - Wait a moment for services to stabilize
	logger.Info("Waiting for services to stabilize...")
	time.Sleep(10 * time.Second)

	// Get current system metrics
	metrics, err := collectSystemMetrics(rc)
	if err != nil {
		return fmt.Errorf("failed to collect system metrics: %w", err)
	}

	// INTERVENE - Check each deployed service
	var issues []string
	var warnings []string

	// Check overall system health
	if metrics.CPUUsage > 90 {
		issues = append(issues, fmt.Sprintf("CPU usage critically high: %.1f%%", metrics.CPUUsage))
	} else if metrics.CPUUsage > 75 {
		warnings = append(warnings, fmt.Sprintf("CPU usage elevated: %.1f%%", metrics.CPUUsage))
	}

	if metrics.MemoryUsage > 90 {
		issues = append(issues, fmt.Sprintf("Memory usage critically high: %.1f%%", metrics.MemoryUsage))
	} else if metrics.MemoryUsage > 80 {
		warnings = append(warnings, fmt.Sprintf("Memory usage elevated: %.1f%%", metrics.MemoryUsage))
	}

	// Check service-specific health
	serviceHealthMap := make(map[ServiceType]ServiceHealth)
	for _, svcType := range services {
		health, err := checkServiceHealth(rc, svcType)
		if err != nil {
			logger.Warn("Failed to check service health",
				zap.String("service", string(svcType)),
				zap.Error(err))
			continue
		}
		serviceHealthMap[svcType] = health

		// Analyze health status
		if !health.Running {
			issues = append(issues, fmt.Sprintf("%s service is not running", svcType))
		} else {
			if health.CPUUsage > 50 {
				warnings = append(warnings,
					fmt.Sprintf("%s using high CPU: %.1f%%", svcType, health.CPUUsage))
			}
			if health.MemoryMB > 1024 && health.MemoryMB > getExpectedMemory(svcType)*2 {
				warnings = append(warnings,
					fmt.Sprintf("%s using excessive memory: %.0f MB", svcType, health.MemoryMB))
			}
		}
	}

	// EVALUATE - Report findings
	logger.Info("Postflight validation summary",
		zap.Float64("cpu_usage", metrics.CPUUsage),
		zap.Float64("memory_usage", metrics.MemoryUsage),
		zap.Int("running_services", len(serviceHealthMap)))

	// Display results to user
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:  Deployment Health Check")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: System Status:")
	logger.Info(fmt.Sprintf("terminal prompt:   CPU Usage:    %.1f%%", metrics.CPUUsage))
	logger.Info(fmt.Sprintf("terminal prompt:   Memory Usage: %.1f%%", metrics.MemoryUsage))
	logger.Info(fmt.Sprintf("terminal prompt:   Load Average: %.2f", metrics.LoadAverage))
	logger.Info("terminal prompt: ")

	if len(serviceHealthMap) > 0 {
		logger.Info("terminal prompt: Service Health:")
		for svcType, health := range serviceHealthMap {
			status := " Running"
			if !health.Running {
				status = " Not Running"
			}
			logger.Info(fmt.Sprintf("terminal prompt:   %s: %s (CPU: %.1f%%, Mem: %.0f MB)",
				svcType, status, health.CPUUsage, health.MemoryMB))
		}
		logger.Info("terminal prompt: ")
	}

	// Show issues if any
	if len(issues) > 0 {
		logger.Error("Critical issues detected", zap.Strings("issues", issues))
		logger.Info("terminal prompt:  Critical Issues Detected:")
		for _, issue := range issues {
			logger.Info(fmt.Sprintf("terminal prompt:   • %s", issue))
		}
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Recommended Actions:")
		logger.Info("terminal prompt:   • Check service logs: journalctl -xe")
		logger.Info("terminal prompt:   • Review resource allocation")
		logger.Info("terminal prompt:   • Consider scaling up hardware")
		return fmt.Errorf("postflight validation failed: %d critical issues found", len(issues))
	}

	// Show warnings if any
	if len(warnings) > 0 {
		logger.Warn("Performance warnings detected", zap.Strings("warnings", warnings))
		logger.Info("terminal prompt: Performance Warnings:")
		for _, warning := range warnings {
			logger.Info(fmt.Sprintf("terminal prompt:   • %s", warning))
		}
		logger.Info("terminal prompt: ")
	}

	// Provide optimization suggestions
	suggestions := generateOptimizationSuggestions(metrics, serviceHealthMap)
	if len(suggestions) > 0 {
		logger.Info("terminal prompt:  Optimization Suggestions:")
		for _, suggestion := range suggestions {
			logger.Info(fmt.Sprintf("terminal prompt:   • %s", suggestion))
		}
		logger.Info("terminal prompt: ")
	}

	logger.Info("terminal prompt:  Postflight validation completed successfully")
	return nil
}

// SystemMetrics contains current system performance metrics
type SystemMetrics struct {
	CPUUsage    float64
	MemoryUsage float64
	LoadAverage float64
	SwapUsage   float64
	ActiveProcs int
}

// ServiceHealth contains health information for a specific service
type ServiceHealth struct {
	Running     bool
	ProcessName string
	PID         int32
	CPUUsage    float64
	MemoryMB    float64
	Uptime      time.Duration
}

// collectSystemMetrics gathers current system performance metrics
func collectSystemMetrics(rc *eos_io.RuntimeContext) (*SystemMetrics, error) {
	logger := otelzap.Ctx(rc.Ctx)
	metrics := &SystemMetrics{}

	// Get CPU usage
	cpuPercent, err := cpu.Percent(3*time.Second, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}
	if len(cpuPercent) > 0 {
		metrics.CPUUsage = cpuPercent[0]
	}

	// Get memory usage
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory info: %w", err)
	}
	metrics.MemoryUsage = memInfo.UsedPercent

	// Get swap usage
	swapInfo, err := mem.SwapMemory()
	if err == nil {
		metrics.SwapUsage = swapInfo.UsedPercent
	}

	// Get load average
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "uptime",
		Capture: true,
	})
	if err == nil {
		// Parse load average from uptime output
		if idx := strings.Index(output, "load average:"); idx >= 0 {
			parts := strings.Split(output[idx+13:], ",")
			if len(parts) > 0 {
				var load float64
				_, _ = fmt.Sscanf(strings.TrimSpace(parts[0]), "%f", &load)
				metrics.LoadAverage = load
			}
		}
	}

	// Count active processes
	procs, _ := process.Processes()
	metrics.ActiveProcs = len(procs)

	logger.Debug("System metrics collected",
		zap.Float64("cpu_usage", metrics.CPUUsage),
		zap.Float64("memory_usage", metrics.MemoryUsage),
		zap.Float64("load_average", metrics.LoadAverage))

	return metrics, nil
}

// checkServiceHealth checks the health of a specific service
func checkServiceHealth(rc *eos_io.RuntimeContext, svcType ServiceType) (ServiceHealth, error) {
	logger := otelzap.Ctx(rc.Ctx)
	health := ServiceHealth{}

	// Map service types to process names
	processMap := map[ServiceType][]string{
		ServiceTypeWebServer:    {"nginx", "apache2", "caddy", "httpd"},
		ServiceTypeDatabase:     {"postgres", "mysql", "mariadb", "mongod"},
		ServiceTypeCache:        {"redis-server", "memcached"},
		ServiceTypeQueue:        {"rabbitmq-server", "kafka"},
		ServiceTypeProxy:        {"haproxy", "nginx", "caddy"},
		ServiceTypeMonitoring:   {"prometheus", "grafana-server"},
		ServiceTypeLogging:      {"elasticsearch", "logstash", "kibana"},
		ServiceTypeVault:        {"vault"},
		ServiceTypeOrchestrator: {"nomad", "consul"},
	}

	// Look for matching processes
	possibleNames := processMap[svcType]
	if len(possibleNames) == 0 {
		return health, fmt.Errorf("unknown service type: %s", svcType)
	}

	procs, err := process.Processes()
	if err != nil {
		return health, fmt.Errorf("failed to list processes: %w", err)
	}

	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			continue
		}

		// Check if this process matches our service
		for _, possibleName := range possibleNames {
			if strings.Contains(strings.ToLower(name), possibleName) {
				health.Running = true
				health.ProcessName = name
				health.PID = proc.Pid

				// Get CPU usage
				cpuPercent, err := proc.CPUPercent()
				if err == nil {
					health.CPUUsage = cpuPercent
				}

				// Get memory usage
				memInfo, err := proc.MemoryInfo()
				if err == nil {
					health.MemoryMB = float64(memInfo.RSS) / (1024 * 1024)
				}

				// Get process creation time for uptime
				createTime, err := proc.CreateTime()
				if err == nil {
					health.Uptime = time.Since(time.Unix(createTime/1000, 0))
				}

				logger.Debug("Service health collected",
					zap.String("service", string(svcType)),
					zap.String("process", name),
					zap.Int32("pid", proc.Pid),
					zap.Float64("cpu", health.CPUUsage),
					zap.Float64("memory_mb", health.MemoryMB))

				return health, nil
			}
		}
	}

	// Service not found running
	return health, nil
}

// getExpectedMemory returns the expected memory usage in MB for a service type
func getExpectedMemory(svcType ServiceType) float64 {
	// These are baseline expectations
	expectations := map[ServiceType]float64{
		ServiceTypeWebServer:    512,  // 512 MB
		ServiceTypeDatabase:     2048, // 2 GB
		ServiceTypeCache:        1024, // 1 GB
		ServiceTypeQueue:        512,  // 512 MB
		ServiceTypeProxy:        256,  // 256 MB
		ServiceTypeMonitoring:   1024, // 1 GB
		ServiceTypeLogging:      2048, // 2 GB
		ServiceTypeVault:        512,  // 512 MB
		ServiceTypeOrchestrator: 512,  // 512 MB
	}

	if expected, ok := expectations[svcType]; ok {
		return expected
	}
	return 512 // Default 512 MB
}

// generateOptimizationSuggestions creates optimization suggestions based on metrics
func generateOptimizationSuggestions(metrics *SystemMetrics, services map[ServiceType]ServiceHealth) []string {
	var suggestions []string

	// High CPU suggestions
	if metrics.CPUUsage > 70 {
		suggestions = append(suggestions, "Consider enabling CPU throttling or load balancing")
		if metrics.LoadAverage > float64(len(services)) {
			suggestions = append(suggestions, "Load average indicates CPU contention - consider scaling horizontally")
		}
	}

	// High memory suggestions
	if metrics.MemoryUsage > 80 {
		suggestions = append(suggestions, "Memory usage is high - consider increasing system RAM")
		if metrics.SwapUsage > 50 {
			suggestions = append(suggestions, "High swap usage detected - performance may be degraded")
		}
	}

	// Service-specific suggestions
	for svcType, health := range services {
		if health.Running && health.MemoryMB > getExpectedMemory(svcType)*3 {
			suggestions = append(suggestions,
				fmt.Sprintf("Check %s configuration for memory leaks or tune memory limits", svcType))
		}
	}

	// General optimization suggestions
	if len(services) > 5 && metrics.CPUUsage > 60 {
		suggestions = append(suggestions, "Consider distributing services across multiple nodes")
	}

	return suggestions
}
