// cmd/read/consul.go

package read

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var ConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Read Consul status and configuration",
	Long: `Display comprehensive information about the Consul installation and cluster state.

This command shows:
- Consul version and build information
- Agent mode (client/server)
- Cluster membership and health
- Service discovery status
- Key/Value store accessibility
- Network configuration
- Performance metrics

EXAMPLES:
  # Show full Consul status
  eos read consul

  # Run comprehensive health check (recommended after cluster setup)
  eos read consul --health

  # Show Consul status in JSON format
  eos read consul --json

  # Show only cluster members
  eos read consul --members

  # Show registered services
  eos read consul --services`,
	RunE: eos.Wrap(runReadConsul),
}

var (
	consulJSON     bool
	consulMembers  bool
	consulServices bool
	consulHealth   bool
)

func runReadConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// If --health flag is set, run comprehensive health check
	if consulHealth {
		return runConsulHealthCheck(rc)
	}

	// Check if Consul is installed
	consulPath, err := exec.LookPath("consul")
	if err != nil {
		logger.Error("Consul not found in PATH")
		return fmt.Errorf("Consul is not installed. Install with: eos create consul")
	}

	logger.Info("Consul binary found", zap.String("path", consulPath))

	// Get Consul version
	versionOutput, err := exec.Command("consul", "version").Output()
	if err != nil {
		logger.Warn("Failed to get Consul version", zap.Error(err))
	} else {
		logger.Info("terminal prompt: Consul Version:")
		logger.Info("terminal prompt:   " + strings.TrimSpace(string(versionOutput)))
	}

	// Get agent info
	agentInfo, err := getConsulAgentInfo(logger)
	if err != nil {
		logger.Warn("Failed to get agent info (Consul may not be running)", zap.Error(err))
		logger.Info("terminal prompt: Status: Consul is not running")
		logger.Info("terminal prompt: Start with: sudo systemctl start consul")
		return nil
	}

	// Display based on flags
	if consulJSON {
		jsonData, _ := json.MarshalIndent(agentInfo, "", "  ")
		logger.Info("terminal prompt: " + string(jsonData))
		return nil
	}

	// Display formatted output
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: === Consul Agent Information ===")
	displayAgentInfo(logger, agentInfo)

	if consulMembers || (!consulMembers && !consulServices) {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: === Cluster Members ===")
		if err := displayClusterMembers(logger); err != nil {
			logger.Warn("Failed to get cluster members", zap.Error(err))
		}
	}

	if consulServices || (!consulMembers && !consulServices) {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: === Registered Services ===")
		if err := displayServices(logger); err != nil {
			logger.Warn("Failed to get services", zap.Error(err))
		}
	}

	// Health check
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: === Health Status ===")
	if err := displayHealthStatus(logger); err != nil {
		logger.Warn("Failed to get health status", zap.Error(err))
	}

	return nil
}

// runConsulHealthCheck runs comprehensive health check using pkg/consul business logic
func runConsulHealthCheck(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ================================================================================")
	logger.Info("terminal prompt: Consul Cluster Health Check")
	logger.Info("terminal prompt: ================================================================================")
	logger.Info("terminal prompt: ")

	// Run health check (business logic in pkg/consul/health_check.go)
	result, err := consul.CheckHealth(rc)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	// Display results
	displayHealthCheckResults(logger, result)

	return nil
}

// displayHealthCheckResults displays comprehensive health check results
func displayHealthCheckResults(logger otelzap.LoggerWithCtx, result *consul.HealthCheckResult) {
	// Overall status
	statusIcon := getStatusIcon(result.Overall)
	logger.Info("terminal prompt: OVERALL STATUS: " + statusIcon + " " + string(result.Overall))
	logger.Info("terminal prompt: ")

	// Agent Health
	logger.Info("terminal prompt: === Local Agent Health ===")
	agentIcon := getStatusIcon(result.Agent.Status)
	logger.Info("terminal prompt:   Status:      " + agentIcon + " " + string(result.Agent.Status))
	logger.Info("terminal prompt:   Running:     " + formatBool(result.Agent.Running))
	logger.Info("terminal prompt:   Reachable:   " + formatBool(result.Agent.Reachable))
	if result.Agent.NodeName != "" {
		logger.Info("terminal prompt:   Node:        " + result.Agent.NodeName)
	}
	if result.Agent.Datacenter != "" {
		logger.Info("terminal prompt:   Datacenter:  " + result.Agent.Datacenter)
	}
	if result.Agent.Version != "" {
		logger.Info("terminal prompt:   Version:     " + result.Agent.Version)
	}
	if len(result.Agent.Issues) > 0 {
		logger.Info("terminal prompt:   Issues:")
		for _, issue := range result.Agent.Issues {
			logger.Info("terminal prompt:     • " + issue)
		}
	}
	logger.Info("terminal prompt: ")

	// Cluster Health
	if result.Agent.Running {
		logger.Info("terminal prompt: === Cluster Health ===")
		clusterIcon := getStatusIcon(result.Cluster.Status)
		logger.Info("terminal prompt:   Status:      " + clusterIcon + " " + string(result.Cluster.Status))
		logger.Info("terminal prompt:   Members:     " + fmt.Sprintf("%d", result.Cluster.MemberCount))
		logger.Info("terminal prompt:   Leader:      " + formatBool(result.Cluster.LeaderPresent))
		if result.Cluster.Leader != "" {
			logger.Info("terminal prompt:   Leader Node: " + result.Cluster.Leader)
		}

		if len(result.Cluster.Members) > 0 {
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt:   Cluster Members:")
			for _, member := range result.Cluster.Members {
				memberStatus := "✓"
				if member.Status != "alive" {
					memberStatus = "✗"
				}
				logger.Info("terminal prompt:     " + memberStatus + " " + member.Name + " (" + member.Address + ") - " + member.Status)
			}
		}

		if len(result.Cluster.Issues) > 0 {
			logger.Info("terminal prompt:   Issues:")
			for _, issue := range result.Cluster.Issues {
				logger.Info("terminal prompt:     • " + issue)
			}
		}
		logger.Info("terminal prompt: ")

		// Services Health
		logger.Info("terminal prompt: === Services Health ===")
		servicesIcon := getStatusIcon(result.Services.Status)
		logger.Info("terminal prompt:   Status:      " + servicesIcon + " " + string(result.Services.Status))
		logger.Info("terminal prompt:   Total:       " + fmt.Sprintf("%d", result.Services.TotalServices))
		logger.Info("terminal prompt:   Healthy:     " + fmt.Sprintf("%d", result.Services.HealthyServices))

		if len(result.Services.Services) > 0 {
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt:   Registered Services:")
			for _, service := range result.Services.Services {
				serviceStatus := "✓"
				if !service.Healthy {
					serviceStatus = "✗"
				}
				logger.Info("terminal prompt:     " + serviceStatus + " " + service.Name +
					fmt.Sprintf(" (passing: %d, warning: %d, critical: %d)",
						service.Passing, service.Warning, service.Critical))
			}
		}

		if len(result.Services.Issues) > 0 {
			logger.Info("terminal prompt:   Issues:")
			for _, issue := range result.Services.Issues {
				logger.Info("terminal prompt:     • " + issue)
			}
		}
		logger.Info("terminal prompt: ")

		// KV Store Health
		logger.Info("terminal prompt: === KV Store Health ===")
		kvIcon := getStatusIcon(result.KV.Status)
		logger.Info("terminal prompt:   Status:      " + kvIcon + " " + string(result.KV.Status))
		logger.Info("terminal prompt:   Accessible:  " + formatBool(result.KV.Accessible))
		logger.Info("terminal prompt:   Writeable:   " + formatBool(result.KV.Writeable))

		if len(result.KV.Issues) > 0 {
			logger.Info("terminal prompt:   Issues:")
			for _, issue := range result.KV.Issues {
				logger.Info("terminal prompt:     • " + issue)
			}
		}
		logger.Info("terminal prompt: ")
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		logger.Info("terminal prompt: === Recommendations ===")
		for i, rec := range result.Recommendations {
			logger.Info("terminal prompt:   " + fmt.Sprintf("%d.", i+1) + " " + rec)
		}
		logger.Info("terminal prompt: ")
	}

	logger.Info("terminal prompt: ================================================================================")
	logger.Info("terminal prompt: Health Check completed at: " + result.Timestamp.Format("2006-01-02 15:04:05"))
	logger.Info("terminal prompt: ================================================================================")
}

// Helper functions for display
func getStatusIcon(status consul.HealthStatus) string {
	switch status {
	case consul.HealthStatusHealthy:
		return "✓"
	case consul.HealthStatusDegraded:
		return "⚠"
	case consul.HealthStatusUnhealthy:
		return "✗"
	default:
		return "?"
	}
}

func formatBool(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func getConsulAgentInfo(_ otelzap.LoggerWithCtx) (map[string]interface{}, error) {
	output, err := exec.Command("consul", "info").Output()
	if err != nil {
		return nil, err
	}

	// Parse consul info output
	info := make(map[string]interface{})
	lines := strings.Split(string(output), "\n")

	currentSection := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Section headers
		if !strings.Contains(line, "=") && !strings.Contains(line, ":") {
			currentSection = line
			info[currentSection] = make(map[string]string)
			continue
		}

		// Key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if currentSection != "" {
				if sectionMap, ok := info[currentSection].(map[string]string); ok {
					sectionMap[key] = value
				}
			} else {
				info[key] = value
			}
		}
	}

	return info, nil
}

func displayAgentInfo(logger otelzap.LoggerWithCtx, info map[string]interface{}) {
	// Display key information
	if agent, ok := info["agent"].(map[string]string); ok {
		logger.Info("terminal prompt:   Mode: " + getOrDefault(agent, "server", "unknown"))
		logger.Info("terminal prompt:   Node: " + getOrDefault(agent, "node", "unknown"))
		logger.Info("terminal prompt:   Datacenter: " + getOrDefault(agent, "datacenter", "unknown"))
	}

	if build, ok := info["build"].(map[string]string); ok {
		logger.Info("terminal prompt:   Version: " + getOrDefault(build, "version", "unknown"))
		logger.Info("terminal prompt:   Revision: " + getOrDefault(build, "revision", "unknown"))
	}

	if runtime, ok := info["runtime"].(map[string]string); ok {
		logger.Info("terminal prompt:   Go Version: " + getOrDefault(runtime, "version", "unknown"))
	}
}

func displayClusterMembers(logger otelzap.LoggerWithCtx) error {
	output, err := exec.Command("consul", "members").Output()
	if err != nil {
		return err
	}

	logger.Info("terminal prompt: " + string(output))
	return nil
}

func displayServices(logger otelzap.LoggerWithCtx) error {
	output, err := exec.Command("consul", "catalog", "services").Output()
	if err != nil {
		return err
	}

	services := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(services) == 0 || (len(services) == 1 && services[0] == "") {
		logger.Info("terminal prompt:   No services registered")
		return nil
	}

	for _, service := range services {
		service = strings.TrimSpace(service)
		if service != "" {
			logger.Info("terminal prompt:   - " + service)
		}
	}

	return nil
}

func displayHealthStatus(logger otelzap.LoggerWithCtx) error {
	// Check if agent is responding
	if err := exec.Command("consul", "info").Run(); err != nil {
		logger.Info("terminal prompt:   Status:  Consul agent not responding")
		return err
	}

	logger.Info("terminal prompt:   Status:  Consul agent is healthy")

	// Check service status
	output, err := exec.Command("systemctl", "is-active", "consul").Output()
	if err != nil {
		logger.Info("terminal prompt:   Service:  not running")
	} else {
		status := strings.TrimSpace(string(output))
		if status == "active" {
			logger.Info("terminal prompt:   Service:  active")
		} else {
			logger.Info("terminal prompt:   Service: " + status)
		}
	}

	return nil
}

func getOrDefault(m map[string]string, key, defaultValue string) string {
	if val, ok := m[key]; ok {
		return val
	}
	return defaultValue
}

func init() {
	ConsulCmd.Flags().BoolVar(&consulJSON, "json", false, "Output in JSON format")
	ConsulCmd.Flags().BoolVar(&consulMembers, "members", false, "Show only cluster members")
	ConsulCmd.Flags().BoolVar(&consulServices, "services", false, "Show only registered services")
	ConsulCmd.Flags().BoolVar(&consulHealth, "health", false, "Run comprehensive cluster health check")

	ReadCmd.AddCommand(ConsulCmd)
}
