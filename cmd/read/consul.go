// cmd/read/consul.go

package read

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
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
)

func runReadConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

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

func getConsulAgentInfo(logger otelzap.LoggerWithCtx) (map[string]interface{}, error) {
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
		logger.Info("terminal prompt:   Status: ❌ Consul agent not responding")
		return err
	}

	logger.Info("terminal prompt:   Status:  Consul agent is healthy")

	// Check service status
	output, err := exec.Command("systemctl", "is-active", "consul").Output()
	if err != nil {
		logger.Info("terminal prompt:   Service: ❌ not running")
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

	ReadCmd.AddCommand(ConsulCmd)
}
