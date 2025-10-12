// cmd/read/nomad.go

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

var NomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Read Nomad status and configuration",
	Long: `Display comprehensive information about the Nomad installation and cluster state.

This command shows:
- Nomad version and build information
- Agent mode (client/server)
- Cluster membership and leader
- Running jobs and allocations
- Node status and resources
- Server members (if in server mode)

EXAMPLES:
  # Show full Nomad status
  eos read nomad

  # Show Nomad status in JSON format
  eos read nomad --json

  # Show only cluster servers
  eos read nomad --servers

  # Show running jobs
  eos read nomad --jobs

  # Show node status
  eos read nomad --nodes`,
	RunE: eos.Wrap(runReadNomad),
}

var (
	nomadJSON    bool
	nomadServers bool
	nomadJobs    bool
	nomadNodes   bool
)

func runReadNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Nomad is installed
	nomadPath, err := exec.LookPath("nomad")
	if err != nil {
		logger.Error("Nomad not found in PATH")
		return fmt.Errorf("Nomad is not installed. Install with: eos create nomad")
	}

	logger.Info("Nomad binary found", zap.String("path", nomadPath))

	// Get Nomad version
	versionOutput, err := exec.Command("nomad", "version").Output()
	if err != nil {
		logger.Warn("Failed to get Nomad version", zap.Error(err))
	} else {
		logger.Info("terminal prompt: Nomad Version:")
		logger.Info("terminal prompt:   " + strings.TrimSpace(string(versionOutput)))
	}

	// Check if Nomad is running
	if err := exec.Command("nomad", "agent-info").Run(); err != nil {
		logger.Warn("Nomad agent not responding (may not be running)")
		logger.Info("terminal prompt: Status: Nomad is not running")
		logger.Info("terminal prompt: Start with: sudo systemctl start nomad")
		return nil
	}

	// Get agent info
	agentInfo, err := getNomadAgentInfo(logger)
	if err != nil {
		logger.Warn("Failed to get agent info", zap.Error(err))
		return err
	}

	// Display based on flags
	if nomadJSON {
		jsonData, _ := json.MarshalIndent(agentInfo, "", "  ")
		logger.Info("terminal prompt: " + string(jsonData))
		return nil
	}

	// Display formatted output
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: === Nomad Agent Information ===")
	displayNomadAgentInfo(logger, agentInfo)

	if nomadServers || (!nomadServers && !nomadJobs && !nomadNodes) {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: === Server Members ===")
		if err := displayServerMembers(logger); err != nil {
			logger.Debug("Failed to get server members (may not be in server mode)", zap.Error(err))
		}
	}

	if nomadNodes || (!nomadServers && !nomadJobs && !nomadNodes) {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: === Node Status ===")
		if err := displayNodeStatus(logger); err != nil {
			logger.Warn("Failed to get node status", zap.Error(err))
		}
	}

	if nomadJobs || (!nomadServers && !nomadJobs && !nomadNodes) {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: === Running Jobs ===")
		if err := displayJobs(logger); err != nil {
			logger.Warn("Failed to get jobs", zap.Error(err))
		}
	}

	// Health check
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: === Health Status ===")
	displayNomadHealthStatus(logger)

	return nil
}

func getNomadAgentInfo(logger otelzap.LoggerWithCtx) (map[string]interface{}, error) {
	output, err := exec.Command("nomad", "agent-info").Output()
	if err != nil {
		return nil, err
	}

	// Parse nomad agent-info output
	info := make(map[string]interface{})
	lines := strings.Split(string(output), "\n")

	currentSection := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Section headers (lines without = or :)
		if !strings.Contains(line, "=") {
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

func displayNomadAgentInfo(logger otelzap.LoggerWithCtx, info map[string]interface{}) {
	// Display key information
	if agent, ok := info["agent"].(map[string]string); ok {
		logger.Info("terminal prompt:   Mode: " + getOrDefault(agent, "server", "client"))
		logger.Info("terminal prompt:   Node: " + getOrDefault(agent, "name", "unknown"))
		logger.Info("terminal prompt:   Datacenter: " + getOrDefault(agent, "datacenter", "unknown"))
		logger.Info("terminal prompt:   Region: " + getOrDefault(agent, "region", "unknown"))
	}

	if build, ok := info["build"].(map[string]string); ok {
		logger.Info("terminal prompt:   Version: " + getOrDefault(build, "version", "unknown"))
		logger.Info("terminal prompt:   Revision: " + getOrDefault(build, "revision", "unknown"))
	}

	if stats, ok := info["stats"].(map[string]string); ok {
		if allocations := getOrDefault(stats, "client.allocations.running", ""); allocations != "" {
			logger.Info("terminal prompt:   Running Allocations: " + allocations)
		}
	}
}

func displayServerMembers(logger otelzap.LoggerWithCtx) error {
	output, err := exec.Command("nomad", "server", "members").Output()
	if err != nil {
		return err
	}

	logger.Info("terminal prompt: " + string(output))
	return nil
}

func displayNodeStatus(logger otelzap.LoggerWithCtx) error {
	output, err := exec.Command("nomad", "node", "status").Output()
	if err != nil {
		return err
	}

	if strings.TrimSpace(string(output)) == "" {
		logger.Info("terminal prompt:   No nodes registered")
		return nil
	}

	logger.Info("terminal prompt: " + string(output))
	return nil
}

func displayJobs(logger otelzap.LoggerWithCtx) error {
	output, err := exec.Command("nomad", "job", "status").Output()
	if err != nil {
		return err
	}

	if strings.TrimSpace(string(output)) == "" || strings.Contains(string(output), "No running jobs") {
		logger.Info("terminal prompt:   No running jobs")
		return nil
	}

	logger.Info("terminal prompt: " + string(output))
	return nil
}

func displayNomadHealthStatus(logger otelzap.LoggerWithCtx) {
	// Check if agent is responding
	if err := exec.Command("nomad", "agent-info").Run(); err != nil {
		logger.Info("terminal prompt:   Status:  Nomad agent not responding")
		return
	}

	logger.Info("terminal prompt:   Status:  Nomad agent is healthy")

	// Check service status
	output, err := exec.Command("systemctl", "is-active", "nomad").Output()
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
}

func init() {
	NomadCmd.Flags().BoolVar(&nomadJSON, "json", false, "Output in JSON format")
	NomadCmd.Flags().BoolVar(&nomadServers, "servers", false, "Show only server members")
	NomadCmd.Flags().BoolVar(&nomadJobs, "jobs", false, "Show only running jobs")
	NomadCmd.Flags().BoolVar(&nomadNodes, "nodes", false, "Show only node status")

	ReadCmd.AddCommand(NomadCmd)
}
