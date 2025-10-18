// cmd/debug/wazuh.go
package debug

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var wazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Diagnose Wazuh components (agent, server, indexer, dashboard, manager)",
	Long: `Comprehensive diagnostic tool for Wazuh/Delphi components.

Automatically detects which Wazuh components are running on this machine:
  • Wazuh Agent       - Security monitoring agent
  • Wazuh Manager     - Central management server
  • Wazuh Indexer     - OpenSearch-based indexer
  • Wazuh Dashboard   - Web UI dashboard
  • Wazuh Server      - Legacy server component

For each detected component, performs relevant diagnostics:
  • Service status and health checks
  • Configuration file validation
  • Log file analysis (last 20-50 lines)
  • Port connectivity checks
  • Process and resource usage
  • Common issue detection
  • Actionable remediation steps

Flags:
  --component <name>  Only check specific component (agent|manager|indexer|dashboard|server)
  --logs <n>          Number of log lines to display (default: 30)
  --verbose           Show detailed diagnostic output
  --fix               Attempt automatic fixes for common issues (requires sudo)

Examples:
  eos debug wazuh                           # Auto-detect and diagnose all components
  eos debug wazuh --component agent         # Only diagnose Wazuh agent
  eos debug wazuh --component manager --logs 50  # Manager with 50 log lines
  eos debug wazuh --verbose                 # Detailed output`,
	RunE: eos.Wrap(runWazuhDebug),
}

var (
	wazuhComponent string
	wazuhLogLines  int
	wazuhVerbose   bool
	wazuhFix       bool
)

func init() {
	wazuhCmd.Flags().StringVar(&wazuhComponent, "component", "", "Specific component to check")
	wazuhCmd.Flags().IntVar(&wazuhLogLines, "logs", 30, "Number of log lines to display")
	wazuhCmd.Flags().BoolVar(&wazuhVerbose, "verbose", false, "Show detailed diagnostic output")
	wazuhCmd.Flags().BoolVar(&wazuhFix, "fix", false, "Attempt automatic fixes")
	debugCmd.AddCommand(wazuhCmd)
}

type WazuhComponent string

const (
	ComponentAgent     WazuhComponent = "agent"
	ComponentManager   WazuhComponent = "manager"
	ComponentIndexer   WazuhComponent = "indexer"
	ComponentDashboard WazuhComponent = "dashboard"
	ComponentServer    WazuhComponent = "server"
)

type ComponentInfo struct {
	Name        WazuhComponent
	ServiceName string
	Detected    bool
	Running     bool
	ConfigPaths []string
	LogPaths    []string
	Ports       []int
	DataDirs    []string
}

type DiagnosticResult struct {
	Component   WazuhComponent
	CheckName   string
	Category    string
	Passed      bool
	Warning     bool
	Error       error
	Details     string
	Remediation []string
}

func runWazuhDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting Wazuh diagnostics",
		zap.String("component_filter", wazuhComponent),
		zap.Int("log_lines", wazuhLogLines))

	components := detectWazuhComponents(rc)
	
	if len(components) == 0 {
		fmt.Println("\n❌ No Wazuh components detected on this system")
		fmt.Println("\nTo install Wazuh components:")
		fmt.Println("  • Agent:     eos create wazuh-agent")
		fmt.Println("  • Manager:   eos create delphi")
		return nil
	}

	if wazuhComponent != "" {
		filtered := make(map[WazuhComponent]*ComponentInfo)
		comp := WazuhComponent(wazuhComponent)
		if info, exists := components[comp]; exists {
			filtered[comp] = info
			components = filtered
		} else {
			return fmt.Errorf("component '%s' not found on this system", wazuhComponent)
		}
	}

	displayDetectedComponents(components)

	var allResults []DiagnosticResult
	for _, info := range components {
		if !info.Detected {
			continue
		}
		
		results := diagnoseComponent(rc, info)
		allResults = append(allResults, results...)
	}

	displayWazuhResults(allResults)

	if wazuhFix {
		applyAutomaticFixes(rc, allResults)
	}

	return nil
}

func detectWazuhComponents(rc *eos_io.RuntimeContext) map[WazuhComponent]*ComponentInfo {
	components := map[WazuhComponent]*ComponentInfo{
		ComponentAgent: {
			Name:        ComponentAgent,
			ServiceName: "wazuh-agent",
			ConfigPaths: []string{"/var/ossec/etc/ossec.conf"},
			LogPaths:    []string{"/var/ossec/logs/ossec.log"},
			DataDirs:    []string{"/var/ossec"},
		},
		ComponentManager: {
			Name:        ComponentManager,
			ServiceName: "wazuh-manager",
			ConfigPaths: []string{"/var/ossec/etc/ossec.conf"},
			LogPaths:    []string{"/var/ossec/logs/ossec.log", "/var/ossec/logs/api.log"},
			Ports:       []int{1514, 1515, 55000},
			DataDirs:    []string{"/var/ossec"},
		},
		ComponentIndexer: {
			Name:        ComponentIndexer,
			ServiceName: "wazuh-indexer",
			ConfigPaths: []string{"/etc/wazuh-indexer/opensearch.yml"},
			LogPaths:    []string{"/var/log/wazuh-indexer/wazuh-indexer.log"},
			Ports:       []int{9200, 9300},
			DataDirs:    []string{"/var/lib/wazuh-indexer"},
		},
		ComponentDashboard: {
			Name:        ComponentDashboard,
			ServiceName: "wazuh-dashboard",
			ConfigPaths: []string{"/etc/wazuh-dashboard/opensearch_dashboards.yml"},
			LogPaths:    []string{"/var/log/wazuh-dashboard/wazuh-dashboard.log"},
			Ports:       []int{443, 5601},
			DataDirs:    []string{"/var/lib/wazuh-dashboard"},
		},
	}

	for _, info := range components {
		ctx, cancel := context.WithTimeout(rc.Ctx, 2*time.Second)
		cmd := exec.CommandContext(ctx, "systemctl", "list-unit-files", info.ServiceName+".service")
		output, err := cmd.Output()
		cancel()

		if err == nil && strings.Contains(string(output), info.ServiceName) {
			info.Detected = true
			
			ctx2, cancel2 := context.WithTimeout(rc.Ctx, 2*time.Second)
			statusCmd := exec.CommandContext(ctx2, "systemctl", "is-active", info.ServiceName)
			statusOutput, _ := statusCmd.Output()
			cancel2()
			
			info.Running = strings.TrimSpace(string(statusOutput)) == "active"
		}
	}

	return components
}

func diagnoseComponent(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	results = append(results, checkServiceStatus(info))
	results = append(results, checkConfigFiles(rc, info)...)
	results = append(results, analyzeComponentLogs(rc, info)...)
	
	if len(info.Ports) > 0 {
		results = append(results, checkPorts(rc, info)...)
	}

	results = append(results, checkProcessResources(rc, info))

	switch info.Name {
	case ComponentAgent:
		results = append(results, diagnoseAgent(rc, info)...)
	case ComponentManager:
		results = append(results, diagnoseManager(rc, info)...)
	case ComponentIndexer:
		results = append(results, diagnoseIndexer(rc, info)...)
	case ComponentDashboard:
		results = append(results, diagnoseDashboard(rc, info)...)
	}

	return results
}

func checkServiceStatus(info *ComponentInfo) DiagnosticResult {
	if !info.Running {
		return DiagnosticResult{
			Component: info.Name,
			CheckName: "Service Status",
			Category:  "System",
			Passed:    false,
			Error:     fmt.Errorf("service %s is not running", info.ServiceName),
			Remediation: []string{
				fmt.Sprintf("Start service: sudo systemctl start %s", info.ServiceName),
				fmt.Sprintf("Check logs: sudo journalctl -u %s -n 50", info.ServiceName),
			},
		}
	}

	return DiagnosticResult{
		Component: info.Name,
		CheckName: "Service Status",
		Category:  "System",
		Passed:    true,
		Details:   fmt.Sprintf("Service %s is active and running", info.ServiceName),
	}
}

func checkConfigFiles(_ *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	for _, configPath := range info.ConfigPaths {
		fileInfo, err := os.Stat(configPath)
		
		if os.IsNotExist(err) {
			results = append(results, DiagnosticResult{
				Component: info.Name,
				CheckName: fmt.Sprintf("Config: %s", filepath.Base(configPath)),
				Category:  "Configuration",
				Passed:    false,
				Error:     fmt.Errorf("config file not found: %s", configPath),
			})
			continue
		}

		details := fmt.Sprintf("Size: %d bytes, Perms: %s", fileInfo.Size(), fileInfo.Mode().Perm())

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Config: %s", filepath.Base(configPath)),
			Category:  "Configuration",
			Passed:    true,
			Details:   details,
		})
	}

	return results
}

func analyzeComponentLogs(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	for _, logPath := range info.LogPaths {
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			continue
		}

		ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
		cmd := exec.CommandContext(ctx, "tail", "-n", fmt.Sprint(wazuhLogLines), logPath)
		output, err := cmd.Output()
		cancel()

		if err != nil {
			continue
		}

		logContent := string(output)
		var errors []string
		lines := strings.Split(logContent, "\n")
		
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "error") || strings.Contains(lineLower, "fatal") {
				errors = append(errors, line)
			}
		}

		details := fmt.Sprintf("Last %d lines from %s", wazuhLogLines, filepath.Base(logPath))
		if len(errors) > 0 {
			details += fmt.Sprintf("\n\nFound %d error(s) - showing first 3:", len(errors))
			for i, e := range errors {
				if i < 3 {
					details += "\n  • " + e
				}
			}
		}

		if wazuhVerbose {
			details += "\n\nRecent logs:\n" + logContent
		}

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Logs: %s", filepath.Base(logPath)),
			Category:  "Logs",
			Passed:    len(errors) == 0,
			Details:   details,
		})
	}

	return results
}

func checkPorts(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ss", "-tlnp")
	output, err := cmd.Output()
	
	if err != nil {
		return results
	}

	portsOutput := string(output)

	for _, port := range info.Ports {
		portStr := fmt.Sprintf(":%d", port)
		listening := strings.Contains(portsOutput, portStr)

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Port %d", port),
			Category:  "Network",
			Passed:    listening,
			Error: func() error {
				if !listening {
					return fmt.Errorf("port %d not listening", port)
				}
				return nil
			}(),
			Details: func() string {
				if listening {
					return fmt.Sprintf("Port %d is listening", port)
				}
				return ""
			}(),
		})
	}

	return results
}

func checkProcessResources(rc *eos_io.RuntimeContext, info *ComponentInfo) DiagnosticResult {
	if !info.Running {
		return DiagnosticResult{
			Component: info.Name,
			CheckName: "Process Resources",
			Category:  "System",
			Passed:    false,
		}
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.Output()
	
	if err != nil {
		return DiagnosticResult{
			Component: info.Name,
			CheckName: "Process Resources",
			Category:  "System",
			Passed:    true,
			Warning:   true,
		}
	}

	var processLines []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, info.ServiceName) {
			processLines = append(processLines, line)
		}
	}

	details := fmt.Sprintf("Found %d process(es)", len(processLines))
	if wazuhVerbose && len(processLines) > 0 {
		details += "\n" + strings.Join(processLines, "\n")
	}

	return DiagnosticResult{
		Component: info.Name,
		CheckName: "Process Resources",
		Category:  "System",
		Passed:    len(processLines) > 0,
		Details:   details,
	}
}

func diagnoseAgent(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	clientKeysPath := "/var/ossec/etc/client.keys"
	if data, err := os.ReadFile(clientKeysPath); err == nil {
		if len(data) == 0 {
			results = append(results, DiagnosticResult{
				Component: info.Name,
				CheckName: "Agent Registration",
				Category:  "Configuration",
				Passed:    false,
				Error:     fmt.Errorf("agent not registered"),
				Remediation: []string{
					"Register agent: sudo /var/ossec/bin/agent-auth -m <manager-ip>",
				},
			})
		} else {
			results = append(results, DiagnosticResult{
				Component: info.Name,
				CheckName: "Agent Registration",
				Category:  "Configuration",
				Passed:    true,
				Details:   "Agent is registered",
			})
		}
	}

	return results
}

func diagnoseManager(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "https://localhost:55000/")
	output, err := cmd.Output()
	cancel()

	apiWorking := err == nil && strings.Contains(string(output), "Wazuh")

	results = append(results, DiagnosticResult{
		Component: info.Name,
		CheckName: "Wazuh API",
		Category:  "Service",
		Passed:    apiWorking,
		Details: func() string {
			if apiWorking {
				return "API is responding"
			}
			return "API not responding"
		}(),
	})

	return results
}

func diagnoseIndexer(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "-u", "admin:admin", 
		"https://localhost:9200/_cluster/health")
	output, err := cmd.Output()
	cancel()

	if err == nil {
		status := "unknown"
		if strings.Contains(string(output), `"green"`) {
			status = "green"
		} else if strings.Contains(string(output), `"yellow"`) {
			status = "yellow"
		} else if strings.Contains(string(output), `"red"`) {
			status = "red"
		}

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: "Cluster Health",
			Category:  "Service",
			Passed:    status == "green" || status == "yellow",
			Warning:   status == "yellow",
			Details:   fmt.Sprintf("Cluster status: %s", status),
		})
	}

	return results
}

func diagnoseDashboard(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "https://localhost:443/app/wazuh")
	err := cmd.Run()
	cancel()

	results = append(results, DiagnosticResult{
		Component: info.Name,
		CheckName: "Dashboard Access",
		Category:  "Service",
		Passed:    err == nil,
		Details: func() string {
			if err == nil {
				return "Dashboard is accessible"
			}
			return "Dashboard not accessible"
		}(),
	})

	return results
}

func displayDetectedComponents(components map[WazuhComponent]*ComponentInfo) {
	fmt.Println("\n🔍 Detected Wazuh Components:")
	fmt.Println(strings.Repeat("=", 60))
	
	for _, info := range components {
		if !info.Detected {
			continue
		}
		
		status := "❌ Stopped"
		if info.Running {
			status = "✅ Running"
		}
		
		fmt.Printf("  • %-15s %s\n", string(info.Name), status)
	}
	fmt.Println()
}

func displayWazuhResults(results []DiagnosticResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println("\n📊 Diagnostic Results:")
	fmt.Println(strings.Repeat("=", 60))

	currentComponent := WazuhComponent("")
	
	for _, result := range results {
		if result.Component != currentComponent {
			currentComponent = result.Component
			fmt.Printf("\n[%s]\n", strings.ToUpper(string(currentComponent)))
		}

		icon := "✅"
		if !result.Passed {
			if result.Warning {
				icon = "⚠️ "
			} else {
				icon = "❌"
			}
		}

		fmt.Printf("%s %s (%s)\n", icon, result.CheckName, result.Category)
		
		if result.Details != "" {
			fmt.Printf("   %s\n", result.Details)
		}
		
		if result.Error != nil {
			fmt.Printf("   Error: %s\n", result.Error)
		}
		
		if len(result.Remediation) > 0 {
			fmt.Println("   Remediation:")
			for _, rem := range result.Remediation {
				fmt.Printf("     • %s\n", rem)
			}
		}
	}
	
	passed := 0
	failed := 0
	warnings := 0
	
	for _, r := range results {
		if r.Passed {
			passed++
		} else if r.Warning {
			warnings++
		} else {
			failed++
		}
	}
	
	fmt.Printf("\n📈 Summary: %d passed, %d failed, %d warnings\n\n", passed, failed, warnings)
}

func applyAutomaticFixes(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Attempting automatic fixes")
	
	fmt.Println("\n🔧 Attempting Automatic Fixes:")
	fmt.Println(strings.Repeat("=", 60))
	
	for _, result := range results {
		if result.Passed || len(result.Remediation) == 0 {
			continue
		}

		// Only auto-fix simple service start issues
		if result.CheckName == "Service Status" && strings.Contains(result.Error.Error(), "not running") {
			serviceName := ""
			for _, rem := range result.Remediation {
				if strings.Contains(rem, "systemctl start") {
					parts := strings.Fields(rem)
					if len(parts) >= 3 {
						serviceName = parts[len(parts)-1]
						break
					}
				}
			}
			
			if serviceName != "" {
				fmt.Printf("  Starting %s...\n", serviceName)
				ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
				cmd := exec.CommandContext(ctx, "sudo", "systemctl", "start", serviceName)
				err := cmd.Run()
				cancel()
				
				if err != nil {
					fmt.Printf("    ❌ Failed to start %s: %v\n", serviceName, err)
				} else {
					fmt.Printf("    ✅ Successfully started %s\n", serviceName)
				}
			}
		}
	}
	
	fmt.Println()
}
