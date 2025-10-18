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
		fmt.Println("\n No Wazuh components detected on this system")
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

	// Check agent registration
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

	// Comprehensive connectivity diagnostics
	results = append(results, diagnoseAgentConnectivity(rc)...)

	return results
}

// diagnoseAgentConnectivity performs comprehensive agent connectivity diagnostics
func diagnoseAgentConnectivity(rc *eos_io.RuntimeContext) []DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []DiagnosticResult

	// Extract server configuration from ossec.conf
	serverAddr, serverPort := extractAgentServerConfig(rc)
	if serverAddr == "" {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Server Configuration",
			Category:  "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("could not extract server address from configuration"),
		})
		return results
	}

	// 1. DNS Resolution Check
	results = append(results, checkDNSResolution(rc, serverAddr)...)

	// 2. Network Interface Check
	results = append(results, checkNetworkInterfaces(rc)...)

	// 3. IPv4 Connectivity Test
	ipv4Addrs := resolveIPv4(rc, serverAddr)
	if len(ipv4Addrs) > 0 {
		results = append(results, checkIPv4Connectivity(rc, ipv4Addrs[0], serverPort)...)
	}

	// 4. IPv6 Connectivity Test
	ipv6Addrs := resolveIPv6(rc, serverAddr)
	if len(ipv6Addrs) > 0 {
		results = append(results, checkIPv6Connectivity(rc, ipv6Addrs[0], serverPort)...)
	}

	// 5. Firewall Check
	results = append(results, checkAgentFirewallRules(rc)...)

	// 6. Self-Connection Detection (is this host the manager?)
	if len(ipv4Addrs) > 0 {
		results = append(results, checkSelfConnection(rc, serverAddr, ipv4Addrs[0])...)
	}

	// 7. Recent Agent Errors
	results = append(results, checkAgentErrors(rc)...)

	logger.Debug("Agent connectivity diagnostics completed",
		zap.String("server", serverAddr),
		zap.String("port", serverPort),
		zap.Int("checks_performed", len(results)))

	return results
}

// extractAgentServerConfig extracts server address and port from ossec.conf
func extractAgentServerConfig(rc *eos_io.RuntimeContext) (string, string) {
	configPath := "/var/ossec/etc/ossec.conf"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Extract address
	addressStart := strings.Index(content, "<address>")
	addressEnd := strings.Index(content, "</address>")
	serverAddr := ""
	if addressStart != -1 && addressEnd != -1 && addressEnd > addressStart {
		serverAddr = strings.TrimSpace(content[addressStart+9 : addressEnd])
	}

	// Extract port
	portStart := strings.Index(content, "<port>")
	portEnd := strings.Index(content, "</port>")
	serverPort := "1514" // default
	if portStart != -1 && portEnd != -1 && portEnd > portStart {
		serverPort = strings.TrimSpace(content[portStart+6 : portEnd])
	}

	return serverAddr, serverPort
}

// checkDNSResolution checks DNS resolution for the server
func checkDNSResolution(rc *eos_io.RuntimeContext, serverAddr string) []DiagnosticResult {
	var results []DiagnosticResult

	// Check IPv4 resolution
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "dig", "+short", "A", serverAddr)
	output, err := cmd.Output()
	cancel()

	ipv4Addrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if err == nil && len(ipv4Addrs) > 0 && ipv4Addrs[0] != "" {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "DNS IPv4 Resolution",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Resolved to: %s", strings.Join(ipv4Addrs, ", ")),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "DNS IPv4 Resolution",
			Category:  "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("no IPv4 addresses resolved"),
			Remediation: []string{
				fmt.Sprintf("Verify DNS: dig +short A %s", serverAddr),
				"Check /etc/resolv.conf for correct nameservers",
			},
		})
	}

	// Check IPv6 resolution
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd2 := exec.CommandContext(ctx2, "dig", "+short", "AAAA", serverAddr)
	output2, err2 := cmd2.Output()
	cancel2()

	ipv6Addrs := strings.Split(strings.TrimSpace(string(output2)), "\n")
	if err2 == nil && len(ipv6Addrs) > 0 && ipv6Addrs[0] != "" {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "DNS IPv6 Resolution",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Resolved to: %s", strings.Join(ipv6Addrs, ", ")),
		})
	}

	return results
}

// resolveIPv4 returns IPv4 addresses for the given hostname
func resolveIPv4(rc *eos_io.RuntimeContext, serverAddr string) []string {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "A", serverAddr)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	addrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validAddrs []string
	for _, addr := range addrs {
		if addr != "" {
			validAddrs = append(validAddrs, addr)
		}
	}
	return validAddrs
}

// resolveIPv6 returns IPv6 addresses for the given hostname
func resolveIPv6(rc *eos_io.RuntimeContext, serverAddr string) []string {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "AAAA", serverAddr)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	addrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validAddrs []string
	for _, addr := range addrs {
		if addr != "" {
			validAddrs = append(validAddrs, addr)
		}
	}
	return validAddrs
}

// checkIPv4Connectivity tests IPv4 connectivity to the server
func checkIPv4Connectivity(rc *eos_io.RuntimeContext, ipv4Addr, port string) []DiagnosticResult {
	var results []DiagnosticResult

	// Ping test
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "ping", "-c", "3", "-W", "2", ipv4Addr)
	err := cmd.Run()
	cancel()

	if err == nil {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv4 Ping Test",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Successfully pinged %s", ipv4Addr),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv4 Ping Test",
			Category:  "Connectivity",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("ping failed to %s", ipv4Addr),
			Remediation: []string{
				"Check network connectivity",
				"Verify firewall allows ICMP",
			},
		})
	}

	// TCP port connectivity test
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd2 := exec.CommandContext(ctx2, "nc", "-zv", "-w", "5", ipv4Addr, port)
	output2, err2 := cmd2.CombinedOutput()
	cancel2()

	if err2 == nil || strings.Contains(string(output2), "succeeded") {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: fmt.Sprintf("IPv4 Port %s Connectivity", port),
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Port %s is reachable on %s", port, ipv4Addr),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: fmt.Sprintf("IPv4 Port %s Connectivity", port),
			Category:  "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("cannot connect to port %s on %s", port, ipv4Addr),
			Details:   string(output2),
			Remediation: []string{
				fmt.Sprintf("Verify Wazuh manager is listening on port %s", port),
				"Check firewall rules: sudo ufw status",
				fmt.Sprintf("Test manually: nc -zv %s %s", ipv4Addr, port),
			},
		})
	}

	return results
}

// checkIPv6Connectivity tests IPv6 connectivity to the server
func checkIPv6Connectivity(rc *eos_io.RuntimeContext, ipv6Addr, port string) []DiagnosticResult {
	var results []DiagnosticResult

	// Ping test
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "ping6", "-c", "3", "-W", "2", ipv6Addr)
	err := cmd.Run()
	cancel()

	if err == nil {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv6 Ping Test",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Successfully pinged %s", ipv6Addr),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv6 Ping Test",
			Category:  "Connectivity",
			Passed:    false,
			Warning:   true,
			Details:   fmt.Sprintf("IPv6 ping failed (may not be configured): %s", ipv6Addr),
		})
	}

	// TCP port connectivity test
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd2 := exec.CommandContext(ctx2, "nc", "-6", "-zv", "-w", "5", ipv6Addr, port)
	output2, err2 := cmd2.CombinedOutput()
	cancel2()

	if err2 == nil || strings.Contains(string(output2), "succeeded") {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: fmt.Sprintf("IPv6 Port %s Connectivity", port),
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Port %s is reachable on %s", port, ipv6Addr),
		})
	}

	return results
}

// checkNetworkInterfaces checks available network interfaces
func checkNetworkInterfaces(rc *eos_io.RuntimeContext) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "ip", "-brief", "addr", "show")
	output, err := cmd.Output()
	cancel()

	if err == nil {
		details := "Network interfaces:\n" + string(output)

		// Check for default route
		ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
		routeCmd := exec.CommandContext(ctx2, "ip", "route", "show")
		routeOutput, routeErr := routeCmd.Output()
		cancel2()

		hasDefaultRoute := false
		if routeErr == nil {
			hasDefaultRoute = strings.Contains(string(routeOutput), "default")
			details += "\n\nDefault route: "
			if hasDefaultRoute {
				details += "configured"
			} else {
				details += "NOT configured"
			}
		}

		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Network Interfaces",
			Category:  "Connectivity",
			Passed:    hasDefaultRoute,
			Warning:   !hasDefaultRoute,
			Details:   details,
			Remediation: func() []string {
				if !hasDefaultRoute {
					return []string{"No default route configured - check network settings"}
				}
				return nil
			}(),
		})
	}

	return results
}

// checkAgentFirewallRules checks firewall configuration for agent connectivity
func checkAgentFirewallRules(rc *eos_io.RuntimeContext) []DiagnosticResult {
	var results []DiagnosticResult

	// Check UFW
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "ufw", "status", "verbose")
	output, err := cmd.Output()
	cancel()

	if err == nil {
		isActive := strings.Contains(string(output), "Status: active")
		details := "UFW Status:\n" + string(output)

		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Firewall Status (UFW)",
			Category:  "Connectivity",
			Passed:    true,
			Warning:   isActive, // Active firewall might block connections
			Details:   details,
			Remediation: func() []string {
				if isActive {
					return []string{
						"UFW is active - ensure outbound connections to Wazuh manager are allowed",
						"Allow outbound: sudo ufw allow out to <manager-ip> port 1514 proto tcp",
					}
				}
				return nil
			}(),
		})
	}

	return results
}

// checkSelfConnection detects if this host is trying to connect to itself
func checkSelfConnection(rc *eos_io.RuntimeContext, serverAddr, serverIP string) []DiagnosticResult {
	var results []DiagnosticResult

	// Get current hostname
	hostname, err := os.Hostname()
	if err != nil {
		return results
	}

	// Get current host IPs
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "hostname", "-I")
	output, err := cmd.Output()
	cancel()

	if err != nil {
		return results
	}

	currentIPs := strings.Fields(string(output))
	isSelf := false

	for _, ip := range currentIPs {
		if ip == serverIP {
			isSelf = true
			break
		}
	}

	if isSelf {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Self-Connection Detection",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("agent is configured to connect to itself"),
			Details: fmt.Sprintf(
				"WARNING: This host (%s) appears to BE %s!\n"+
					"Current IPs: %s\n"+
					"Server resolves to: %s\n"+
					"Agents should not be installed on the manager server.",
				hostname, serverAddr, strings.Join(currentIPs, ", "), serverIP),
			Remediation: []string{
				"Remove Wazuh agent from the manager server",
				"Install agent on a different host",
				"Or configure a separate manager if this should be an agent",
			},
		})
	}

	return results
}

// checkAgentErrors analyzes recent agent errors
func checkAgentErrors(rc *eos_io.RuntimeContext) []DiagnosticResult {
	var results []DiagnosticResult

	logPath := "/var/ossec/logs/ossec.log"
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "grep", "ERROR", logPath)
	output, err := cmd.Output()
	cancel()

	if err != nil && len(output) == 0 {
		// No errors found - this is good
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Recent Agent Errors",
			Category:  "Logs",
			Passed:    true,
			Details:   "No recent ERROR entries in agent log",
		})
		return results
	}

	// Parse and categorize errors
	errorLines := strings.Split(string(output), "\n")
	var connectErrors, authErrors, configErrors, otherErrors []string

	for _, line := range errorLines {
		if line == "" {
			continue
		}
		lineLower := strings.ToLower(line)

		if strings.Contains(lineLower, "connect") || strings.Contains(lineLower, "connection") {
			connectErrors = append(connectErrors, line)
		} else if strings.Contains(lineLower, "auth") || strings.Contains(lineLower, "key") {
			authErrors = append(authErrors, line)
		} else if strings.Contains(lineLower, "config") {
			configErrors = append(configErrors, line)
		} else {
			otherErrors = append(otherErrors, line)
		}
	}

	details := fmt.Sprintf("Found %d error entries:\n", len(errorLines)-1)
	if len(connectErrors) > 0 {
		details += fmt.Sprintf("  • Connection errors: %d\n", len(connectErrors))
	}
	if len(authErrors) > 0 {
		details += fmt.Sprintf("  • Authentication errors: %d\n", len(authErrors))
	}
	if len(configErrors) > 0 {
		details += fmt.Sprintf("  • Configuration errors: %d\n", len(configErrors))
	}
	if len(otherErrors) > 0 {
		details += fmt.Sprintf("  • Other errors: %d\n", len(otherErrors))
	}

	// Show last 3 errors
	details += "\nMost recent errors:\n"
	recentErrors := errorLines
	if len(recentErrors) > 10 {
		recentErrors = recentErrors[len(recentErrors)-10:]
	}
	for i, line := range recentErrors {
		if line != "" && i < 3 {
			details += "  " + line + "\n"
		}
	}

	remediation := []string{}
	if len(connectErrors) > 0 {
		remediation = append(remediation, "Connection errors detected - check network connectivity to manager")
	}
	if len(authErrors) > 0 {
		remediation = append(remediation, "Authentication errors detected - verify agent registration")
	}
	if len(configErrors) > 0 {
		remediation = append(remediation, "Configuration errors detected - check /var/ossec/etc/ossec.conf")
	}
	remediation = append(remediation, "View full log: sudo tail -50 /var/ossec/logs/ossec.log")

	results = append(results, DiagnosticResult{
		Component:   ComponentAgent,
		CheckName:   "Recent Agent Errors",
		Category:    "Logs",
		Passed:      false,
		Details:     details,
		Remediation: remediation,
	})

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

		status := " Stopped"
		if info.Running {
			status = " Running"
		}

		fmt.Printf("  • %-15s %s\n", string(info.Name), status)
	}
	fmt.Println()
}

func displayWazuhResults(results []DiagnosticResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println("\n Diagnostic Results:")
	fmt.Println(strings.Repeat("=", 60))

	currentComponent := WazuhComponent("")

	for _, result := range results {
		if result.Component != currentComponent {
			currentComponent = result.Component
			fmt.Printf("\n[%s]\n", strings.ToUpper(string(currentComponent)))
		}

		icon := ""
		if !result.Passed {
			if result.Warning {
				icon = "⚠️ "
			} else {
				icon = ""
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

	fmt.Printf("\n Summary: %d passed, %d failed, %d warnings\n\n", passed, failed, warnings)
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
					fmt.Printf("     Failed to start %s: %v\n", serviceName, err)
				} else {
					fmt.Printf("     Successfully started %s\n", serviceName)
				}
			}
		}
	}

	fmt.Println()
}
