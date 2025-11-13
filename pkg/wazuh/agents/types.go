// Package agents provides comprehensive agent management and monitoring architecture for Eos.
//
// # Agent and Monitoring Architecture Guide
//
// This package implements Eos's solution to the "agent sprawl" problem where infrastructure
// accumulates multiple monitoring and management agents. The architecture follows a
// four- consolidation strategy:
//
// ## The Agent Sprawl Problem
//
// Traditional infrastructure often accumulates multiple agents:
// - Wazuh (security monitoring)
// -  agents (configuration management)
// - Zabbix agents (infrastructure monitoring)
// - Jenkins agents (CI/CD)
// - Prometheus exporters (metrics)
// - Various log shippers (Filebeat, Fluentd)
//
// Each agent requires network ports, credentials, update cycles, configuration files,
// resources, and meta-monitoring - creating security and maintenance overhead.
//
// ## Four- Consolidation Strategy
//
// 1. **Monitoring Layer** (OpenTelemetry or Telegraf)
//   - All telemetry: metrics, logs, network monitoring
//   - Single agent replacing multiple specialized agents
//   - Unified configuration language
//
// 2. **Security Layer** (Wazuh/Wazuh)
//   - Kept separate for security reasons
//   - Different privileges and audit requirements
//   - Implements separation of duties principle
//   - Handles authentication logs, file integrity, system calls
//
// 3. **Automation Layer** (Jenkins + )
//   - Jenkins: CI/CD orchestration (the "when and what")
//   - : Configuration management (the "how")
//   - Jenkins as conductor,  as orchestra
//
// 4. **Maintenance Layer** (Scripts)
//   - Backups and patching
//   - Simple, auditable scripts
//   - Periodic, well-defined tasks
//
// ## Architecture Benefits
//
// - Different types of system management have fundamentally different requirements
// - Like a house where electrical and plumbing systems are separate
// - Each  serves a distinct purpose that would be compromised if merged
// - Reduced attack surface with fewer network ports and credentials
// - Simplified maintenance and update cycles
//
// ## Implementation Notes
//
// This package focuses on the Security Layer (Wazuh/Wazuh agents) and provides:
// - Agent discovery and mapping functionality
// - Package recommendation based on OS and architecture
// - Integration with Wazuh API for agent management
// - Support for agent re-registration and upgrades
//
// For monitoring layer consolidation, see pkg/monitoring/
// For automation layer integration, see pkg/automation/
// For maintenance scripts, see scripts/ directory
package agents

// Config represents Wazuh API configuration
type Config struct {
	Protocol    string
	FQDN        string
	Port        string
	APIUser     string
	APIPassword string
}

// OSInfo represents operating system information
type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

// Agent represents a Wazuh/Wazuh agent
type Agent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      OSInfo `json:"os"`
}

// AgentsResponse represents the API response containing agents
type AgentsResponse struct {
	Data struct {
		AffectedItems []Agent `json:"affected_items"`
		TotalItems    int     `json:"total_items"`
		TotalAffected int     `json:"total_affected_items"`
		FailedItems   int     `json:"failed_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// PackageMapping represents a package mapping for different distributions
type PackageMapping struct {
	Distribution string
	MinVersion   int
	Arch         string
	Package      string
}
