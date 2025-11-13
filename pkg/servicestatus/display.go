// pkg/servicestatus/display.go
package servicestatus

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// displayText renders the status in human-readable text format
func (s *ServiceStatus) displayText() string {
	var b strings.Builder

	// Header
	b.WriteString(fmt.Sprintf("\n%s Service Status\n", s.Name))
	b.WriteString(strings.Repeat("=", 80))
	b.WriteString("\n\n")

	// Installation Status
	b.WriteString(s.renderSection("Installation Status", func() string {
		var sb strings.Builder
		sb.WriteString(s.statusLine("Installed", s.Installation.Installed))
		if s.Installation.Installed {
			sb.WriteString(s.infoLine("Binary Path", s.Installation.BinaryPath))
			sb.WriteString(s.infoLine("Version", s.Installation.Version))
			if s.Installation.ConfigDir != "" {
				sb.WriteString(s.infoLine("Config Directory", s.Installation.ConfigDir))
			}
			if s.Installation.DataDir != "" {
				sb.WriteString(s.infoLine("Data Directory", s.Installation.DataDir))
			}
		}
		return sb.String()
	}))

	// Service Status
	b.WriteString(s.renderSection("Service Status", func() string {
		var sb strings.Builder
		sb.WriteString(s.statusLine("Running", s.Service.Running))
		if s.Service.Running {
			sb.WriteString(s.infoLine("Status", s.Service.Status))
			sb.WriteString(s.infoLine("Enabled at Boot", fmt.Sprintf("%v", s.Service.Enabled)))
			if s.Service.Uptime > 0 {
				sb.WriteString(s.infoLine("Uptime", formatDuration(s.Service.Uptime)))
			}
			if s.Service.PID > 0 {
				sb.WriteString(s.infoLine("PID", fmt.Sprintf("%d", s.Service.PID)))
			}
			if s.Service.RestartCount > 0 {
				sb.WriteString(s.infoLine("Restart Count", fmt.Sprintf("%d", s.Service.RestartCount)))
			}
		} else if s.Service.FailureReason != "" {
			sb.WriteString(s.errorLine("Failure Reason", s.Service.FailureReason))
		}
		return sb.String()
	}))

	// Configuration
	b.WriteString(s.renderSection("Configuration", func() string {
		var sb strings.Builder
		sb.WriteString(s.statusLine("Valid", s.Configuration.Valid))
		sb.WriteString(s.infoLine("Config Path", s.Configuration.ConfigPath))

		if len(s.Configuration.Details) > 0 {
			for key, value := range s.Configuration.Details {
				sb.WriteString(s.infoLine(key, value))
			}
		}

		if len(s.Configuration.Errors) > 0 {
			sb.WriteString(s.errorLine("Errors", fmt.Sprintf("%d error(s)", len(s.Configuration.Errors))))
			for _, err := range s.Configuration.Errors {
				sb.WriteString(fmt.Sprintf("    - %s\n", err))
			}
		}

		if len(s.Configuration.Warnings) > 0 {
			sb.WriteString(s.warningLine("Warnings", fmt.Sprintf("%d warning(s)", len(s.Configuration.Warnings))))
			for _, warn := range s.Configuration.Warnings {
				sb.WriteString(fmt.Sprintf("    - %s\n", warn))
			}
		}
		return sb.String()
	}))

	// Health
	b.WriteString(s.renderSection("Health", func() string {
		var sb strings.Builder
		statusSymbol := s.healthSymbol(s.Health.Status)
		sb.WriteString(fmt.Sprintf("  Status: %s %s\n", statusSymbol, s.Health.Status))
		if s.Health.Message != "" {
			sb.WriteString(s.infoLine("Message", s.Health.Message))
		}
		if s.Health.ResponseTime > 0 {
			sb.WriteString(s.infoLine("Response Time", s.Health.ResponseTime.String()))
		}
		if s.Health.IsSealed != nil {
			sb.WriteString(s.statusLine("Sealed", *s.Health.IsSealed))
		}
		if s.Health.IsLeader != nil {
			sb.WriteString(s.statusLine("Leader", *s.Health.IsLeader))
		}

		if len(s.Health.Checks) > 0 {
			sb.WriteString("  \n  Health Checks:\n")
			for _, check := range s.Health.Checks {
				symbol := s.healthSymbol(check.Status)
				sb.WriteString(fmt.Sprintf("    %s %s: %s\n", symbol, check.Name, check.Message))
			}
		}
		return sb.String()
	}))

	// Network
	if len(s.Network.Endpoints) > 0 {
		b.WriteString(s.renderSection("Network Endpoints", func() string {
			var sb strings.Builder
			for _, ep := range s.Network.Endpoints {
				healthStr := "✗"
				if ep.Healthy {
					healthStr = "✓"
				}
				sb.WriteString(fmt.Sprintf("  %s %s: %s://%s:%d\n",
					healthStr, ep.Name, ep.Protocol, ep.Address, ep.Port))
			}
			return sb.String()
		}))
	}

	// Integrations
	if len(s.Integrations) > 0 {
		b.WriteString(s.renderSection("Integrations", func() string {
			var sb strings.Builder
			for _, integ := range s.Integrations {
				status := "✗"
				if integ.Connected && integ.Healthy {
					status = "✓"
				} else if integ.Connected {
					status = "⚠"
				}
				reqStr := ""
				if integ.Required {
					reqStr = " (required)"
				}
				sb.WriteString(fmt.Sprintf("  %s %s: %s%s\n",
					status, integ.ServiceName, integ.Type, reqStr))
				if integ.Details != "" {
					sb.WriteString(fmt.Sprintf("      %s\n", integ.Details))
				}
			}
			return sb.String()
		}))
	}

	// Cluster
	if s.Cluster != nil {
		b.WriteString(s.renderSection("Cluster Information", func() string {
			var sb strings.Builder
			sb.WriteString(s.infoLine("Mode", s.Cluster.Mode))
			sb.WriteString(s.infoLine("Node Name", s.Cluster.NodeName))
			sb.WriteString(s.infoLine("Datacenter", s.Cluster.Datacenter))
			if s.Cluster.Leader != "" {
				sb.WriteString(s.infoLine("Leader", s.Cluster.Leader))
			}
			sb.WriteString(s.statusLine("Cluster Healthy", s.Cluster.Healthy))
			sb.WriteString(s.infoLine("Members", fmt.Sprintf("%d", len(s.Cluster.Members))))
			if s.Cluster.QuorumSize > 0 {
				sb.WriteString(s.infoLine("Quorum Size", fmt.Sprintf("%d", s.Cluster.QuorumSize)))
			}

			if len(s.Cluster.Members) > 0 {
				sb.WriteString("  \n  Cluster Members:\n")
				for _, member := range s.Cluster.Members {
					leaderStr := ""
					if member.Leader {
						leaderStr = " (leader)"
					}
					sb.WriteString(fmt.Sprintf("    - %s [%s] %s%s\n",
						member.Name, member.Role, member.Status, leaderStr))
				}
			}
			return sb.String()
		}))
	}

	// Summary
	b.WriteString("\n")
	b.WriteString(strings.Repeat("=", 80))
	b.WriteString("\n")
	if s.IsHealthy() {
		b.WriteString(fmt.Sprintf("✓ %s is healthy and operational\n", s.Name))
	} else if s.HasWarnings() {
		b.WriteString(fmt.Sprintf("⚠ %s is operational but has warnings\n", s.Name))
	} else {
		b.WriteString(fmt.Sprintf("✗ %s has issues that require attention\n", s.Name))
	}
	b.WriteString(fmt.Sprintf("\nChecked at: %s\n", s.CheckedAt.Format(time.RFC3339)))

	return b.String()
}

// displayJSON renders the status in JSON format
func (s *ServiceStatus) displayJSON() string {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal JSON: %v"}`, err)
	}
	return string(data)
}

// displayYAML renders the status in YAML format
func (s *ServiceStatus) displayYAML() string {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("error: failed to marshal YAML: %v\n", err)
	}
	return string(data)
}

// displayShort renders a one-line summary
func (s *ServiceStatus) displayShort() string {
	symbol := "✗"
	if s.IsHealthy() {
		symbol = "✓"
	} else if s.HasWarnings() {
		symbol = "⚠"
	}

	uptimeStr := "-"
	if s.Service.Uptime > 0 {
		uptimeStr = formatDuration(s.Service.Uptime)
	}

	return fmt.Sprintf("%s %-15s %-10s %-10s %-15s %s",
		symbol,
		s.Name,
		s.Service.Status,
		s.Health.Status,
		s.Installation.Version,
		uptimeStr)
}

// Helper methods for consistent formatting

func (s *ServiceStatus) renderSection(title string, content func() string) string {
	return fmt.Sprintf("\n%s\n%s\n%s\n",
		title,
		strings.Repeat("-", len(title)),
		content())
}

func (s *ServiceStatus) statusLine(label string, value bool) string {
	symbol := "✗"
	valueStr := "No"
	if value {
		symbol = "✓"
		valueStr = "Yes"
	}
	return fmt.Sprintf("  %s %-20s %s\n", symbol, label+":", valueStr)
}

func (s *ServiceStatus) infoLine(label, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("  • %-20s %s\n", label+":", value)
}

func (s *ServiceStatus) errorLine(label, value string) string {
	return fmt.Sprintf("  ✗ %-20s %s\n", label+":", value)
}

func (s *ServiceStatus) warningLine(label, value string) string {
	return fmt.Sprintf("  ⚠ %-20s %s\n", label+":", value)
}

func (s *ServiceStatus) healthSymbol(status HealthStatus) string {
	switch status {
	case HealthStatusHealthy:
		return "✓"
	case HealthStatusDegraded:
		return "⚠"
	case HealthStatusUnhealthy:
		return "✗"
	default:
		return "?"
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%dh", hours)
}
