// cmd/debug/wazuh.go
package debug

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/spf13/cobra"
)

var wazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Diagnose Wazuh components and Iris/Temporal integration",
	Long: `Comprehensive diagnostic tool for Wazuh components and Iris webhook integration.

MODE 1: Component Diagnostics (default)
Automatically detects which Wazuh components are running on this machine:
  • Wazuh Agent       - Security monitoring agent
  • Wazuh Manager     - Central management server
  • Wazuh Indexer     - OpenSearch-based indexer
  • Wazuh Dashboard   - Web UI dashboard

For each detected component, performs relevant diagnostics:
  • Service status and health checks
  • Configuration file validation
  • Log file analysis (last 20-50 lines)
  • Port connectivity checks
  • Process and resource usage
  • Common issue detection
  • Actionable remediation steps

MODE 2: Webhook Integration Diagnostics (--webhook-out)
Comprehensive checks for Wazuh → Iris webhook integration:

Network Connectivity (4 checks):
  • Ping Iris machine
  • TCP connection to webhook port
  • Network latency measurement
  • Firewall rule analysis

Iris Service Health (4 checks):
  • HTTP health endpoint verification
  • Temporal connection status
  • Systemd service status
  • Port listening status

Wazuh Integration Configuration (7 checks):
  • Integration .env file existence
  • HOOK_URL correctness
  • Script permissions
  • ossec.conf integration settings
  • Alert level threshold
  • Wazuh Manager service status
  • No hardcoded credentials

Python Dependencies (2 checks):
  • requests module availability
  • python-dotenv module availability

Test Webhook (3 checks):
  • Test alert payload creation
  • Integration script execution
  • Response validation

Log Analysis (2 checks):
  • Integration logs review
  • Sent payload logs review

Remote Checks (optional with --ssh-key):
  • Iris service status on remote machine
  • Port status verification
  • Temporal service logs

Flags (Component Mode):
  --component <name>  Only check specific component (agent|manager|indexer|dashboard)
  --logs <n>          Number of log lines to display (default: 30)
  --verbose           Show detailed diagnostic output
  --fix               Attempt automatic fixes for common issues (requires sudo)

Flags (Webhook Mode):
  --webhook-out       Enable webhook integration diagnostics mode
  --iris-ip          Iris machine IP address (default: 192.168.122.133)
  --iris-port        Iris webhook port (default: 9101)
  --ssh-key          SSH private key for remote checks (optional)
  --auto-start       Automatically start Temporal server if not running (local only)
  --temporal-ip      IP address for Temporal server to bind to (default: 0.0.0.0)
  --temporal-port    Port for Temporal server to listen on (default: 7233)
  --temporal-db      Path to Temporal database file (default: /tmp/temporal.db)

Examples:
  # Component diagnostics
  eos debug wazuh                                    # Auto-detect and diagnose all components
  eos debug wazuh --component agent                  # Only diagnose Wazuh agent
  eos debug wazuh --component manager --logs 50      # Manager with 50 log lines
  eos debug wazuh --verbose --fix                    # Detailed output with auto-fix

  # Webhook integration diagnostics
  eos debug wazuh --webhook-out                      # Check webhook integration
  eos debug wazuh --webhook-out --iris-ip 192.168.122.133 --iris-port 9101
  eos debug wazuh --webhook-out --ssh-key ~/.ssh/id_rsa --verbose
  eos debug wazuh --webhook-out --auto-start --temporal-ip 0.0.0.0`,
	RunE: eos.Wrap(wazuh.RunDiagnostics),
}

func init() {
	// Component diagnostics flags
	wazuhCmd.Flags().StringVar(&wazuh.Component, "component", "", "Specific component to check")
	wazuhCmd.Flags().IntVar(&wazuh.LogLines, "logs", 30, "Number of log lines to display")
	wazuhCmd.Flags().BoolVar(&wazuh.Verbose, "verbose", false, "Show detailed diagnostic output")
	wazuhCmd.Flags().BoolVar(&wazuh.Fix, "fix", false, "Attempt automatic fixes")
	
	// Webhook diagnostics flags
	wazuhCmd.Flags().BoolVar(&wazuh.WebhookOut, "webhook-out", false, "Check outbound webhook from Wazuh to Iris")
	wazuhCmd.Flags().StringVar(&wazuh.IrisIP, "iris-ip", "192.168.122.133", "Iris machine IP address")
	wazuhCmd.Flags().IntVar(&wazuh.IrisPort, "iris-port", 9101, "Iris webhook port")
	wazuhCmd.Flags().StringVar(&wazuh.SSHKey, "ssh-key", "", "SSH private key for remote checks")
	wazuhCmd.Flags().BoolVar(&wazuh.AutoStart, "auto-start", false, "Automatically start Temporal server if not running")
	wazuhCmd.Flags().StringVar(&wazuh.TemporalDB, "temporal-db", "/tmp/temporal.db", "Path to Temporal database file")
	wazuhCmd.Flags().StringVar(&wazuh.TemporalIP, "temporal-ip", "0.0.0.0", "IP address for Temporal server to bind to")
	wazuhCmd.Flags().IntVar(&wazuh.TemporalPort, "temporal-port", 7233, "Port for Temporal server to listen on")
	
	debugCmd.AddCommand(wazuhCmd)
}
