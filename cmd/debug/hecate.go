// cmd/debug/hecate.go
package debug

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
)

var (
	hecateComponent       string
	hecateAuthentikCheck  bool
	hecateAuthentikConfig bool
	hecateBionicGPTCheck  bool
	hecatePath            string
	hecateVerbose         bool
)

var hecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Diagnose Hecate components and display configuration files",
	Long: `Comprehensive diagnostic tool for Hecate reverse proxy framework.

Automatically detects which Hecate components are running:
  • Caddy           - Reverse proxy
  • Authentik       - Identity provider
  • PostgreSQL      - Database
  • Redis           - Cache
  • Nginx           - Alternative reverse proxy
  • Coturn          - TURN/STUN server

For each detected component, performs relevant diagnostics:
  • Service status and health checks
  • Configuration file validation
  • Log file analysis
  • Port connectivity checks
  • Resource usage
  • Common issue detection
  • Actionable remediation steps

Configuration file display (NEW):
  • .env file (with sensitive values redacted)
  • docker-compose.yml (full content with line numbers)
  • Caddyfile (full content with line numbers)
  • Consul KV configuration dump
  • Docker container status and recent logs

Authentik-specific diagnostics (--authentik flag):
  • Current version check
  • Disk space verification
  • Container health status
  • PostgreSQL encoding check
  • Redis connectivity
  • Custom modifications detection
  • Environment file validation
  • Active task queue check
  • Memory usage analysis
  • Backup status

Authentik configuration export (--authentik-config flag):
  • Brands configuration
  • Flows (authentication, enrollment, recovery, etc.)
  • Stages and stage bindings
  • Groups and permissions
  • Applications and providers
  • Full observability of self-enrollment setup

BionicGPT integration diagnostics (--bionicgpt flag):
  • Authentik → Caddy → BionicGPT triangle validation
  • Caddy forward_auth configuration check
  • Header mapping verification (X-Authentik-* → X-Auth-Request-*)
  • Authentik proxy provider status
  • Authentik application and outpost assignment
  • BionicGPT backend connectivity
  • BionicGPT header trust configuration
  • Authentik group and user synchronization status
  • End-to-end authentication flow test
  • Common misconfigurations detection

Flags:
  --component <name>  Only check specific component (caddy|authentik|postgresql|redis|nginx|coturn)
  --authentik         Run comprehensive Authentik pre-upgrade health check
  --authentik-config  Export Authentik configuration (brands, flows, stages, groups, applications)
  --bionicgpt         Run BionicGPT integration diagnostics (Authentik-Caddy-BionicGPT)
  --path <path>       Path to Hecate installation (default: /opt/hecate)
  --verbose           Show detailed diagnostic output

Examples:
  eos debug hecate                      # Full diagnostics + file display
  eos debug hecate --component authentik  # Only diagnose Authentik
  eos debug hecate --authentik          # Full Authentik pre-upgrade check
  eos debug hecate --authentik-config   # Export Authentik configuration
  eos debug hecate --bionicgpt          # BionicGPT integration diagnostics
  eos debug hecate --path /custom/path  # Custom installation path

Output is automatically saved to ~/.eos/debug/eos-debug-hecate-{timestamp}.txt`,
	RunE: eos.WrapDebug("hecate", hecate.RunHecateDebug),
}

func init() {
	hecateCmd.Flags().StringVar(&hecateComponent, "component", "", "Specific component to check")
	hecateCmd.Flags().BoolVar(&hecateAuthentikCheck, "authentik", false, "Run comprehensive Authentik pre-upgrade check")
	hecateCmd.Flags().BoolVar(&hecateAuthentikConfig, "authentik-config", false, "Export Authentik configuration (brands, flows, stages, groups, applications)")
	hecateCmd.Flags().BoolVar(&hecateBionicGPTCheck, "bionicgpt", false, "Run BionicGPT integration diagnostics (Authentik-Caddy-BionicGPT triangle)")
	hecateCmd.Flags().StringVar(&hecatePath, "path", "/opt/hecate", "Path to Hecate installation")
	hecateCmd.Flags().BoolVar(&hecateVerbose, "verbose", false, "Show detailed diagnostic output")
	debugCmd.AddCommand(hecateCmd)
}
