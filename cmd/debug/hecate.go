// cmd/debug/hecate.go
package debug

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
)

var (
	hecateComponent      string
	hecateAuthentikCheck bool
	hecateBionicGPTCheck bool
	hecateCaddyCheck     bool
	hecatePath           string
	hecateVerbose        bool
)

var hecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Diagnose Hecate components and display configuration files",
	Long: `Comprehensive diagnostic tool for Hecate reverse proxy framework.

ARCHITECTURE: Running 'eos debug hecate' with NO flags runs ALL diagnostics.
Flags are FILTERS - use them to run ONLY specific diagnostic suites.

Diagnostic Suites (all run by default):

1. Standard Component Diagnostics:
   • Caddy           - Reverse proxy
   • Authentik       - Identity provider
   • PostgreSQL      - Database
   • Redis           - Cache
   • Nginx           - Alternative reverse proxy
   • Coturn          - TURN/STUN server

   For each detected component:
   • Service status and health checks
   • Configuration file validation
   • Log file analysis
   • Port connectivity checks
   • Resource usage
   • Common issue detection
   • Actionable remediation steps

   Configuration file display:
   • .env file (with sensitive values redacted)
   • docker-compose.yml (full content with line numbers)
   • Caddyfile (full content with line numbers)
   • Consul KV configuration dump
   • Docker container status and recent logs

2. Caddy Admin API Diagnostics (--caddy flag to run ONLY this):
   • Connection testing with retry attempts
   • Health endpoint verification
   • Configuration retrieval and parsing
   • Route listing and validation
   • Admin API port accessibility
   • Network connectivity diagnosis
   • Timeout and performance analysis

3. Authentik Diagnostics (--authentik flag to run ONLY this):
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
   • OpenAPI schema validation

4. BionicGPT Integration Diagnostics (--bionicgpt flag to run ONLY this):
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

Flags (all are FILTERS - omit to run everything):
  --component <name>  Only check specific component (caddy|authentik|postgresql|redis|nginx|coturn)
  --authentik         Run ONLY Authentik diagnostics (filter out others)
  --bionicgpt         Run ONLY BionicGPT integration diagnostics (filter out others)
  --caddy             Run ONLY Caddy Admin API diagnostics (filter out others)
  --path <path>       Path to Hecate installation (default: /opt/hecate)
  --verbose           Show detailed diagnostic output

Examples:
  eos debug hecate                        # ALL diagnostics (standard + caddy + authentik + bionicgpt)
  eos debug hecate --component authentik  # Standard diagnostics for Authentik component only
  eos debug hecate --authentik            # ONLY Authentik suite (filters out caddy, bionicgpt, standard)
  eos debug hecate --caddy                # ONLY Caddy Admin API suite
  eos debug hecate --bionicgpt            # ONLY BionicGPT integration suite
  eos debug hecate --path /custom/path    # All diagnostics with custom path

Output is automatically saved to ~/.eos/debug/eos-debug-hecate-{timestamp}.txt`,
	RunE: eos.WrapDebug("hecate", hecate.RunHecateDebug),
}

func init() {
	hecateCmd.Flags().StringVar(&hecateComponent, "component", "", "Specific component to check")
	hecateCmd.Flags().BoolVar(&hecateAuthentikCheck, "authentik", false, "Run comprehensive Authentik health check + configuration export")
	hecateCmd.Flags().BoolVar(&hecateBionicGPTCheck, "bionicgpt", false, "Run BionicGPT integration diagnostics (Authentik-Caddy-BionicGPT triangle)")
	hecateCmd.Flags().BoolVar(&hecateCaddyCheck, "caddy", false, "Run Caddy Admin API diagnostics (connection, health, routes)")
	hecateCmd.Flags().StringVar(&hecatePath, "path", "/opt/hecate", "Path to Hecate installation")
	hecateCmd.Flags().BoolVar(&hecateVerbose, "verbose", false, "Show detailed diagnostic output")
	debugCmd.AddCommand(hecateCmd)
}
