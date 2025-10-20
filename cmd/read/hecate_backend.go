// cmd/read/hecate_backend.go

package read

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/backend"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/hybrid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var readHecateBackendCmd = &cobra.Command{
	Use:   "hecate-backend [backend-id]",
	Short: "Read Hecate hybrid backend connection details",
	Long: `Read and display details about a Hecate hybrid backend connection.

This command shows:
- Backend service configuration
- Connection status and health
- Tunnel information
- Security settings
- Performance metrics

Examples:
  # Show specific backend details
  eos read hecate-backend backend-myapp-1234567890
  
  # Show all backends
  eos read hecate-backend --all
  
  # Show backend health status
  eos read hecate-backend backend-myapp-1234567890 --health
  
  # Show connection diagnostics
  eos read hecate-backend backend-myapp-1234567890 --diagnostics
`,
	RunE: eos_cli.Wrap(runReadHecateBackend),
}

func init() {
	// Register with read command
	ReadCmd.AddCommand(readHecateBackendCmd)

	// Flags
	readHecateBackendCmd.Flags().Bool("all", false, "Show all backends")
	readHecateBackendCmd.Flags().Bool("health", false, "Show health status")
	readHecateBackendCmd.Flags().Bool("diagnostics", false, "Show connection diagnostics")
	readHecateBackendCmd.Flags().String("format", "table", "Output format (table, json, yaml)")
	readHecateBackendCmd.Flags().Bool("verbose", false, "Show verbose output")
	readHecateBackendCmd.Flags().String("datacenter", "", "Filter by datacenter")
	readHecateBackendCmd.Flags().String("status", "", "Filter by status (connected, disconnected, error)")
}

func runReadHecateBackend(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	showAll, _ := cmd.Flags().GetBool("all")
	showHealth, _ := cmd.Flags().GetBool("health")
	showDiagnostics, _ := cmd.Flags().GetBool("diagnostics")
	format, _ := cmd.Flags().GetString("format")
	verbose, _ := cmd.Flags().GetBool("verbose")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	statusFilter, _ := cmd.Flags().GetString("status")

	if showAll {
		// Show all backends
		logger.Info("Retrieving all hybrid backends")
		return showAllBackends(rc, format, verbose, datacenter, statusFilter)
	}

	// Require backend ID if not showing all
	if len(args) == 0 {
		logger.Info("terminal prompt: Enter backend ID")
		input, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read backend ID: %w", err)
		}
		args = []string{input}
	}

	backendID := args[0]
	logger.Info("Reading backend details",
		zap.String("backend_id", backendID))

	if showHealth {
		return showBackendHealth(rc, backendID, format)
	}

	if showDiagnostics {
		return showBackendDiagnostics(rc, backendID, format)
	}

	return showBackendDetails(rc, backendID, format, verbose)
}

func showAllBackends(rc *eos_io.RuntimeContext, format string, verbose bool, datacenter, statusFilter string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Retrieving all hybrid backends")

	// Delegate to pkg/hecate/backend for business logic
	backends, err := backend.GetAllBackends(rc, datacenter, statusFilter)
	if err != nil {
		return fmt.Errorf("failed to get backends: %w", err)
	}

	if len(backends) == 0 {
		logger.Info("No hybrid backends found")
		return nil
	}

	// Delegate to pkg/hecate/backend for display formatting
	switch format {
	case "json":
		return backend.DisplayBackendsJSON(backends)
	case "yaml":
		return backend.DisplayBackendsYAML(backends)
	default:
		return backend.DisplayBackendsTable(backends, verbose)
	}
}

func showBackendDetails(rc *eos_io.RuntimeContext, backendID, format string, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting backend details",
		zap.String("backend_id", backendID))

	// Delegate to pkg/hecate/backend for business logic
	details, err := backend.GetBackendDetails(rc, backendID)
	if err != nil {
		return fmt.Errorf("failed to get backend details: %w", err)
	}

	// Delegate to pkg/hecate/backend for display formatting
	switch format {
	case "json":
		return backend.DisplayBackendJSON(details)
	case "yaml":
		return backend.DisplayBackendYAML(details)
	default:
		return backend.DisplayBackendTable(details, verbose)
	}
}

func showBackendHealth(rc *eos_io.RuntimeContext, backendID, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting backend health status",
		zap.String("backend_id", backendID))

	// Get health status from pkg/hecate/hybrid
	status, err := hybrid.GetBackendHealth(rc, backendID)
	if err != nil {
		return fmt.Errorf("failed to get backend health: %w", err)
	}

	// Delegate to pkg/hecate/backend for display formatting
	switch format {
	case "json":
		return backend.DisplayHealthJSON(status)
	case "yaml":
		return backend.DisplayHealthYAML(status)
	default:
		return backend.DisplayHealthTable(status)
	}
}

func showBackendDiagnostics(rc *eos_io.RuntimeContext, backendID, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Running backend diagnostics",
		zap.String("backend_id", backendID))

	// Delegate to pkg/hecate/backend for business logic
	diagnostics, err := backend.RunDiagnostics(rc, backendID)
	if err != nil {
		return fmt.Errorf("failed to run diagnostics: %w", err)
	}

	// Delegate to pkg/hecate/backend for display formatting
	switch format {
	case "json":
		return backend.DisplayDiagnosticsJSON(diagnostics)
	case "yaml":
		return backend.DisplayDiagnosticsYAML(diagnostics)
	default:
		return backend.DisplayDiagnosticsTable(diagnostics)
	}
}
