package create

import (
	"context"
	"strconv"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createHecateAPICmd = &cobra.Command{
	Use:   "api",
	Short: "Start the Hecate API server",
	Long: `Start the Hecate API server for managing routes, authentication policies, and state reconciliation.

The API server provides REST endpoints for:
- Route management (create, read, update, delete)
- Authentication policy management
- State reconciliation
- Secret rotation
- Health checks and metrics

Examples:
  eos create hecate api --port 8080
  eos create hecate api --port 8080 --host 0.0.0.0`,
	RunE: eos_cli.Wrap(runCreateHecateAPI),
}

func init() {
	CreateHecateCmd.AddCommand(createHecateAPICmd)

	// Define flags
	createHecateAPICmd.Flags().Int("port", 8080, "Port to run the API server on")
	createHecateAPICmd.Flags().String("host", "localhost", "Host to bind the API server to")
	createHecateAPICmd.Flags().Bool("enable-cors", false, "Enable CORS for the API")
	createHecateAPICmd.Flags().String("cors-origins", "*", "Allowed CORS origins")
}
// TODO: refactor
func runCreateHecateAPI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	port, _ := cmd.Flags().GetInt("port")
	host, _ := cmd.Flags().GetString("host")
	enableCORS, _ := cmd.Flags().GetBool("enable-cors")
	_, _ = cmd.Flags().GetString("cors-origins")

	logger.Info("Starting Hecate API server",
		zap.Int("port", port),
		zap.String("host", host),
		zap.Bool("enable_cors", enableCORS))

	// Create API handler
	handler := api.NewHandler(rc)

	// Start the server
	serverCtx, cancel := context.WithCancel(rc.Ctx)
	defer cancel()

	logger.Info("Hecate API server started",
		zap.String("address", host+":"+strconv.Itoa(port)))

	return handler.StartServer(serverCtx, port)
}
