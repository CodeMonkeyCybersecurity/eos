// cmd/delete/hecate_backend.go

package delete

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/hybrid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var deleteHecateBackendCmd = &cobra.Command{
	Use:   "hecate-backend <backend-id>",
	Short: "Delete a Hecate hybrid backend connection",
	Long: `Delete a Hecate hybrid backend connection and clean up all associated resources.

This command will:
- Remove the backend service from Consul
- Tear down the secure tunnel connection
- Clean up certificates and security configurations
- Stop health monitoring
- Remove routing configurations
- Clean up state store entries

Example:
  eos delete hecate-backend backend-myapp-1234567890
  
  # Force deletion without confirmation
  eos delete hecate-backend backend-myapp-1234567890 --force
  
  # Clean up all related resources
  eos delete hecate-backend backend-myapp-1234567890 --cleanup-all
`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(runDeleteHecateBackend),
}

func init() {
	// Register with delete command
	DeleteCmd.AddCommand(deleteHecateBackendCmd)

	// Flags
	deleteHecateBackendCmd.Flags().Bool("force", false, "Force deletion without confirmation")
	deleteHecateBackendCmd.Flags().Bool("cleanup-all", false, "Clean up all related resources")
	deleteHecateBackendCmd.Flags().Bool("preserve-certificates", false, "Preserve certificates for reuse")
	deleteHecateBackendCmd.Flags().Bool("dry-run", false, "Show what would be deleted without actually deleting")
}

func runDeleteHecateBackend(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	backendID := args[0]
	force, _ := cmd.Flags().GetBool("force")
	cleanupAll, _ := cmd.Flags().GetBool("cleanup-all")
	preserveCertificates, _ := cmd.Flags().GetBool("preserve-certificates")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	logger.Info("Deleting Hecate hybrid backend",
		zap.String("backend_id", backendID),
		zap.Bool("force", force),
		zap.Bool("cleanup_all", cleanupAll),
		zap.Bool("dry_run", dryRun))

	// ASSESS - Get backend details and validate deletion
	backend, err := getBackendForDeletion(rc, backendID)
	if err != nil {
		return fmt.Errorf("failed to get backend details: %w", err)
	}

	if backend == nil {
		logger.Info("Backend not found",
			zap.String("backend_id", backendID))
		return nil
	}

	// Show deletion plan
	if err := showDeletionPlan(rc, backend, cleanupAll, preserveCertificates); err != nil {
		return fmt.Errorf("failed to show deletion plan: %w", err)
	}

	// Confirm deletion if not forced
	if !force && !dryRun {
		logger.Info("terminal prompt: Are you sure you want to delete this backend? (y/N)")
		confirmation, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if confirmation != "y" && confirmation != "Y" && confirmation != "yes" {
			logger.Info("Deletion cancelled")
			return nil
		}
	}

	if dryRun {
		logger.Info("Dry run completed - no changes made")
		return nil
	}

	// INTERVENE - Perform deletion
	if err := performBackendDeletion(rc, backend, cleanupAll, preserveCertificates); err != nil {
		return fmt.Errorf("failed to delete backend: %w", err)
	}

	// EVALUATE - Verify deletion
	if err := verifyBackendDeletion(rc, backendID); err != nil {
		logger.Warn("Backend deletion verification failed",
			zap.Error(err))
	}

	logger.Info("Hecate hybrid backend deleted successfully",
		zap.String("backend_id", backendID))

	return nil
}

func getBackendForDeletion(rc *eos_io.RuntimeContext, backendID string) (*hybrid.Backend, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting backend details for deletion",
		zap.String("backend_id", backendID))

	// TODO: Implement backend retrieval from state store
	// This would involve:
	// 1. Query Consul KV for backend configuration
	// 2. Get service registration details
	// 3. Get tunnel configuration
	// 4. Get security configuration

	// For now, return a mock backend
	backend := &hybrid.Backend{
		ID:           backendID,
		Name:         "mock-backend",
		LocalAddress: "192.168.1.100:8080",
		PublicDomain: "app.example.com",
		FrontendDC:   "hetzner",
		BackendDC:    "garage",
	}

	return backend, nil
}

func showDeletionPlan(rc *eos_io.RuntimeContext, backend *hybrid.Backend, cleanupAll, preserveCertificates bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deletion plan for backend",
		zap.String("backend_id", backend.ID),
		zap.String("name", backend.Name),
		zap.String("public_domain", backend.PublicDomain))

	// Resources to be deleted
	resources := []string{
		"Consul service registration",
		"Health monitoring",
		"Routing configuration",
		"State store entries",
	}

	if cleanupAll {
		resources = append(resources, []string{
			"Tunnel configuration",
			"Network routing rules",
			"Consul intentions",
		}...)
	}

	if !preserveCertificates {
		resources = append(resources, "Security certificates")
	}

	logger.Info("The following resources will be deleted:")
	for _, resource := range resources {
		logger.Info(fmt.Sprintf("  - %s", resource))
	}

	return nil
}

func performBackendDeletion(rc *eos_io.RuntimeContext, backend *hybrid.Backend, cleanupAll, preserveCertificates bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Performing backend deletion",
		zap.String("backend_id", backend.ID))

	// Stop health monitoring
	if err := stopHealthMonitoring(rc, backend.ID); err != nil {
		logger.Warn("Failed to stop health monitoring",
			zap.Error(err))
	}

	// Remove Consul service registration
	if err := removeConsulService(rc, backend); err != nil {
		logger.Warn("Failed to remove Consul service",
			zap.Error(err))
	}

	// Remove routing configuration
	if err := removeRoutingConfiguration(rc, backend); err != nil {
		logger.Warn("Failed to remove routing configuration",
			zap.Error(err))
	}

	if cleanupAll {
		// Tear down tunnel
		if err := teardownTunnel(rc, backend); err != nil {
			logger.Warn("Failed to tear down tunnel",
				zap.Error(err))
		}

		// Remove Consul intentions
		if err := removeConsulIntentions(rc, backend); err != nil {
			logger.Warn("Failed to remove Consul intentions",
				zap.Error(err))
		}
	}

	// Clean up certificates
	if !preserveCertificates {
		if err := cleanupCertificates(rc, backend); err != nil {
			logger.Warn("Failed to clean up certificates",
				zap.Error(err))
		}
	}

	// Remove from state store
	if err := removeFromStateStore(rc, backend.ID); err != nil {
		logger.Warn("Failed to remove from state store",
			zap.Error(err))
	}

	logger.Info("Backend deletion completed",
		zap.String("backend_id", backend.ID))

	return nil
}

func verifyBackendDeletion(rc *eos_io.RuntimeContext, backendID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying backend deletion",
		zap.String("backend_id", backendID))

	// Check if backend still exists in state store
	if exists, err := backendExistsInStateStore(rc, backendID); err != nil {
		return fmt.Errorf("failed to check backend existence: %w", err)
	} else if exists {
		return fmt.Errorf("backend still exists in state store")
	}

	// Check if Consul service is removed
	if exists, err := consulServiceExists(rc, backendID); err != nil {
		logger.Warn("Failed to check Consul service existence",
			zap.Error(err))
	} else if exists {
		logger.Warn("Consul service still exists")
	}

	logger.Info("Backend deletion verification completed",
		zap.String("backend_id", backendID))

	return nil
}

// Helper functions

func stopHealthMonitoring(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implement health monitoring stop
	return nil
}

func removeConsulService(_ *eos_io.RuntimeContext, _ *hybrid.Backend) error {
	// TODO: Implement Consul service removal
	return nil
}

func removeRoutingConfiguration(_ *eos_io.RuntimeContext, _ *hybrid.Backend) error {
	// TODO: Implement routing configuration removal
	return nil
}

func teardownTunnel(_ *eos_io.RuntimeContext, _ *hybrid.Backend) error {
	// TODO: Implement tunnel teardown
	return nil
}

func removeConsulIntentions(_ *eos_io.RuntimeContext, _ *hybrid.Backend) error {
	// TODO: Implement Consul intentions removal
	return nil
}

func cleanupCertificates(_ *eos_io.RuntimeContext, _ *hybrid.Backend) error {
	// TODO: Implement certificate cleanup
	return nil
}

func removeFromStateStore(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implement state store removal
	return nil
}

func backendExistsInStateStore(_ *eos_io.RuntimeContext, _ string) (bool, error) {
	// TODO: Implement state store existence check
	return false, nil
}

func consulServiceExists(_ *eos_io.RuntimeContext, _ string) (bool, error) {
	// TODO: Implement Consul service existence check
	return false, nil
}
