// cmd/create/boundary.go

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var CreateBoundaryCmd = &cobra.Command{
	Use:   "boundary",
	Short: "Install HashiCorp Boundary using native installer",
	Long: `Install HashiCorp Boundary for secure remote access.

This installer provides:
- Controller and/or worker configuration
- Database setup for controllers
- KMS configuration
- Development mode
- TLS setup

Examples:
  eos create boundary --dev                     # Development mode
  eos create boundary --controller              # Controller only
  eos create boundary --worker                  # Worker only
  eos create boundary --database-url=...        # With PostgreSQL`,
	RunE: eos.Wrap(runCreateBoundaryNative),
}

// TODO: refactor
var (
	// Installation options
	boundaryRole        string
	boundaryVersion     string
	boundaryForce       bool
	boundaryClean       bool
	boundaryClusterName string

	// Controller options
	boundaryDatabaseURL       string
	boundaryPublicClusterAddr string
	boundaryPublicAddr        string

	// Worker options
	boundaryUpstreams       string
	boundaryPublicProxyAddr string

	// Common options
	boundaryListenerAddr string
	boundaryTLSDisable   bool
	boundaryTLSCertFile  string
	boundaryTLSKeyFile   string

	// KMS options
	boundaryKMSType   string
	boundaryKMSKeyID  string
	boundaryKMSRegion string

	// Stream output
	boundaryStreamOutput bool
)

// TODO: refactor
func runCreateBoundaryNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Boundary using native installer")

	// Parse flags
	config := &boundary.InstallConfig{
		Version:           boundaryVersion,
		UseRepository:     false, // Always use binary for Boundary
		ControllerEnabled: boundaryRole == "controller" || boundaryRole == "dev",
		WorkerEnabled:     boundaryRole == "worker" || boundaryRole == "dev",
		DevMode:           boundaryRole == "dev",
		DatabaseURL:       boundaryDatabaseURL,
		ClusterAddr:       boundaryPublicClusterAddr,
		PublicAddr:        boundaryPublicAddr,
		RecoveryKmsType:   boundaryKMSType,
		KmsKeyID:          boundaryKMSKeyID,
		CleanInstall:      boundaryClean,
		ForceReinstall:    boundaryForce,
	}

	// Create and run installer
	installer := boundary.NewBoundaryInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("boundary installation failed: %w", err)
	}

	logger.Info("Boundary installation completed successfully")
	if config.DevMode {
		logger.Info("terminal prompt: Boundary is installed in dev mode. Run: boundary-dev")
	} else {
		logger.Info("terminal prompt: Boundary is installed. Check status with: systemctl status boundary")
	}
	return nil
}

// TODO: Legacy boundary creation - removed during HashiCorp migration
// This function was replaced with Nomad-based orchestration
// Restore if direct boundary installation is needed outside of Nomad

// initializeBoundaryClient replaced with Nomad orchestration
// TODO: Nomad client initialization for Boundary
// This will be implemented when Nomad API integration is complete

// displayBoundaryStatus - REMOVED: Function no longer used
// TODO: Restore when Boundary status display is needed

// TODO: Boundary fallback implementation
// This will be replaced with administrator escalation pattern
// when system-level boundary installation is needed

func init() {
	// Role configuration
	CreateBoundaryCmd.Flags().StringVar(&boundaryRole, "role", "controller", "Boundary role: controller, worker, or dev")
	CreateBoundaryCmd.Flags().StringVar(&boundaryVersion, "version", "", "Specific Boundary version to install")
	CreateBoundaryCmd.Flags().BoolVar(&boundaryForce, "force", false, "Force reinstallation even if already installed")
	CreateBoundaryCmd.Flags().BoolVar(&boundaryClean, "clean", false, "Remove all data and perform clean installation")
	CreateBoundaryCmd.Flags().StringVar(&boundaryClusterName, "cluster-name", "eos", "Boundary cluster name")

	// Controller configuration
	CreateBoundaryCmd.Flags().StringVar(&boundaryDatabaseURL, "database-url", "", "PostgreSQL connection string for controllers")
	CreateBoundaryCmd.Flags().StringVar(&boundaryPublicClusterAddr, "public-cluster-addr", "", "Public address for cluster communication")
	CreateBoundaryCmd.Flags().StringVar(&boundaryPublicAddr, "public-addr", "", "Public address for API")

	// Worker configuration
	CreateBoundaryCmd.Flags().StringVar(&boundaryUpstreams, "upstream", "", "Comma-separated list of upstream controllers for workers")
	CreateBoundaryCmd.Flags().StringVar(&boundaryPublicProxyAddr, "public-proxy-addr", "", "Public address for worker proxy")

	// Common configuration
	CreateBoundaryCmd.Flags().StringVar(&boundaryListenerAddr, "listener-addr", "0.0.0.0", "Listener address")
	CreateBoundaryCmd.Flags().BoolVar(&boundaryTLSDisable, "tls-disable", false, "Disable TLS (not recommended for production)")
	CreateBoundaryCmd.Flags().StringVar(&boundaryTLSCertFile, "tls-cert", "", "Path to TLS certificate file")
	CreateBoundaryCmd.Flags().StringVar(&boundaryTLSKeyFile, "tls-key", "", "Path to TLS key file")

	// KMS configuration
	CreateBoundaryCmd.Flags().StringVar(&boundaryKMSType, "kms-type", "aead", "KMS type (aead, awskms, azurekeyvault, gcpckms, ocikms, transit)")
	CreateBoundaryCmd.Flags().StringVar(&boundaryKMSKeyID, "kms-key-id", "", "KMS key ID")
	CreateBoundaryCmd.Flags().StringVar(&boundaryKMSRegion, "kms-region", "", "KMS region (for cloud KMS)")

	// Output options
	CreateBoundaryCmd.Flags().BoolVar(&boundaryStreamOutput, "stream", false, "Stream installation output in real-time")

	// Register the command
	CreateCmd.AddCommand(CreateBoundaryCmd)
}
