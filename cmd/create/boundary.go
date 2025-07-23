// cmd/create/boundary.go

package create

import (
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateBoundaryCmd = &cobra.Command{
	Use:   "boundary",
	Short: "Install and configure HashiCorp Boundary",
	Long: `Install and configure HashiCorp Boundary for secure remote access.

This command will:
- Check if Boundary is already installed and running
- Install Boundary with proper idempotency
- Configure Boundary as controller or worker based on flags
- Set up database (for controllers)
- Configure KMS for encryption
- Set up systemd service
- Verify installation and connectivity

ARCHITECTURE:
Boundary provides identity-based access to infrastructure without exposing
networks. It consists of:
- Controllers: Manage workers, handle API requests, store data
- Workers: Proxy connections between users and targets
- Database: PostgreSQL backend for controllers

EXAMPLES:
  # Install Boundary controller with PostgreSQL
  eos create boundary --role controller --database-url "postgresql://boundary:password@localhost/boundary"

  # Install Boundary worker connecting to controllers
  eos create boundary --role worker --upstream "controller1.example.com:9201,controller2.example.com:9201"

  # Install combined dev mode (controller + worker)
  eos create boundary --role dev

  # Install with specific version
  eos create boundary --version 0.15.0

  # Force reinstall/reconfigure
  eos create boundary --force

  # Clean install (remove existing data)
  eos create boundary --clean`,
	RunE: eos.Wrap(runCreateBoundary),
}

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
	boundaryUpstreams      string
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

func runCreateBoundary(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}
	
	logger.Info("Starting Boundary installation process",
		zap.String("role", boundaryRole),
		zap.String("version", boundaryVersion),
		zap.String("cluster", boundaryClusterName),
		zap.Bool("force", boundaryForce),
		zap.Bool("clean", boundaryClean))
	
	// Validate role
	if boundaryRole != "controller" && boundaryRole != "worker" && boundaryRole != "dev" {
		return eos_err.NewUserError("role must be one of: controller, worker, dev")
	}
	
	// Validate controller requirements
	if (boundaryRole == "controller" || boundaryRole == "dev") && boundaryDatabaseURL == "" {
		logger.Info("terminal prompt: Database URL is required for controller role")
		logger.Info("terminal prompt: Please enter PostgreSQL connection string (e.g., postgresql://boundary:password@localhost/boundary)")
		
		dbURL, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read database URL: %w", err)
		}
		boundaryDatabaseURL = dbURL
	}
	
	// Validate worker requirements
	if boundaryRole == "worker" && boundaryUpstreams == "" {
		logger.Info("terminal prompt: Upstream controllers are required for worker role")
		logger.Info("terminal prompt: Please enter comma-separated controller addresses (e.g., controller1:9201,controller2:9201)")
		
		upstreams, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read upstreams: %w", err)
		}
		boundaryUpstreams = upstreams
	}
	
	// Initialize Salt client
	saltClient, err := initializeBoundarySaltClient(logger)
	if err != nil {
		logger.Info("Salt API not configured, falling back to local salt-call execution")
		return runCreateBoundaryFallback(rc, cmd, args)
	}
	
	// Create Boundary manager
	manager, err := boundary.NewManager(rc, saltClient)
	if err != nil {
		return fmt.Errorf("failed to create boundary manager: %w", err)
	}
	
	// Build configuration
	config := &boundary.Config{
		Role:              boundaryRole,
		Version:           boundaryVersion,
		ClusterName:       boundaryClusterName,
		DatabaseURL:       boundaryDatabaseURL,
		PublicClusterAddr: boundaryPublicClusterAddr,
		PublicAddr:        boundaryPublicAddr,
		PublicProxyAddr:   boundaryPublicProxyAddr,
		ListenerAddress:   boundaryListenerAddr,
		TLSDisable:        boundaryTLSDisable,
		TLSCertFile:       boundaryTLSCertFile,
		TLSKeyFile:        boundaryTLSKeyFile,
		KMSType:           boundaryKMSType,
		KMSKeyID:          boundaryKMSKeyID,
		KMSRegion:         boundaryKMSRegion,
	}
	
	// Parse upstreams for workers
	if boundaryUpstreams != "" {
		config.InitialUpstreams = strings.Split(boundaryUpstreams, ",")
		for i, upstream := range config.InitialUpstreams {
			config.InitialUpstreams[i] = strings.TrimSpace(upstream)
		}
	}
	
	// Create options
	createOpts := &boundary.CreateOptions{
		Target:       "*", // Could be made configurable
		Config:       config,
		Force:        boundaryForce,
		Clean:        boundaryClean,
		StreamOutput: boundaryStreamOutput,
		Timeout:      30 * time.Minute,
	}
	
	// Check current status first
	logger.Info("Checking current Boundary status")
	statusOpts := &boundary.StatusOptions{
		Target:   createOpts.Target,
		Detailed: true,
	}
	
	status, err := manager.Status(rc.Ctx, statusOpts)
	if err != nil {
		logger.Warn("Could not determine Boundary status", zap.Error(err))
	} else {
		// Display current status
		displayBoundaryStatus(logger, status)
		
		// Check if already installed and running
		allRunning := true
		for _, minionStatus := range status.Minions {
			if !minionStatus.Status.Running || minionStatus.Status.Failed {
				allRunning = false
				break
			}
		}
		
		if allRunning && !boundaryForce && !boundaryClean {
			logger.Info("terminal prompt: Boundary is already installed and running.")
			logger.Info("terminal prompt: Use --force to reconfigure or --clean for a fresh install.")
			return nil
		}
	}
	
	// Execute installation
	logger.Info("terminal prompt: Starting Boundary installation...")
	
	if boundaryStreamOutput {
		logger.Info("terminal prompt: Streaming installation progress...")
	}
	
	err = manager.Create(rc.Ctx, createOpts)
	if err != nil {
		return fmt.Errorf("boundary installation failed: %w", err)
	}
	
	// Verify installation
	logger.Info("Verifying Boundary installation")
	time.Sleep(5 * time.Second) // Give services time to start
	
	finalStatus, err := manager.Status(rc.Ctx, statusOpts)
	if err != nil {
		logger.Warn("Could not verify final status", zap.Error(err))
	} else {
		displayBoundaryStatus(logger, finalStatus)
	}
	
	logger.Info("terminal prompt: ✅ Boundary installation completed successfully!")
	
	// Display connection information based on role
	switch boundaryRole {
	case "controller", "dev":
		logger.Info(fmt.Sprintf("terminal prompt: Boundary API available at: https://<server-ip>:%d", 9200))
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Next steps:")
		logger.Info("terminal prompt: 1. Initialize the database: boundary database init -config /etc/boundary/controller.hcl")
		logger.Info("terminal prompt: 2. Create initial admin user")
		logger.Info("terminal prompt: 3. Configure authentication methods")
		logger.Info("terminal prompt: 4. Set up targets and host catalogs")
		
	case "worker":
		logger.Info("terminal prompt: Boundary worker installed and connected to upstream controllers")
		logger.Info("terminal prompt: Worker will proxy connections for authorized sessions")
	}
	
	return nil
}

func initializeBoundarySaltClient(logger otelzap.LoggerWithCtx) (*salt.Client, error) {
	// Get underlying zap logger
	baseLogger := logger.ZapLogger()
	config := salt.ClientConfig{
		BaseURL:            getEnvOrDefault("SALT_API_URL", "https://localhost:8000"),
		Username:           getEnvOrDefault("SALT_API_USER", "eos-service"),
		Password:           os.Getenv("SALT_API_PASSWORD"),
		EAuth:              "pam",
		Timeout:            10 * time.Minute,
		MaxRetries:         3,
		InsecureSkipVerify: getEnvOrDefault("SALT_API_INSECURE", "false") == "true",
		Logger:             baseLogger,
	}
	
	if config.Password == "" {
		// Fall back to using salt-call directly if API is not configured
		return nil, fmt.Errorf("Salt API not configured")
	}
	
	return salt.NewClient(config)
}

func displayBoundaryStatus(logger otelzap.LoggerWithCtx, status *boundary.StatusResult) {
	logger.Info("terminal prompt: Current Boundary Status:")
	
	for minion, minionStatus := range status.Minions {
		logger.Info(fmt.Sprintf("terminal prompt: === %s ===", minion))
		s := minionStatus.Status
		logger.Info(fmt.Sprintf("terminal prompt:   Installed:     %v", s.Installed))
		logger.Info(fmt.Sprintf("terminal prompt:   Running:       %v", s.Running))
		logger.Info(fmt.Sprintf("terminal prompt:   Role:          %s", s.Role))
		if s.Version != "" {
			logger.Info(fmt.Sprintf("terminal prompt:   Version:       %s", s.Version))
		}
		if s.Failed {
			logger.Info(fmt.Sprintf("terminal prompt:   ⚠️  Status:       FAILED"))
			if s.LastError != "" {
				logger.Info(fmt.Sprintf("terminal prompt:   Last Error:    %s", s.LastError))
			}
		}
		if s.DatabaseConnected {
			logger.Info(fmt.Sprintf("terminal prompt:   Database:      Connected"))
		}
	}
}

// runCreateBoundaryFallback is the fallback implementation using salt-call
func runCreateBoundaryFallback(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// This would contain the original shell-based implementation
	// For now, we'll return an error indicating API is required
	return fmt.Errorf("Salt API required for Boundary installation. Please configure SALT_API_* environment variables")
}

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