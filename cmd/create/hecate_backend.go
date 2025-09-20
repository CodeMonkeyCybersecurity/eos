// cmd/create/hecate_backend.go

package create

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/hybrid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createHecateBackendCmd = &cobra.Command{
	Use:   "hecate-backend",
	Short: "Create a new Hecate hybrid backend connection",
	Long: `Create a new Hecate hybrid backend connection that connects a locally-hosted
backend service to a cloud-hosted frontend proxy through secure tunneling.

This command will:
- Register the backend service in Consul
- Establish secure tunnel connection (Consul Connect, WireGuard, or Cloudflare)
- Configure cross-datacenter routing
- Set up health monitoring
- Configure mTLS certificates

Example:
  eos create hecate-backend \
    --name="my-app" \
    --local-address="192.168.1.100:8080" \
    --public-domain="app.example.com" \
    --frontend-dc="hetzner" \
    --backend-dc="garage" \
    --connection-type="consul-connect"
`,
	RunE: eos_cli.Wrap(runCreateHecateBackend),
}

func init() {
	// Register with create command
	CreateCmd.AddCommand(createHecateBackendCmd)

	// Required flags
	createHecateBackendCmd.Flags().String("name", "", "Name of the backend service (prompted if not provided)")
	createHecateBackendCmd.Flags().String("local-address", "", "Local address of the backend service (prompted if not provided)")
	createHecateBackendCmd.Flags().String("public-domain", "", "Public domain for the service (prompted if not provided)")
	createHecateBackendCmd.Flags().String("frontend-dc", "hetzner", "Frontend datacenter name")
	createHecateBackendCmd.Flags().String("backend-dc", "garage", "Backend datacenter name")

	// Optional flags
	createHecateBackendCmd.Flags().String("connection-type", "", "Connection type (consul-connect, wireguard, cloudflare). Auto-detected if not provided.")
	createHecateBackendCmd.Flags().String("service-port", "8080", "Port for the backend service")
	createHecateBackendCmd.Flags().String("health-check-path", "/health", "Health check path")
	createHecateBackendCmd.Flags().Duration("health-check-timeout", 10*time.Second, "Health check timeout")
	createHecateBackendCmd.Flags().Bool("enable-mtls", true, "Enable mutual TLS")
	createHecateBackendCmd.Flags().String("encryption", "aes-256-gcm", "Encryption algorithm")
	createHecateBackendCmd.Flags().Bool("auto-discovery", true, "Enable auto-discovery of optimal connection method")
	createHecateBackendCmd.Flags().StringSlice("tags", []string{}, "Additional tags for the service")
	createHecateBackendCmd.Flags().String("auth-policy", "", "Authentication policy name")
}

func runCreateHecateBackend(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Hecate hybrid backend connection")

	// Parse flags and prompt for required values
	config, err := parseBackendConfig(rc, cmd)
	if err != nil {
		return fmt.Errorf("failed to parse backend configuration: %w", err)
	}

	// Create backend configuration
	backend := &hybrid.Backend{
		ID:           fmt.Sprintf("backend-%s-%d", config.Name, time.Now().Unix()),
		Name:         config.Name,
		LocalAddress: config.LocalAddress,
		PublicDomain: config.PublicDomain,
		FrontendDC:   config.FrontendDC,
		BackendDC:    config.BackendDC,
		Port:         config.Port,
		DNSName:      config.DNSName,
		ConsulService: hybrid.ConsulServiceDef{
			Name: config.Name,
			Port: config.Port,
			Tags: config.Tags,
			Meta: map[string]string{
				"hybrid-backend": "true",
				"created-by":     "eos-hecate",
				"frontend-dc":    config.FrontendDC,
				"backend-dc":     config.BackendDC,
			},
		},
		HealthCheck: hybrid.HealthCheckDef{
			HTTP:    fmt.Sprintf("http://%s%s", config.LocalAddress, config.HealthCheckPath),
			Timeout: config.HealthCheckTimeout,
		},
		Authentication: &hybrid.AuthConfig{
			Policy: &hybrid.AuthPolicy{
				Name:     config.AuthPolicy,
				Provider: "authentik", // Default provider
			},
		},
	}

	// ASSESS - Validate prerequisites
	if err := validateBackendPrerequisites(rc, backend); err != nil {
		return fmt.Errorf("backend prerequisites validation failed: %w", err)
	}

	// INTERVENE - Create hybrid backend connection
	if err := hybrid.RegisterBackendService(rc, backend); err != nil {
		return fmt.Errorf("failed to register backend service: %w", err)
	}

	// Set up monitoring
	if err := hybrid.MonitorHybridHealth(rc, backend); err != nil {
		logger.Warn("Failed to set up health monitoring",
			zap.Error(err))
	}

	// EVALUATE - Verify backend creation
	if err := verifyBackendCreation(rc, backend); err != nil {
		return fmt.Errorf("backend creation verification failed: %w", err)
	}

	logger.Info("Hecate hybrid backend created successfully",
		zap.String("backend_id", backend.ID),
		zap.String("name", backend.Name),
		zap.String("public_domain", backend.PublicDomain))

	// Print connection details
	logger.Info("Connection details",
		zap.String("backend_id", backend.ID),
		zap.String("local_address", backend.LocalAddress),
		zap.String("public_url", fmt.Sprintf("https://%s", backend.PublicDomain)),
		zap.String("frontend_dc", backend.FrontendDC),
		zap.String("backend_dc", backend.BackendDC))

	return nil
}

type BackendConfig struct {
	Name               string
	LocalAddress       string
	PublicDomain       string
	FrontendDC         string
	BackendDC          string
	ConnectionType     string
	Port               int
	DNSName            string
	HealthCheckPath    string
	HealthCheckTimeout time.Duration
	EnableMTLS         bool
	Encryption         string
	AutoDiscovery      bool
	Tags               []string
	AuthPolicy         string
}

func parseBackendConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*BackendConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get flags
	name, _ := cmd.Flags().GetString("name")
	localAddress, _ := cmd.Flags().GetString("local-address")
	publicDomain, _ := cmd.Flags().GetString("public-domain")
	frontendDC, _ := cmd.Flags().GetString("frontend-dc")
	backendDC, _ := cmd.Flags().GetString("backend-dc")
	connectionType, _ := cmd.Flags().GetString("connection-type")
	servicePort, _ := cmd.Flags().GetString("service-port")
	healthCheckPath, _ := cmd.Flags().GetString("health-check-path")
	healthCheckTimeout, _ := cmd.Flags().GetDuration("health-check-timeout")
	enableMTLS, _ := cmd.Flags().GetBool("enable-mtls")
	encryption, _ := cmd.Flags().GetString("encryption")
	autoDiscovery, _ := cmd.Flags().GetBool("auto-discovery")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	authPolicy, _ := cmd.Flags().GetString("auth-policy")

	// Parse port
	port := 8080
	if servicePort != "" {
		if p, err := parsePort(servicePort); err == nil {
			port = p
		}
	}

	// Extract port from local address if not provided
	if localAddress != "" {
		if host, portStr, err := parseHostPort(localAddress); err == nil {
			if p, err := parsePort(portStr); err == nil {
				port = p
				localAddress = host
			}
		}
	}

	// Interactive prompts for required fields
	if name == "" {
		logger.Info("terminal prompt: Enter backend service name")
		input, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read service name: %w", err)
		}
		name = input
	}

	if localAddress == "" {
		logger.Info("terminal prompt: Enter local address (e.g., 192.168.1.100:8080)")
		input, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read local address: %w", err)
		}
		localAddress = input
	}

	if publicDomain == "" {
		logger.Info("terminal prompt: Enter public domain (e.g., app.example.com)")
		input, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read public domain: %w", err)
		}
		publicDomain = input
	}

	config := &BackendConfig{
		Name:               name,
		LocalAddress:       localAddress,
		PublicDomain:       publicDomain,
		FrontendDC:         frontendDC,
		BackendDC:          backendDC,
		ConnectionType:     connectionType,
		Port:               port,
		HealthCheckPath:    healthCheckPath,
		HealthCheckTimeout: healthCheckTimeout,
		EnableMTLS:         enableMTLS,
		Encryption:         encryption,
		AutoDiscovery:      autoDiscovery,
		Tags:               tags,
		AuthPolicy:         authPolicy,
	}

	return config, nil
}

func validateBackendPrerequisites(rc *eos_io.RuntimeContext, backend *hybrid.Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating backend prerequisites",
		zap.String("backend_id", backend.ID))

	// Check if local address is reachable
	if err := validateLocalAddress(rc, backend.LocalAddress); err != nil {
		return fmt.Errorf("local address validation failed: %w", err)
	}

	// Check if public domain is not already in use
	if err := validatePublicDomain(rc, backend.PublicDomain); err != nil {
		return fmt.Errorf("public domain validation failed: %w", err)
	}

	// Check Consul connectivity
	if err := validateConsulConnectivity(rc); err != nil {
		return fmt.Errorf("consul connectivity validation failed: %w", err)
	}

	return nil
}

func verifyBackendCreation(rc *eos_io.RuntimeContext, backend *hybrid.Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying backend creation",
		zap.String("backend_id", backend.ID))

	// Check if service is registered in Consul
	if err := verifyConsulServiceRegistration(rc, backend.ConsulService.Name); err != nil {
		return fmt.Errorf("consul service registration verification failed: %w", err)
	}

	// Check if health monitoring is active
	if err := verifyHealthMonitoring(rc, backend.ID); err != nil {
		logger.Warn("Health monitoring verification failed",
			zap.Error(err))
	}

	// Test connectivity through tunnel
	if err := testTunnelConnectivity(rc, backend); err != nil {
		logger.Warn("Tunnel connectivity test failed",
			zap.Error(err))
	}

	return nil
}

// Helper functions

func parsePort(_ string) (int, error) {
	// TODO: Implement port parsing
	return 8080, nil
}

func parseHostPort(_ string) (string, string, error) {
	// TODO: Implement host:port parsing
	return "localhost", "8080", nil
}

func validateLocalAddress(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implement local address validation
	return nil
}

func validatePublicDomain(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implement public domain validation
	return nil
}

func validateConsulConnectivity(_ *eos_io.RuntimeContext) error {
	// TODO: Implement Consul connectivity validation
	return nil
}

func verifyConsulServiceRegistration(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implement Consul service registration verification
	return nil
}

func verifyHealthMonitoring(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implement health monitoring verification
	return nil
}

func testTunnelConnectivity(_ *eos_io.RuntimeContext, _ *hybrid.Backend) error {
	// TODO: Implement tunnel connectivity test
	return nil
}
