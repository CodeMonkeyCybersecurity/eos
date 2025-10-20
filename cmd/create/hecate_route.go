package create

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createHecateRouteCmd = &cobra.Command{
	Use:   "route",
	Short: "Create a new reverse proxy route in Hecate",
	Long: `Create a new reverse proxy route in Hecate.
	
This command creates a route that maps a domain to an upstream backend service.
You can optionally specify authentication policies, custom headers, and health checks.

Examples:
  eos create hecate route --domain app.example.com --upstream localhost:3000
  eos create hecate route --domain api.example.com --upstream localhost:8080 --auth-policy api-users
  eos create hecate route --domain secure.example.com --upstream localhost:443 --require-mfa`,
	RunE: eos_cli.Wrap(runCreateHecateRoute),
}

func init() {
	// Add route subcommand to the existing Hecate command
	CreateHecateCmd.AddCommand(createHecateRouteCmd)

	// Define flags
	createHecateRouteCmd.Flags().String("domain", "", "Domain name for the route (prompted if not provided)")
	createHecateRouteCmd.Flags().String("upstream", "", "Upstream backend address (prompted if not provided)")
	createHecateRouteCmd.Flags().String("auth-policy", "", "Authentication policy name")
	createHecateRouteCmd.Flags().StringSlice("headers", []string{}, "Custom headers in key=value format")
	createHecateRouteCmd.Flags().Bool("auto-https", true, "Enable automatic HTTPS via Let's Encrypt")
	createHecateRouteCmd.Flags().Bool("force-https", true, "Force redirect HTTP to HTTPS")
	createHecateRouteCmd.Flags().String("health-check-path", "", "Health check endpoint path")
	createHecateRouteCmd.Flags().String("health-check-interval", "30s", "Health check interval")
	createHecateRouteCmd.Flags().Bool("require-mfa", false, "Require MFA for authentication")
	createHecateRouteCmd.Flags().Bool("require-auth", false, "Require Authentik SSO authentication (forward_auth)")

	// Domain and upstream are required but will be prompted if not provided
}

func runCreateHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	domain, _ := cmd.Flags().GetString("domain")
	upstream, _ := cmd.Flags().GetString("upstream")
	authPolicy, _ := cmd.Flags().GetString("auth-policy")
	headersList, _ := cmd.Flags().GetStringSlice("headers")
	autoHTTPS, _ := cmd.Flags().GetBool("auto-https")
	_, _ = cmd.Flags().GetBool("force-https") // Not used in current implementation
	healthCheckPath, _ := cmd.Flags().GetString("health-check-path")
	healthCheckInterval, _ := cmd.Flags().GetString("health-check-interval")
	requireMFA, _ := cmd.Flags().GetBool("require-mfa")
	requireAuth, _ := cmd.Flags().GetBool("require-auth")

	// Prompt for domain if not provided
	if domain == "" {
		logger.Info("Domain not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the domain name for the route")

		input, err := eos_io.PromptInput(rc, "Domain", "Enter domain name")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		domain = input
	}

	// Prompt for upstream if not provided
	if upstream == "" {
		logger.Info("Upstream not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the upstream backend address")

		input, err := eos_io.PromptInput(rc, "Upstream", "Enter upstream address")
		if err != nil {
			return fmt.Errorf("failed to read upstream: %w", err)
		}
		upstream = input
	}

	// Validate reserved domains cannot be protected with auth
	if requireAuth && hecate.IsReservedDomain(domain) {
		return fmt.Errorf("cannot enable authentication on reserved domain '%s' - this would lock you out of the SSO provider itself", domain)
	}

	logger.Info("Creating new Hecate route",
		zap.String("domain", domain),
		zap.String("upstream", upstream),
		zap.String("auth_policy", authPolicy),
		zap.Bool("require_auth", requireAuth))

	// Parse headers
	headers := make(map[string]string)
	for _, header := range headersList {
		// Parse key=value format
		var key, value string
		_, err := fmt.Sscanf(header, "%s=%s", &key, &value)
		if err != nil {
			logger.Warn("Invalid header format, skipping",
				zap.String("header", header))
			continue
		}
		headers[key] = value
	}

	// Build route configuration
	route := &hecate.Route{
		Domain:      domain,
		Upstream:    &hecate.Upstream{URL: upstream},
		AuthPolicy:  nil, // Will be set below if needed
		RequireAuth: requireAuth,
		Headers:     headers,
		TLS: &hecate.TLSConfig{
			Enabled: autoHTTPS,
		},
	}

	// Add health check if specified
	if healthCheckPath != "" {
		interval, err := time.ParseDuration(healthCheckInterval)
		if err != nil {
			logger.Warn("Invalid health check interval, using default",
				zap.Error(err))
			interval = 30 * time.Second
		}

		route.HealthCheck = &hecate.HealthCheck{
			Path:             healthCheckPath,
			Interval:         interval,
			Timeout:          5 * time.Second,
			FailureThreshold: 3,
			SuccessThreshold: 2,
			HealthyStatus:    []int{200, 204},
			Enabled:          true,
		}
	}

	// Create auth policy if MFA is required and no policy specified
	if requireMFA && authPolicy == "" {
		// Generate a default policy name
		policyName := fmt.Sprintf("%s-mfa-policy", strings.ReplaceAll(domain, ".", "-"))

		logger.Info("Creating MFA authentication policy",
			zap.String("policy_name", policyName))

		authPolicyObj := &hecate.AuthPolicy{
			Name:       policyName,
			Provider:   "authentik",
			Flow:       "default-authentication-flow",
			RequireMFA: true,
		}

		if err := hecate.CreateAuthPolicy(rc, authPolicyObj); err != nil {
			return fmt.Errorf("failed to create auth policy: %w", err)
		}

		route.AuthPolicy = &hecate.AuthPolicy{
			Name:       policyName,
			Provider:   "authentik", // Default provider
			RequireMFA: requireMFA,
		}
	}

	// Load Hecate configuration
	config, err := hecate.LoadRouteConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load Hecate config: %w", err)
	}

	// Create the route
	if err := hecate.CreateRoute(rc, config, route); err != nil {
		return err
	}

	logger.Info("Route created successfully",
		zap.String("domain", domain),
		zap.String("upstream", upstream))

	// Print success message
	logger.Info("terminal prompt: Route created successfully!")
	logger.Info("terminal prompt: Domain", zap.String("value", domain))
	logger.Info("terminal prompt: Upstream", zap.String("value", upstream))
	if route.AuthPolicy != nil {
		logger.Info("terminal prompt: Auth Policy", zap.String("value", route.AuthPolicy.Name))
	}
	if route.TLS.Enabled {
		logger.Info("terminal prompt: 🔒 HTTPS will be automatically configured via Let's Encrypt")
	}
	logger.Info("terminal prompt: You can now access your service at", zap.String("url", "https://"+domain))

	return nil
}
