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
	createHecateRouteCmd.Flags().String("domain", "", "Domain name for the route (required)")
	createHecateRouteCmd.Flags().String("upstream", "", "Upstream backend address (required)")
	createHecateRouteCmd.Flags().String("auth-policy", "", "Authentication policy name")
	createHecateRouteCmd.Flags().StringSlice("headers", []string{}, "Custom headers in key=value format")
	createHecateRouteCmd.Flags().Bool("auto-https", true, "Enable automatic HTTPS via Let's Encrypt")
	createHecateRouteCmd.Flags().Bool("force-https", true, "Force redirect HTTP to HTTPS")
	createHecateRouteCmd.Flags().String("health-check-path", "", "Health check endpoint path")
	createHecateRouteCmd.Flags().String("health-check-interval", "30s", "Health check interval")
	createHecateRouteCmd.Flags().Bool("require-mfa", false, "Require MFA for authentication")

	// Mark required flags
	_ = createHecateRouteCmd.MarkFlagRequired("domain")
	_ = createHecateRouteCmd.MarkFlagRequired("upstream")
}

func runCreateHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	domain, _ := cmd.Flags().GetString("domain")
	upstream, _ := cmd.Flags().GetString("upstream")
	authPolicy, _ := cmd.Flags().GetString("auth-policy")
	headersList, _ := cmd.Flags().GetStringSlice("headers")
	autoHTTPS, _ := cmd.Flags().GetBool("auto-https")
	forceHTTPS, _ := cmd.Flags().GetBool("force-https")
	healthCheckPath, _ := cmd.Flags().GetString("health-check-path")
	healthCheckInterval, _ := cmd.Flags().GetString("health-check-interval")
	requireMFA, _ := cmd.Flags().GetBool("require-mfa")

	logger.Info("Creating new Hecate route",
		zap.String("domain", domain),
		zap.String("upstream", upstream),
		zap.String("auth_policy", authPolicy))

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
		Domain:     domain,
		Upstream:   upstream,
		AuthPolicy: authPolicy,
		Headers:    headers,
		TLS: &hecate.TLSConfig{
			AutoHTTPS:  autoHTTPS,
			ForceHTTPS: forceHTTPS,
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
			Path:               healthCheckPath,
			Interval:           interval,
			Timeout:            5 * time.Second,
			UnhealthyThreshold: 3,
			HealthyThreshold:   2,
			ExpectedStatus:     []int{200, 204},
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

		route.AuthPolicy = policyName
	}

	// Create the route
	if err := hecate.CreateRoute(rc, route); err != nil {
		return err
	}

	logger.Info("Route created successfully",
		zap.String("domain", domain),
		zap.String("upstream", upstream))

	// Print success message
	fmt.Printf("\n Route created successfully!\n")
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Upstream: %s\n", upstream)
	if route.AuthPolicy != "" {
		fmt.Printf("Auth Policy: %s\n", route.AuthPolicy)
	}
	if route.TLS.AutoHTTPS {
		fmt.Printf("\n🔒 HTTPS will be automatically configured via Let's Encrypt\n")
	}
	fmt.Printf("\nYou can now access your service at: https://%s\n", domain)

	return nil
}
