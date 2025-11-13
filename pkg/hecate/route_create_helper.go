// pkg/hecate/route_create_helper.go

package hecate

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RouteCreationOptions contains all options for creating a new route
// Simplified to match Hecate's YAML config philosophy: domain + backend + optional auth
type RouteCreationOptions struct {
	Domain      string
	Upstream    string   // Backend address (e.g., "localhost:3000", "192.168.1.100:8080")
	RequireAuth bool     // Enable Authentik SSO protection
	Headers     []string // Optional custom headers in "key=value" format
	Force       bool     // Skip confirmation prompt
}

// CreateRouteInteractive creates a new route with interactive prompts for missing values
// This is the unified implementation used by both "eos create hecate route" and "eos update hecate route --add"
func CreateRouteInteractive(rc *eos_io.RuntimeContext, opts *RouteCreationOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Prompt for required fields if not provided
	if opts.Domain == "" {
		logger.Info("Domain not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the domain name for the new route")

		input, err := eos_io.PromptInput(rc, "Domain", "Enter domain name")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		opts.Domain = input
	}

	if opts.Upstream == "" {
		logger.Info("Upstream not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the upstream backend address (e.g., localhost:3000)")

		input, err := eos_io.PromptInput(rc, "Upstream", "Enter upstream address")
		if err != nil {
			return fmt.Errorf("failed to read upstream: %w", err)
		}
		opts.Upstream = input
	}

	// Validate reserved domains cannot be protected with auth
	if opts.RequireAuth && IsReservedDomain(opts.Domain) {
		return fmt.Errorf("cannot enable authentication on reserved domain '%s' - this would lock you out of the SSO provider itself", opts.Domain)
	}

	logger.Info("Creating new Hecate route",
		zap.String("domain", opts.Domain),
		zap.String("upstream", opts.Upstream),
		zap.Bool("require_auth", opts.RequireAuth))

	// Parse headers from key=value format
	headers := make(map[string]string)
	for _, header := range opts.Headers {
		parts := strings.SplitN(header, "=", 2)
		if len(parts) != 2 {
			logger.Warn("Invalid header format, skipping",
				zap.String("header", header))
			continue
		}
		headers[parts[0]] = parts[1]
	}

	// INTERVENE: Build route configuration
	// Note: Caddy automatically handles HTTPS via Let's Encrypt, so no TLS config needed
	route := &Route{
		Domain:      opts.Domain,
		Upstream:    &Upstream{URL: opts.Upstream},
		RequireAuth: opts.RequireAuth,
		Headers:     headers,
	}

	// Show what will be created if not forced
	if !opts.Force {
		logger.Info("terminal prompt: About to create new route:")
		logger.Info(fmt.Sprintf("terminal prompt:   Domain: %s", opts.Domain))
		logger.Info(fmt.Sprintf("terminal prompt:   Upstream: %s", opts.Upstream))
		if opts.RequireAuth {
			logger.Info("terminal prompt:   Auth: Authentik SSO required")
		}
		logger.Info("terminal prompt:   HTTPS: Automatic (Caddy + Let's Encrypt)")
		logger.Info("terminal prompt: Proceed with creation? (y/N)")

		confirm, err := eos_io.PromptInput(rc, "Confirm", "Proceed with creation? (y/N)")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if !strings.HasPrefix(strings.ToLower(confirm), "y") {
			logger.Info("terminal prompt: Route creation cancelled")
			return nil
		}
	}

	// Load Hecate configuration
	config, err := LoadRouteConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load Hecate config: %w", err)
	}

	// Create the route
	if err := CreateRoute(rc, config, route); err != nil {
		return fmt.Errorf("failed to create route: %w", err)
	}

	// EVALUATE: Display success message
	logger.Info("Route created successfully",
		zap.String("domain", opts.Domain),
		zap.String("upstream", opts.Upstream))

	logger.Info("terminal prompt: Route created successfully!")
	logger.Info("terminal prompt: Domain", zap.String("value", opts.Domain))
	logger.Info("terminal prompt: Upstream", zap.String("value", opts.Upstream))
	if opts.RequireAuth {
		logger.Info("terminal prompt: Auth: Authentik SSO enabled")
	}
	logger.Info("terminal prompt: HTTPS will be automatically configured via Let's Encrypt")
	logger.Info("terminal prompt: You can now access your service at", zap.String("url", "https://"+opts.Domain))

	return nil
}
