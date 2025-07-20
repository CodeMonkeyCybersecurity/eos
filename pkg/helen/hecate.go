// pkg/helen/hecate.go
// Hecate reverse proxy integration for Helen deployments

package helen

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureHecateStaticRoute configures the Hecate reverse proxy for static Helen deployment
func ConfigureHecateStaticRoute(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Hecate configuration
	hecateConfig := &hecate.HecateConfig{
		// Use default configuration
	}
	
	// Create route for static site
	route := &hecate.Route{
		ID:     fmt.Sprintf("helen-static-%s", config.Namespace),
		Domain: config.Domain,
		Upstream: &hecate.Upstream{
			URL:             fmt.Sprintf("http://localhost:%d", config.Port),
			Timeout:         30 * time.Second,
			HealthCheckPath: "/",
		},
		Headers: map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"X-XSS-Protection":       "1; mode=block",
			"Cache-Control":          "public, max-age=3600",
		},
		HealthCheck: &hecate.HealthCheck{
			Path:     "/",
			Interval: 10 * time.Second,
			Timeout:  5 * time.Second,
			Enabled:  true,
		},
		Status: hecate.RouteStatus{
			State:  "active",
			Health: "healthy",
		},
	}
	
	logger.Info("Configuring Hecate route for static Helen",
		zap.String("domain", config.Domain),
		zap.String("upstream", route.Upstream.URL))
	
	return hecate.CreateRoute(rc, hecateConfig, route)
}

// ConfigureHecateRoute is a wrapper that calls ConfigureHecateStaticRoute
// This maintains backward compatibility with existing code
func ConfigureHecateRoute(rc *eos_io.RuntimeContext, config *Config) error {
	return ConfigureHecateStaticRoute(rc, config)
}

// ConfigureHecateGhostRoute configures the Hecate reverse proxy for Ghost deployment
func ConfigureHecateGhostRoute(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Hecate configuration
	hecateConfig := &hecate.HecateConfig{
		// Use default configuration
	}
	
	// Create route for Ghost CMS
	route := &hecate.Route{
		ID:     fmt.Sprintf("helen-ghost-%s", config.Environment),
		Domain: config.Domain,
		Upstream: &hecate.Upstream{
			URL:             fmt.Sprintf("http://localhost:%d", config.Port),
			Timeout:         300 * time.Second, // Longer timeout for Ghost admin operations
			HealthCheckPath: "/ghost/api/admin/site/",
		},
		Headers: map[string]string{
			"X-Forwarded-Proto":   "https",
			"X-Forwarded-Host":    config.Domain,
			"X-Real-IP":           "$remote_addr",
			"X-Forwarded-For":     "$proxy_add_x_forwarded_for",
			"X-Helen-Environment": config.Environment,
		},
		HealthCheck: &hecate.HealthCheck{
			Path:     "/ghost/api/admin/site/",
			Interval: 10 * time.Second,
			Timeout:  5 * time.Second,
			Enabled:  true,
		},
		Status: hecate.RouteStatus{
			State:  "active",
			Health: "healthy",
		},
	}
	
	// Add authentication if enabled
	if config.EnableAuth {
		route.AuthPolicy = &hecate.AuthPolicy{
			Name:       fmt.Sprintf("helen-ghost-%s-auth", config.Environment),
			Provider:   "authentik",
			RequireMFA: false,
			SessionTTL: 24 * time.Hour,
		}
	}
	
	// Add rate limiting for API endpoints
	route.RateLimit = &hecate.RateLimit{
		RequestsPerSecond: 100,
		BurstSize:         200,
		WindowSize:        time.Minute,
		KeyBy:             "ip",
		Enabled:           true,
	}
	
	logger.Info("Configuring Hecate route for Ghost",
		zap.String("domain", config.Domain),
		zap.String("upstream", route.Upstream.URL),
		zap.Bool("auth_enabled", config.EnableAuth))
	
	return hecate.CreateRoute(rc, hecateConfig, route)
}