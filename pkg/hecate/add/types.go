// pkg/hecate/add/types.go

package add

import "time"

// ServiceOptions contains all options for adding a new service to Hecate
type ServiceOptions struct {
	// Required fields
	Service string // Service name (alphanumeric, hyphens, underscores)
	DNS     string // Domain/subdomain for this service
	Backend string // Backend address (ip:port or hostname:port)

	// Optional fields
	SSO                 bool     // Enable SSO for this route
	SSOProvider         string   // SSO provider to use (default: authentik)
	AdminGroup          string   // Admin group name for authorization (used by Moni, default varies by service)
	SAMLEntityID        string   // SAML entity ID (for SAML-based integrations like Wazuh)
	AllowInsecureTLS    bool     // Allow InsecureSkipVerify for TLS connections (INSECURE - use with caution)
	CustomDirectives    []string // Custom Caddy directives
	DryRun              bool     // Show changes without applying
	SkipDNSCheck        bool     // Skip DNS resolution validation
	SkipBackendCheck    bool     // Skip backend connectivity check
	BackupRetentionDays int      // Days to keep old backups (0 = keep forever)

	// Telemetry fields
	InvocationMethod string // How command was invoked: "flag" or "subcommand" (for UX metrics)

	// Internal state tracking
	UsedAdminAPI bool // Track if Admin API was used (for conditional reload logic)
}

// RouteConfig represents a Caddy route configuration
type RouteConfig struct {
	Service          string
	DNS              string
	Backend          string
	SSO              bool
	SSOProvider      string
	CustomDirectives []string
	LogFile          string
}

// BackupInfo represents a Caddyfile backup
type BackupInfo struct {
	Path      string
	Timestamp time.Time
	Size      int64
}

// ValidationResult contains the results of validation checks
type ValidationResult struct {
	Valid   bool
	Message string
	Details map[string]string
}

// HealthCheck represents a service health check result
type HealthCheckResult struct {
	Reachable bool
	Latency   time.Duration
	Error     string
	Details   map[string]interface{}
}

// endpointAttempt tracks individual HTTP validation attempts
// Used by Wazuh integrator for detailed error reporting
type endpointAttempt struct {
	URL        string // Endpoint URL attempted
	StatusCode int    // HTTP status code (0 if connection failed)
	Status     string // HTTP status text
	Error      string // Error message if connection failed
	Protocol   string // "HTTP" or "HTTPS"
}
