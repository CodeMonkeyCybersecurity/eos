// pkg/hecate/validation.go

package hecate

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ValidateRoute validates a route configuration
func ValidateRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route cannot be nil")
	}

	// Validate domain
	if err := validateDomain(route.Domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Validate upstream
	if err := validateUpstream(route.Upstream); err != nil {
		return fmt.Errorf("invalid upstream: %w", err)
	}

	// Validate auth policy if present
	if route.AuthPolicy != nil {
		if err := validateAuthPolicy(route.AuthPolicy); err != nil {
			return fmt.Errorf("invalid auth policy: %w", err)
		}
	}

	// Validate health check if present
	if route.HealthCheck != nil {
		if err := validateHealthCheck(route.HealthCheck); err != nil {
			return fmt.Errorf("invalid health check: %w", err)
		}
	}

	// Validate rate limit if present
	if route.RateLimit != nil {
		if err := validateRateLimit(route.RateLimit); err != nil {
			return fmt.Errorf("invalid rate limit: %w", err)
		}
	}

	// Validate TLS config if present
	if route.TLS != nil {
		if err := validateTLSConfig(route.TLS); err != nil {
			return fmt.Errorf("invalid TLS config: %w", err)
		}
	}

	return nil
}

// validateDomain validates a domain name
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Basic domain validation regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	// Check domain length
	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %d characters (max 253)", len(domain))
	}

	// Check for invalid characters
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain contains consecutive dots")
	}

	return nil
}

// validateUpstream validates an upstream configuration
func validateUpstream(upstream *Upstream) error {
	if upstream == nil {
		return fmt.Errorf("upstream cannot be nil")
	}

	if upstream.URL == "" {
		return fmt.Errorf("upstream URL cannot be empty")
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(upstream.URL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("upstream URL must use http or https scheme, got: %s", parsedURL.Scheme)
	}

	// Validate host
	if parsedURL.Host == "" {
		return fmt.Errorf("upstream URL must include host")
	}

	// Validate timeout
	if upstream.Timeout < 0 {
		return fmt.Errorf("upstream timeout cannot be negative")
	}

	// Validate connection limits
	if upstream.MaxIdleConns < 0 {
		return fmt.Errorf("max idle connections cannot be negative")
	}

	if upstream.MaxConnsPerHost < 0 {
		return fmt.Errorf("max connections per host cannot be negative")
	}

	// Validate keep alive
	if upstream.KeepAlive < 0 {
		return fmt.Errorf("keep alive duration cannot be negative")
	}

	return nil
}

// validateAuthPolicy validates an authentication policy
func validateAuthPolicy(policy *AuthPolicy) error {
	if policy == nil {
		return fmt.Errorf("auth policy cannot be nil")
	}

	if policy.Name == "" {
		return fmt.Errorf("auth policy name cannot be empty")
	}

	if policy.Provider == "" {
		return fmt.Errorf("auth policy provider cannot be empty")
	}

	// Validate provider type
	validProviders := []string{"authentik", "keycloak", "oauth2", "saml", "oidc"}
	isValidProvider := false
	for _, provider := range validProviders {
		if policy.Provider == provider {
			isValidProvider = true
			break
		}
	}
	if !isValidProvider {
		return fmt.Errorf("invalid auth provider: %s (valid: %s)", policy.Provider, strings.Join(validProviders, ", "))
	}

	// Validate session TTL
	if policy.SessionTTL < 0 {
		return fmt.Errorf("session TTL cannot be negative")
	}

	// Validate permissions
	for i, perm := range policy.Permissions {
		if err := validatePermission(&perm); err != nil {
			return fmt.Errorf("invalid permission at index %d: %w", i, err)
		}
	}

	return nil
}

// validatePermission validates a permission
func validatePermission(perm *Permission) error {
	if perm.Resource == "" {
		return fmt.Errorf("permission resource cannot be empty")
	}

	if len(perm.Actions) == 0 {
		return fmt.Errorf("permission must have at least one action")
	}

	// Validate actions
	validActions := []string{"read", "write", "create", "update", "delete", "list", "admin"}
	for _, action := range perm.Actions {
		isValidAction := false
		for _, validAction := range validActions {
			if action == validAction {
				isValidAction = true
				break
			}
		}
		if !isValidAction {
			return fmt.Errorf("invalid action: %s (valid: %s)", action, strings.Join(validActions, ", "))
		}
	}

	return nil
}

// validateHealthCheck validates a health check configuration
func validateHealthCheck(hc *HealthCheck) error {
	if hc == nil {
		return fmt.Errorf("health check cannot be nil")
	}

	if hc.Path == "" {
		return fmt.Errorf("health check path cannot be empty")
	}

	if !strings.HasPrefix(hc.Path, "/") {
		return fmt.Errorf("health check path must start with /")
	}

	if hc.Interval <= 0 {
		return fmt.Errorf("health check interval must be positive")
	}

	if hc.Timeout <= 0 {
		return fmt.Errorf("health check timeout must be positive")
	}

	if hc.Timeout >= hc.Interval {
		return fmt.Errorf("health check timeout must be less than interval")
	}

	if hc.FailureThreshold <= 0 {
		return fmt.Errorf("failure threshold must be positive")
	}

	if hc.SuccessThreshold <= 0 {
		return fmt.Errorf("success threshold must be positive")
	}

	// Validate HTTP method
	if hc.Method != "" {
		validMethods := []string{"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"}
		isValidMethod := false
		for _, method := range validMethods {
			if hc.Method == method {
				isValidMethod = true
				break
			}
		}
		if !isValidMethod {
			return fmt.Errorf("invalid HTTP method: %s (valid: %s)", hc.Method, strings.Join(validMethods, ", "))
		}
	}

	return nil
}

// validateRateLimit validates a rate limit configuration
func validateRateLimit(rl *RateLimit) error {
	if rl == nil {
		return fmt.Errorf("rate limit cannot be nil")
	}

	if rl.RequestsPerSecond <= 0 {
		return fmt.Errorf("requests per second must be positive")
	}

	if rl.BurstSize < 0 {
		return fmt.Errorf("burst size cannot be negative")
	}

	if rl.WindowSize <= 0 {
		return fmt.Errorf("window size must be positive")
	}

	// Validate key strategy
	if rl.KeyBy != "" {
		validKeys := []string{"ip", "header", "query", "cookie", "user"}
		isValidKey := false
		for _, key := range validKeys {
			if rl.KeyBy == key {
				isValidKey = true
				break
			}
		}
		if !isValidKey {
			return fmt.Errorf("invalid rate limit key: %s (valid: %s)", rl.KeyBy, strings.Join(validKeys, ", "))
		}
	}

	return nil
}

// validateTLSConfig validates a TLS configuration
func validateTLSConfig(tls *TLSConfig) error {
	if tls == nil {
		return fmt.Errorf("TLS config cannot be nil")
	}

	// Validate TLS versions
	if tls.MinVersion != "" {
		validVersions := []string{"1.0", "1.1", "1.2", "1.3"}
		isValidVersion := false
		for _, version := range validVersions {
			if tls.MinVersion == version {
				isValidVersion = true
				break
			}
		}
		if !isValidVersion {
			return fmt.Errorf("invalid min TLS version: %s (valid: %s)", tls.MinVersion, strings.Join(validVersions, ", "))
		}
	}

	if tls.MaxVersion != "" {
		validVersions := []string{"1.0", "1.1", "1.2", "1.3"}
		isValidVersion := false
		for _, version := range validVersions {
			if tls.MaxVersion == version {
				isValidVersion = true
				break
			}
		}
		if !isValidVersion {
			return fmt.Errorf("invalid max TLS version: %s (valid: %s)", tls.MaxVersion, strings.Join(validVersions, ", "))
		}
	}

	// Validate HSTS if present
	if tls.HSTS != nil {
		if err := validateHSTS(tls.HSTS); err != nil {
			return fmt.Errorf("invalid HSTS config: %w", err)
		}
	}

	return nil
}

// validateHSTS validates HSTS configuration
func validateHSTS(hsts *HSTS) error {
	if hsts.MaxAge < 0 {
		return fmt.Errorf("HSTS max age cannot be negative")
	}

	// Recommend minimum max age for security
	if hsts.MaxAge > 0 && hsts.MaxAge < 300 {
		return fmt.Errorf("HSTS max age should be at least 300 seconds (5 minutes)")
	}

	return nil
}

// ValidateRouteConfig validates the overall route configuration
func ValidateRouteConfig(config *HecateConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.Environment == "" {
		return fmt.Errorf("environment must be specified")
	}

	// Validate at least one backend endpoint is configured
	if config.CaddyAPIEndpoint == "" {
		return fmt.Errorf("at least one backend API endpoint must be configured")
	}

	// Validate backend endpoints if provided
	if config.CaddyAPIEndpoint != "" {
		if _, err := url.Parse(config.CaddyAPIEndpoint); err != nil {
			return fmt.Errorf("invalid Caddy API endpoint: %w", err)
		}
	}

	if config.AuthentikAPIEndpoint != "" {
		if _, err := url.Parse(config.AuthentikAPIEndpoint); err != nil {
			return fmt.Errorf("invalid Authentik API endpoint: %w", err)
		}
	}

	if config.KeycloakAPIEndpoint != "" {
		if _, err := url.Parse(config.KeycloakAPIEndpoint); err != nil {
			return fmt.Errorf("invalid Keycloak API endpoint: %w", err)
		}
	}

	// Validate state backend
	validBackends := []string{"file", "consul", "etcd", "vault"}
	isValidBackend := false
	for _, backend := range validBackends {
		if config.StateBackend == backend {
			isValidBackend = true
			break
		}
	}
	if !isValidBackend {
		return fmt.Errorf("invalid state backend: %s (valid: %s)", config.StateBackend, strings.Join(validBackends, ", "))
	}

	// Validate log level
	if config.LogLevel != "" {
		validLevels := []string{"debug", "info", "warn", "error"}
		isValidLevel := false
		for _, level := range validLevels {
			if config.LogLevel == level {
				isValidLevel = true
				break
			}
		}
		if !isValidLevel {
			return fmt.Errorf("invalid log level: %s (valid: %s)", config.LogLevel, strings.Join(validLevels, ", "))
		}
	}

	// Validate metrics interval
	if config.MetricsInterval < 0 {
		return fmt.Errorf("metrics interval cannot be negative")
	}

	// Validate backup config if present
	if config.Backup != nil {
		if err := validateBackupConfig(config.Backup); err != nil {
			return fmt.Errorf("invalid backup config: %w", err)
		}
	}

	return nil
}

// validateBackupConfig validates backup configuration
func validateBackupConfig(backup *BackupConfig) error {
	if backup.Directory == "" {
		return fmt.Errorf("backup directory cannot be empty")
	}

	if backup.Retention < 0 {
		return fmt.Errorf("backup retention cannot be negative")
	}

	// Validate cron schedule if provided
	if backup.Schedule != "" {
		// Basic cron validation - could be more comprehensive
		fields := strings.Fields(backup.Schedule)
		if len(fields) != 5 && len(fields) != 6 {
			return fmt.Errorf("invalid cron schedule format: %s", backup.Schedule)
		}
	}

	return nil
}