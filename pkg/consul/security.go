// pkg/consul/security.go

package consul

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityValidator handles security validation for Consul configurations
type SecurityValidator struct{}

// ValidationResult represents the result of a security validation
type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
	Score    int      `json:"security_score"` // 0-100
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{}
}

// ValidateConfig performs comprehensive security validation on Consul configuration
func (sv *SecurityValidator) ValidateConfig(rc *eos_io.RuntimeContext, config *EnhancedConfig) *ValidationResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing security validation on Consul configuration")

	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		Score:    100,
	}

	// Validate address security
	sv.validateAddress(config.Address, result)

	// Validate TLS configuration
	sv.validateTLS(config.TLSConfig, result)

	// Validate ACL configuration
	sv.validateACL(config.ACLConfig, result)

	// Validate security settings
	sv.validateSecurityConfig(config.SecurityConfig, result)

	// Validate token security
	sv.validateToken(config.Token, result)

	// Validate monitoring security
	sv.validateMonitoring(config.MonitoringConfig, result)

	// Set overall validity
	result.Valid = len(result.Errors) == 0

	logger.Info("Security validation completed",
		zap.Bool("valid", result.Valid),
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)),
		zap.Int("security_score", result.Score))

	return result
}

// validateAddress checks if the address configuration is secure
func (sv *SecurityValidator) validateAddress(address string, result *ValidationResult) {
	if address == "" {
		result.Errors = append(result.Errors, "Address cannot be empty")
		result.Score -= 20
		return
	}

	// Check for wildcard binding (security risk)
	if strings.Contains(address, "0.0.0.0") {
		result.Warnings = append(result.Warnings, "Binding to 0.0.0.0 exposes service to all interfaces - consider restricting to specific IPs")
		result.Score -= 10
	}

	// Validate port
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid address format: %s", err))
		result.Score -= 15
		return
	}

	// Check for default Consul port (potential security issue)
	if port == "8500" || port == strconv.Itoa(shared.PortConsul) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Using default Consul port %s - consider using a custom port for security", port))
		result.Score -= 5
	}

	// Validate IP address
	if ip := net.ParseIP(host); ip == nil {
		// Could be a hostname - validate it's not localhost variants
		if host == "localhost" || host == shared.GetInternalHostname() {
			result.Warnings = append(result.Warnings, "Localhost binding may not be suitable for production environments")
			result.Score -= 5
		}
	}
}

// validateTLS checks TLS configuration security
func (sv *SecurityValidator) validateTLS(tlsConfig *TLSConfig, result *ValidationResult) {
	if tlsConfig == nil {
		result.Errors = append(result.Errors, "TLS configuration is required for production deployments")
		result.Score -= 30
		return
	}

	if !tlsConfig.Enabled {
		result.Errors = append(result.Errors, "TLS must be enabled for secure communications")
		result.Score -= 30
		return
	}

	// Check certificate files
	if tlsConfig.CertFile == "" {
		result.Errors = append(result.Errors, "TLS certificate file path is required")
		result.Score -= 10
	}

	if tlsConfig.KeyFile == "" {
		result.Errors = append(result.Errors, "TLS private key file path is required")
		result.Score -= 10
	}

	if tlsConfig.CAFile == "" {
		result.Warnings = append(result.Warnings, "CA file not specified - consider using a custom CA for better security")
		result.Score -= 5
	}

	// Check verification settings
	if !tlsConfig.VerifyIncoming {
		result.Warnings = append(result.Warnings, "TLS incoming verification disabled - this reduces security")
		result.Score -= 10
	}

	if !tlsConfig.VerifyOutgoing {
		result.Warnings = append(result.Warnings, "TLS outgoing verification disabled - this reduces security")
		result.Score -= 10
	}
}

// validateACL checks ACL configuration security
func (sv *SecurityValidator) validateACL(aclConfig *ACLConfig, result *ValidationResult) {
	if aclConfig == nil {
		result.Errors = append(result.Errors, "ACL configuration is required for production security")
		result.Score -= 25
		return
	}

	if !aclConfig.Enabled {
		result.Errors = append(result.Errors, "ACLs must be enabled for secure access control")
		result.Score -= 25
		return
	}

	// Check default policy
	if aclConfig.DefaultPolicy == "allow" {
		result.Errors = append(result.Errors, "ACL default policy should be 'deny' for zero-trust security")
		result.Score -= 15
	}

	if !aclConfig.TokenPersist {
		result.Warnings = append(result.Warnings, "Token persistence disabled - tokens may be lost on restart")
		result.Score -= 5
	}
}

// validateSecurityConfig checks security-specific settings
func (sv *SecurityValidator) validateSecurityConfig(secConfig *SecurityConfig, result *ValidationResult) {
	if secConfig == nil {
		result.Warnings = append(result.Warnings, "Security configuration not specified - using defaults")
		result.Score -= 10
		return
	}

	if !secConfig.EncryptionEnabled {
		result.Errors = append(result.Errors, "Gossip encryption must be enabled for secure cluster communication")
		result.Score -= 20
	}

	if !secConfig.DenyByDefault {
		result.Warnings = append(result.Warnings, "Consider enabling deny-by-default for better security posture")
		result.Score -= 5
	}

	// Validate CIDR blocks
	for _, cidr := range secConfig.AllowedCIDRs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid CIDR block: %s", cidr))
			result.Score -= 5
		}

		// Check for overly permissive CIDRs
		if cidr == "0.0.0.0/0" {
			result.Errors = append(result.Errors, "Allowing all IP addresses (0.0.0.0/0) is a major security risk")
			result.Score -= 25
		}
	}
}

// validateToken checks token security
func (sv *SecurityValidator) validateToken(token string, result *ValidationResult) {
	if token == "" {
		result.Warnings = append(result.Warnings, "No token specified - ensure proper authentication is configured")
		return
	}

	// Check token format (UUIDs are typically used)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(token) {
		result.Warnings = append(result.Warnings, "Token does not appear to be in UUID format - ensure it's properly generated")
		result.Score -= 5
	}

	// Check for weak tokens
	if len(token) < 16 {
		result.Errors = append(result.Errors, "Token is too short - use strong, randomly generated tokens")
		result.Score -= 15
	}

	// Check for common weak tokens
	weakTokens := []string{"password", "admin", "root", "consul", "secret"}
	tokenLower := strings.ToLower(token)
	for _, weak := range weakTokens {
		if strings.Contains(tokenLower, weak) {
			result.Errors = append(result.Errors, "Token contains common words - use cryptographically secure random tokens")
			result.Score -= 20
			break
		}
	}
}

// validateMonitoring checks monitoring configuration security
func (sv *SecurityValidator) validateMonitoring(monConfig *MonitoringConfig, result *ValidationResult) {
	if monConfig == nil {
		result.Warnings = append(result.Warnings, "Monitoring configuration not specified")
		return
	}

	// Check webhook URL security
	if monConfig.AlertingWebhook != "" {
		if strings.HasPrefix(monConfig.AlertingWebhook, "http://") {
			result.Warnings = append(result.Warnings, "Alerting webhook uses HTTP instead of HTTPS - sensitive data may be exposed")
			result.Score -= 10
		}

		if !strings.HasPrefix(monConfig.AlertingWebhook, "https://") && !strings.HasPrefix(monConfig.AlertingWebhook, "http://") {
			result.Errors = append(result.Errors, "Invalid webhook URL format")
			result.Score -= 5
		}
	}
}

// ValidateService performs security validation on service registration
func (sv *SecurityValidator) ValidateService(rc *eos_io.RuntimeContext, service AdvancedService) *ValidationResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating service security",
		zap.String("service", service.Name))

	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{},
		Score:    100,
	}

	// Validate service name
	if service.Name == "" {
		result.Errors = append(result.Errors, "Service name cannot be empty")
		result.Score -= 20
	}

	// Check for insecure service names
	if strings.Contains(strings.ToLower(service.Name), "test") {
		result.Warnings = append(result.Warnings, "Service name contains 'test' - ensure this is not a production service")
		result.Score -= 5
	}

	// Validate health checks
	sv.validateHealthChecks(service.HealthChecks, result)

	// Validate Connect configuration
	sv.validateConnect(service.ConnectConfig, result)

	// Validate metadata
	sv.validateMetadata(service.Meta, result)

	result.Valid = len(result.Errors) == 0

	logger.Info("Service security validation completed",
		zap.String("service", service.Name),
		zap.Bool("valid", result.Valid),
		zap.Int("security_score", result.Score))

	return result
}

// validateHealthChecks checks health check security
func (sv *SecurityValidator) validateHealthChecks(checks []AdvancedHealthCheck, result *ValidationResult) {
	if len(checks) == 0 {
		result.Warnings = append(result.Warnings, "No health checks configured - service health cannot be monitored")
		result.Score -= 10
		return
	}

	for _, check := range checks {
		// Check for insecure HTTP health checks
		if check.Type == "http" && strings.HasPrefix(check.Target, "http://") {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Health check '%s' uses HTTP - consider HTTPS for security", check.Name))
			result.Score -= 5
		}

		// Check for overly permissive TLS settings
		if check.TLSSkipVerify {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Health check '%s' skips TLS verification - this reduces security", check.Name))
			result.Score -= 5
		}

		// Validate script checks for security
		if check.Type == "script" {
			if strings.Contains(check.Target, "rm ") || strings.Contains(check.Target, "sudo ") {
				result.Errors = append(result.Errors, fmt.Sprintf("Health check script '%s' contains potentially dangerous commands", check.Name))
				result.Score -= 15
			}
		}
	}
}

// validateConnect checks Connect/service mesh security
func (sv *SecurityValidator) validateConnect(connectConfig *ConnectConfiguration, result *ValidationResult) {
	if connectConfig == nil {
		result.Warnings = append(result.Warnings, "Service mesh (Connect) not configured - consider enabling for mTLS")
		result.Score -= 5
		return
	}

	// Validate upstream configurations
	if connectConfig.SidecarService != nil && connectConfig.SidecarService.Proxy != nil {
		for _, upstream := range connectConfig.SidecarService.Proxy.Upstreams {
			if upstream.DestinationName == "" {
				result.Errors = append(result.Errors, "Upstream destination name cannot be empty")
				result.Score -= 10
			}
		}
	}
}

// validateMetadata checks service metadata for sensitive information
func (sv *SecurityValidator) validateMetadata(meta map[string]string, result *ValidationResult) {
	sensitiveKeys := []string{"password", "secret", "key", "token", "credential"}

	for key, value := range meta {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(value)

		// Check for sensitive information in metadata
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(keyLower, sensitive) || strings.Contains(valueLower, sensitive) {
				result.Errors = append(result.Errors, fmt.Sprintf("Metadata may contain sensitive information: %s", key))
				result.Score -= 15
				break
			}
		}
	}
}
