// pkg/hecate/add/validation.go

package add

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateInput validates all user inputs
func ValidateInput(rc *eos_io.RuntimeContext, opts *ServiceOptions) *ValidationResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := &ValidationResult{
		Valid:   true,
		Details: make(map[string]string),
	}

	// Validate service name
	if err := validateServiceName(opts.Service); err != nil {
		result.Valid = false
		result.Message = fmt.Sprintf("invalid service name: %v", err)
		result.Details["service"] = err.Error()
		return result
	}
	logger.Debug("Service name validated", zap.String("service", opts.Service))

	// Validate DNS
	if err := validateDNS(opts.DNS); err != nil {
		result.Valid = false
		result.Message = fmt.Sprintf("invalid DNS: %v", err)
		result.Details["dns"] = err.Error()
		return result
	}
	logger.Debug("DNS format validated", zap.String("dns", opts.DNS))

	// Validate backend
	if err := validateBackend(opts.Backend); err != nil {
		result.Valid = false
		result.Message = fmt.Sprintf("invalid backend: %v", err)
		result.Details["backend"] = err.Error()
		return result
	}
	logger.Debug("Backend format validated", zap.String("backend", opts.Backend))

	// Validate SSO provider if SSO is enabled
	if opts.SSO {
		if err := validateSSOProvider(opts.SSOProvider); err != nil {
			result.Valid = false
			result.Message = fmt.Sprintf("invalid SSO provider: %v", err)
			result.Details["sso_provider"] = err.Error()
			return result
		}
		logger.Debug("SSO provider validated", zap.String("provider", opts.SSOProvider))
	}

	result.Message = "all inputs are valid"
	return result
}

// validateServiceName validates the service name format
func validateServiceName(service string) error {
	if service == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	// Pattern: alphanumeric, hyphens, underscores only
	pattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !pattern.MatchString(service) {
		return fmt.Errorf("service name must contain only alphanumeric characters, hyphens, and underscores")
	}

	// Check length (reasonable limits)
	if len(service) < 2 {
		return fmt.Errorf("service name must be at least 2 characters")
	}
	if len(service) > 63 {
		return fmt.Errorf("service name must be less than 64 characters")
	}

	return nil
}

// validateDNS validates the DNS format
func validateDNS(dns string) error {
	if dns == "" {
		return fmt.Errorf("DNS cannot be empty")
	}

	// Basic hostname validation
	if len(dns) > 253 {
		return fmt.Errorf("DNS name too long (max 253 characters)")
	}

	// Pattern: valid domain name format
	pattern := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	if !pattern.MatchString(dns) {
		return fmt.Errorf("invalid DNS format (must be a valid domain name)")
	}

	// Each label must be <= 63 characters
	labels := strings.Split(dns, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("DNS label '%s' is too long (max 63 characters)", label)
		}
	}

	return nil
}

// validateBackend validates the backend address format
func validateBackend(backend string) error {
	if backend == "" {
		return fmt.Errorf("backend cannot be empty")
	}

	// Split host and port
	host, portStr, err := net.SplitHostPort(backend)
	if err != nil {
		return fmt.Errorf("invalid backend format (must be hostname:port or ip:port): %w", err)
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port number: %w", err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	// Validate host (can be IP or hostname)
	if ip := net.ParseIP(host); ip == nil {
		// Not an IP, validate as hostname
		if err := validateHostname(host); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}

	return nil
}

// validateHostname validates a hostname format
func validateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	// Allow localhost
	if hostname == "localhost" {
		return nil
	}

	// Basic hostname validation
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}

	pattern := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.?)+$`)
	if !pattern.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format")
	}

	return nil
}

// validateSSOProvider validates the SSO provider
func validateSSOProvider(provider string) error {
	validProviders := []string{"authentik", "keycloak", "authelia"}

	for _, valid := range validProviders {
		if provider == valid {
			return nil
		}
	}

	return fmt.Errorf("unsupported SSO provider: %s (supported: %s)",
		provider, strings.Join(validProviders, ", "))
}

// CheckDNSResolution checks if the DNS resolves to this server
func CheckDNSResolution(rc *eos_io.RuntimeContext, dns string) *HealthCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := &HealthCheckResult{
		Details: make(map[string]interface{}),
	}

	start := time.Now()

	// Resolve DNS
	ips, err := net.LookupIP(dns)
	if err != nil {
		result.Reachable = false
		result.Error = fmt.Sprintf("DNS resolution failed: %v", err)
		logger.Warn("DNS resolution failed",
			zap.String("dns", dns),
			zap.Error(err))
		return result
	}

	result.Latency = time.Since(start)
	result.Details["resolved_ips"] = ips

	// Get this server's IPs
	serverIPs, err := getServerIPs()
	if err != nil {
		result.Reachable = false
		result.Error = fmt.Sprintf("failed to get server IPs: %v", err)
		logger.Error("Failed to get server IPs", zap.Error(err))
		return result
	}

	// Check if DNS points to this server
	for _, resolvedIP := range ips {
		for _, serverIP := range serverIPs {
			if resolvedIP.Equal(serverIP) {
				result.Reachable = true
				result.Details["matched_ip"] = resolvedIP.String()
				logger.Info("DNS points to this server",
					zap.String("dns", dns),
					zap.String("ip", resolvedIP.String()))
				return result
			}
		}
	}

	result.Reachable = false
	result.Error = fmt.Sprintf("DNS does not point to this server (resolved to: %v, server IPs: %v)", ips, serverIPs)
	logger.Warn("DNS does not point to this server",
		zap.String("dns", dns),
		zap.Any("resolved_ips", ips),
		zap.Any("server_ips", serverIPs))

	return result
}

// CheckBackendConnectivity checks if the backend is reachable
func CheckBackendConnectivity(rc *eos_io.RuntimeContext, backend string) *HealthCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := &HealthCheckResult{
		Details: make(map[string]interface{}),
	}

	start := time.Now()

	// Parse backend
	host, port, err := net.SplitHostPort(backend)
	if err != nil {
		result.Reachable = false
		result.Error = fmt.Sprintf("invalid backend format: %v", err)
		return result
	}

	// Try to connect
	conn, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		result.Reachable = false
		result.Error = fmt.Sprintf("failed to connect: %v", err)
		result.Latency = time.Since(start)
		logger.Warn("Backend not reachable",
			zap.String("backend", backend),
			zap.Error(err))
		return result
	}
	defer conn.Close()

	result.Latency = time.Since(start)
	result.Reachable = true
	result.Details["host"] = host
	result.Details["port"] = port
	result.Details["latency_ms"] = result.Latency.Milliseconds()

	logger.Info("Backend is reachable",
		zap.String("backend", backend),
		zap.Duration("latency", result.Latency))

	// Try HTTP health check if possible
	httpResult := tryHTTPHealthCheck(backend)
	if httpResult != nil {
		result.Details["http_status"] = httpResult
	}

	return result
}

// tryHTTPHealthCheck attempts an HTTP GET to the backend
func tryHTTPHealthCheck(backend string) map[string]interface{} {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Try HTTP first
	resp, err := client.Get(fmt.Sprintf("http://%s/", backend))
	if err != nil {
		// Try HTTPS if HTTP fails
		resp, err = client.Get(fmt.Sprintf("https://%s/", backend))
		if err != nil {
			return nil
		}
	}
	defer resp.Body.Close()

	return map[string]interface{}{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
		"proto":       resp.Proto,
	}
}

// CheckHecateInstallation verifies Hecate is installed and running
func CheckHecateInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if /opt/hecate exists
	if _, err := os.Stat("/opt/hecate"); os.IsNotExist(err) {
		return fmt.Errorf("Hecate installation not found at /opt/hecate\n\n" +
			"Install Hecate first:\n" +
			"  sudo eos create hecate")
	}

	// Check if Caddyfile exists
	caddyfilePath := "/opt/hecate/Caddyfile"
	if _, err := os.Stat(caddyfilePath); os.IsNotExist(err) {
		return fmt.Errorf("Caddyfile not found at %s\n\n"+
			"Hecate installation may be incomplete. Reinstall with:\n"+
			"  sudo eos create hecate", caddyfilePath)
	}

	// Check if docker-compose.yml exists
	composeFile := "/opt/hecate/docker-compose.yml"
	if _, err := os.Stat(composeFile); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose.yml not found at %s\n\n"+
			"Hecate installation may be incomplete. Reinstall with:\n"+
			"  sudo eos create hecate", composeFile)
	}

	logger.Info("Hecate installation verified")
	return nil
}

// CheckAuthentikInstallation checks if Authentik is configured and accessible (for SSO)
// This uses the Authentik API SDK to verify the installation
func CheckAuthentikInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking Authentik installation")

	// Check if .env file exists (basic check)
	envFile := "/opt/hecate/.env"
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return fmt.Errorf("Authentik not configured (.env file not found)\n\n" +
			"Configure Authentik when creating Hecate:\n" +
			"  sudo eos create hecate")
	}

	// Read .env to get Authentik credentials
	content, err := os.ReadFile(envFile)
	if err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	envContent := string(content)

	// Check if Authentik variables exist
	if !strings.Contains(envContent, "AUTHENTIK") {
		return fmt.Errorf("Authentik not configured in Hecate installation\n\n" +
			"Authentik is required for SSO. Either:\n" +
			"  1. Reinstall Hecate with Authentik enabled\n" +
			"  2. Add service without --sso flag")
	}

	// Extract Authentik API token from .env
	// Format: AUTHENTIK_API_TOKEN=token_value
	var authentikToken string
	for _, line := range strings.Split(envContent, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AUTHENTIK_API_TOKEN=") {
			authentikToken = strings.TrimPrefix(line, "AUTHENTIK_API_TOKEN=")
			authentikToken = strings.Trim(authentikToken, "\"'") // Remove quotes
			break
		}
	}

	if authentikToken == "" {
		logger.Warn("AUTHENTIK_API_TOKEN not found in .env, skipping API health check")
		logger.Info("Authentik configuration file exists (basic check passed)")
		return nil
	}

	// Try to connect to Authentik API to verify it's actually running
	// Authentik typically runs on localhost when deployed with Hecate
	authentikURL := "http://localhost:9000" // Authentik default port in Hecate stack

	authentikClient, err := authentik.NewAuthentikClient(authentikURL, authentikToken)
	if err != nil {
		logger.Warn("Failed to create Authentik client",
			zap.Error(err))
		logger.Info("Authentik configuration file exists (basic check passed)")
		return nil
	}

	// Verify Authentik is actually responding
	if err := authentikClient.Health(); err != nil {
		logger.Warn("Authentik API health check failed",
			zap.Error(err),
			zap.String("url", authentikURL))
		logger.Warn("Authentik may not be running or accessible")
		logger.Warn("SSO routing will be added, but may not work until Authentik is started")
		return nil // Don't fail - allow adding route even if Authentik is temporarily down
	}

	// Get Authentik version to confirm it's working
	version, err := authentikClient.GetVersion()
	if err != nil {
		logger.Debug("Failed to get Authentik version", zap.Error(err))
	} else {
		logger.Info("Authentik installation verified",
			zap.String("version", version),
			zap.String("url", authentikURL))
	}

	return nil
}

// getServerIPs returns all non-loopback IPs of this server
func getServerIPs() ([]net.IP, error) {
	var ips []net.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip loopback addresses
			if ip != nil && !ip.IsLoopback() {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

// CheckDuplicateService checks if a service with this name or DNS already exists
func CheckDuplicateService(rc *eos_io.RuntimeContext, caddyfilePath, service, dns string) error {
	logger := otelzap.Ctx(rc.Ctx)

	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	contentStr := string(content)

	// Check for duplicate service name
	serviceComment := fmt.Sprintf("# Service: %s", service)
	if strings.Contains(contentStr, serviceComment) {
		return fmt.Errorf("service '%s' already exists in Caddyfile\n\n"+
			"To update existing service, use:\n"+
			"  eos update hecate --modify --service %s", service, service)
	}

	// Check for duplicate DNS
	dnsBlock := fmt.Sprintf("%s {", dns)
	if strings.Contains(contentStr, dnsBlock) {
		return fmt.Errorf("DNS '%s' already exists in Caddyfile\n\n"+
			"Each domain can only have one route. Check existing routes with:\n"+
			"  eos list hecate routes", dns)
	}

	logger.Info("No duplicate service or DNS found")
	return nil
}

// ValidateCustomDirectives validates custom Caddy directives
func ValidateCustomDirectives(directives []string) error {
	if len(directives) == 0 {
		return nil
	}

	// Basic validation - check for obviously dangerous directives
	dangerousPatterns := []string{
		"file_server",     // Could expose file system
		"php_fastcgi",     // Could execute code
		"exec",            // Could execute arbitrary commands
		"import",          // Could import malicious config
		"bind",            // Could bind to different interface
		"tls internal",    // Could break TLS setup
	}

	for _, directive := range directives {
		directiveLower := strings.ToLower(directive)

		// Check for dangerous patterns
		for _, pattern := range dangerousPatterns {
			if strings.Contains(directiveLower, pattern) {
				return fmt.Errorf("potentially dangerous directive detected: '%s'\n"+
					"Directive '%s' is not allowed for security reasons", directive, pattern)
			}
		}

		// Ensure directive doesn't try to open/close blocks
		if strings.Contains(directive, "{") || strings.Contains(directive, "}") {
			return fmt.Errorf("custom directives cannot contain braces: '%s'\n"+
				"Each directive should be a single line", directive)
		}
	}

	return nil
}
