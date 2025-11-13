// pkg/hecate/dns_validation.go

package hecate

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hetzner"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DNSValidationResult holds the results of DNS validation for a single domain
type DNSValidationResult struct {
	Domain      string
	HasARecord  bool
	ResolvedIPs []string
	IsValid     bool
	Message     string
}

// ValidateDNSRecords checks if DNS A records exist for all configured domains
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Query DNS for each domain
// - Intervene: Check against local IP or Hetzner API
// - Evaluate: Return validation results
func ValidateDNSRecords(rc *eos_io.RuntimeContext, config *YAMLHecateConfig) ([]DNSValidationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating DNS records for Hecate deployment",
		zap.Int("domain_count", len(config.Apps)))

	results := make([]DNSValidationResult, 0, len(config.Apps))

	// Get local IP address for comparison
	localIP, err := getLocalIP()
	if err != nil {
		logger.Warn("Could not determine local IP, skipping IP comparison",
			zap.Error(err))
	}

	for appName, app := range config.Apps {
		result := DNSValidationResult{
			Domain: app.Domain,
		}

		logger.Debug("Checking DNS for domain",
			zap.String("app", appName),
			zap.String("domain", app.Domain))

		// Resolve A records via standard DNS lookup
		ips, err := net.LookupIP(app.Domain)
		if err != nil {
			result.IsValid = false
			result.Message = fmt.Sprintf("DNS lookup failed: %v", err)
			logger.Warn("DNS lookup failed",
				zap.String("domain", app.Domain),
				zap.Error(err))
			results = append(results, result)
			continue
		}

		// Filter to IPv4 addresses
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				result.ResolvedIPs = append(result.ResolvedIPs, ipv4.String())
			}
		}

		if len(result.ResolvedIPs) > 0 {
			result.HasARecord = true

			// Check if resolved IP matches local IP
			if localIP != "" {
				matchesLocal := false
				for _, resolvedIP := range result.ResolvedIPs {
					if resolvedIP == localIP {
						matchesLocal = true
						break
					}
				}

				if matchesLocal {
					result.IsValid = true
					result.Message = fmt.Sprintf("✓ Points to this server (%s)", localIP)
				} else {
					result.IsValid = false
					result.Message = fmt.Sprintf("  Points to %s (this server is %s)",
						strings.Join(result.ResolvedIPs, ", "), localIP)
				}
			} else {
				// Can't determine local IP, just confirm A record exists
				result.IsValid = true
				result.Message = fmt.Sprintf("✓ A record exists (%s)",
					strings.Join(result.ResolvedIPs, ", "))
			}
		} else {
			result.HasARecord = false
			result.IsValid = false
			result.Message = "❌ No A record found"
		}

		logger.Info("DNS validation result",
			zap.String("domain", app.Domain),
			zap.Bool("valid", result.IsValid),
			zap.Strings("resolved_ips", result.ResolvedIPs))

		results = append(results, result)
	}

	return results, nil
}

// ValidateDNSWithHetzner validates DNS records using Hetzner DNS API
// This is optional and only used if HETZNER_DNS_TOKEN is set
func ValidateDNSWithHetzner(rc *eos_io.RuntimeContext, config *YAMLHecateConfig) ([]DNSValidationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Hetzner DNS token is available
	token := os.Getenv("HETZNER_DNS_TOKEN")
	if token == "" {
		logger.Debug("HETZNER_DNS_TOKEN not set, skipping Hetzner DNS validation")
		// Fallback to standard DNS validation
		return ValidateDNSRecords(rc, config)
	}

	logger.Info("Validating DNS records via Hetzner DNS API")

	// Initialize Hetzner DNS client
	// Get the underlying *zap.Logger from LoggerWithCtx
	zapLogger := logger.Logger().Logger
	dnsClient := hetzner.NewClient(token, zapLogger)

	results := make([]DNSValidationResult, 0, len(config.Apps))

	for appName, app := range config.Apps {
		result := DNSValidationResult{
			Domain: app.Domain,
		}

		// Extract zone from domain (e.g., "example.com" from "app.example.com")
		zoneName := extractZoneName(app.Domain)

		logger.Debug("Looking up zone in Hetzner DNS",
			zap.String("app", appName),
			zap.String("domain", app.Domain),
			zap.String("zone", zoneName))

		// Get all zones from Hetzner and filter by name
		allZones, err := dnsClient.GetZones(rc)
		if err != nil {
			// Zone not found in Hetzner, fallback to standard lookup
			logger.Debug("Failed to get zones from Hetzner DNS, using standard lookup",
				zap.Error(err))

			standardResult, err := ValidateDNSRecords(rc, &YAMLHecateConfig{
				Apps: map[string]AppConfig{appName: app},
			})
			if err == nil && len(standardResult) > 0 {
				results = append(results, standardResult[0])
			}
			continue
		}

		// Filter zones by name
		var zones []hetzner.DNSZone
		for _, zone := range allZones {
			if zone.Name == zoneName {
				zones = append(zones, zone)
			}
		}

		if len(zones) == 0 {
			// Zone not found in Hetzner, fallback to standard lookup
			logger.Debug("Zone not found in Hetzner DNS, using standard lookup",
				zap.String("zone", zoneName))

			standardResult, err := ValidateDNSRecords(rc, &YAMLHecateConfig{
				Apps: map[string]AppConfig{appName: app},
			})
			if err == nil && len(standardResult) > 0 {
				results = append(results, standardResult[0])
			}
			continue
		}

		zoneID := zones[0].ID

		// Get records for this zone
		records, err := dnsClient.GetRecords(rc, zoneID)
		if err != nil {
			result.IsValid = false
			result.Message = fmt.Sprintf("Failed to get records: %v", err)
			results = append(results, result)
			continue
		}

		// Find A record for this domain
		found := false
		for _, record := range records {
			if record.Type == "A" && matchesDomain(record.Name, app.Domain, zoneName) {
				found = true
				result.HasARecord = true
				result.ResolvedIPs = append(result.ResolvedIPs, record.Value)
			}
		}

		if found {
			result.IsValid = true
			result.Message = fmt.Sprintf("✓ Found in Hetzner DNS (%s)",
				strings.Join(result.ResolvedIPs, ", "))
		} else {
			result.IsValid = false
			result.Message = "❌ Not found in Hetzner DNS"
		}

		results = append(results, result)
	}

	return results, nil
}

// getLocalIP attempts to determine the primary local IP address
func getLocalIP() (string, error) {
	// Try to get local IP by dialing (doesn't actually connect)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// extractZoneName extracts the root zone from a domain
// e.g., "app.example.com" -> "example.com"
// e.g., "example.com" -> "example.com"
func extractZoneName(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	// Return last two parts
	return strings.Join(parts[len(parts)-2:], ".")
}

// matchesDomain checks if a DNS record name matches the target domain
func matchesDomain(recordName, targetDomain, zoneName string) bool {
	// Handle different record name formats:
	// - "@" means the zone itself
	// - "subdomain" means subdomain.zone
	// - "" or "." also means the zone itself

	if recordName == "@" || recordName == "" || recordName == "." {
		return targetDomain == zoneName
	}

	// Construct full domain from record name
	fullDomain := recordName + "." + zoneName
	return fullDomain == targetDomain
}
