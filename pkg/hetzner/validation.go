// pkg/hetzner/validation.go
//
// Input validation for Hetzner DNS operations.
// Implements fail-fast strategy: validate ALL inputs before making API calls.

package hetzner

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

var (
	// subdomainLabelRegex validates individual domain labels per RFC 1035/1123
	subdomainLabelRegex = regexp.MustCompile(SubdomainValidationPattern)
)

// ValidateIPAddress validates IPv4 or IPv6 address.
//
// Behavior:
//   - ASSESS: Parse IP using net.ParseIP
//   - EVALUATE: Check for invalid/loopback/link-local addresses
//
// Error Handling:
//   - Returns eos_err.NewUserError for invalid IP (user can fix)
//   - Returns error for loopback/link-local (not suitable for public DNS)
//
// Parameters:
//
//	ipString: IP address as string (e.g., "203.0.113.1" or "2001:db8::1")
//
// Returns:
//
//	net.IP: Parsed IP address
//	error: Non-nil if validation failed
func ValidateIPAddress(ipString string) (net.IP, error) {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, eos_err.NewUserError(
			"invalid IP address: %s\n"+
				"Expected valid IPv4 (e.g., 203.0.113.1) or IPv6 (e.g., 2001:db8::1)",
			ipString)
	}

	// Check for loopback (127.0.0.1, ::1)
	if ip.IsLoopback() {
		return nil, eos_err.NewUserError(
			"cannot use loopback IP address for public DNS: %s\n"+
				"Use a publicly routable IP address",
			ipString)
	}

	// Check for link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return nil, eos_err.NewUserError(
			"cannot use link-local IP address for public DNS: %s\n"+
				"Use a publicly routable IP address",
			ipString)
	}

	return ip, nil
}

// ValidateSubdomainName validates subdomain per RFC 1035 and RFC 1123.
//
// RFC 1035 Section 2.3.1: Preferred name syntax
//   - Labels: 1-63 chars, [a-z0-9-], no leading/trailing hyphens
//   - Total length: ≤253 chars
//
// RFC 1123 Section 2.1: Host Names
//   - Relaxes RFC 952, allows digits in first character
//
// Behavior:
//   - ASSESS: Check domain length
//   - ASSESS: Split into labels, validate each
//   - EVALUATE: Ensure all labels match pattern
//
// Error Handling:
//   - Returns eos_err.NewUserError with specific validation failure
//
// Parameters:
//
//	subdomain: Fully qualified domain name (e.g., "app.example.com")
//
// Returns:
//
//	error: Non-nil if validation failed
func ValidateSubdomainName(subdomain string) error {
	// Trim trailing dot if present (FQDN notation)
	subdomain = strings.TrimSuffix(subdomain, ".")

	// Check total length (RFC 1035 Section 2.3.4: 255 octets, minus length bytes = 253)
	if len(subdomain) > MaxDomainLength {
		return eos_err.NewUserError(
			"domain name too long: %d characters (max %d)\n"+
				"Domain: %s",
			len(subdomain), MaxDomainLength, subdomain)
	}

	if len(subdomain) == 0 {
		return eos_err.NewUserError("domain name cannot be empty")
	}

	// Split into labels and validate each
	labels := strings.Split(subdomain, ".")
	if len(labels) < 2 {
		return eos_err.NewUserError(
			"domain must have at least 2 labels (e.g., example.com): %s",
			subdomain)
	}

	for i, label := range labels {
		// Check label length (RFC 1035 Section 2.3.4: 63 octets)
		if len(label) == 0 {
			return eos_err.NewUserError(
				"domain label %d is empty in: %s",
				i+1, subdomain)
		}

		if len(label) > MaxSubdomainLabelLength {
			return eos_err.NewUserError(
				"domain label %d too long: %d characters (max %d)\n"+
					"Label: %q in %s",
				i+1, len(label), MaxSubdomainLabelLength, label, subdomain)
		}

		// Validate character set and format
		// Pattern: [a-z0-9]([a-z0-9-]*[a-z0-9])?
		// Note: DNS is case-insensitive, normalize to lowercase
		labelLower := strings.ToLower(label)
		if !subdomainLabelRegex.MatchString(labelLower) {
			// Provide specific guidance based on common mistakes
			var hint string
			if strings.Contains(label, "_") {
				hint = "Underscores (_) are not allowed in DNS names, use hyphens (-) instead"
			} else if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				hint = "Labels cannot start or end with hyphens"
			} else if !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(label) {
				hint = "Only letters, digits, and hyphens are allowed"
			} else {
				hint = "Label must match pattern: [a-z0-9]([a-z0-9-]*[a-z0-9])?"
			}

			return eos_err.NewUserError(
				"invalid domain label %d: %q in %s\n"+
					"%s",
				i+1, label, subdomain, hint)
		}
	}

	return nil
}

// ExtractZoneName extracts the root zone from a fully qualified domain name.
//
// Examples:
//   - "app.example.com" → "example.com"
//   - "example.com"     → "example.com"
//   - "sub.app.example.com" → "example.com"
//
// Behavior:
//   - ASSESS: Split domain into labels
//   - EVALUATE: Return last 2 labels as zone name
//
// Parameters:
//
//	domain: Fully qualified domain name
//
// Returns:
//
//	string: Root zone name (e.g., "example.com")
func ExtractZoneName(domain string) string {
	// Trim trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	// Return last two labels (e.g., "example.com" from "app.example.com")
	return strings.Join(parts[len(parts)-2:], ".")
}

// ExtractSubdomainLabel extracts the subdomain label from a FQDN relative to its zone.
//
// Examples:
//   - domain="app.example.com", zone="example.com" → "app"
//   - domain="sub.app.example.com", zone="example.com" → "sub.app"
//   - domain="example.com", zone="example.com" → "@" (zone apex)
//
// Behavior:
//   - ASSESS: Check if domain ends with zone
//   - EVALUATE: Return subdomain prefix or "@" for apex
//
// Parameters:
//
//	domain: Fully qualified domain name (e.g., "app.example.com")
//	zone: Zone name (e.g., "example.com")
//
// Returns:
//
//	string: Subdomain label or "@" for zone apex
//	error: Non-nil if domain doesn't belong to zone
func ExtractSubdomainLabel(domain, zone string) (string, error) {
	// Normalize: remove trailing dots
	domain = strings.TrimSuffix(domain, ".")
	zone = strings.TrimSuffix(zone, ".")

	// Special case: domain == zone (zone apex)
	if domain == zone {
		return "@", nil
	}

	// Check if domain ends with zone
	expectedSuffix := "." + zone
	if !strings.HasSuffix(domain, expectedSuffix) {
		return "", fmt.Errorf(
			"domain %q does not belong to zone %q",
			domain, zone)
	}

	// Extract subdomain prefix
	subdomain := strings.TrimSuffix(domain, expectedSuffix)
	if subdomain == "" {
		return "@", nil
	}

	return subdomain, nil
}

// ValidateRecordType validates DNS record type.
//
// Behavior:
//   - ASSESS: Check if recordType matches known types
//   - EVALUATE: Return error if unknown
//
// Parameters:
//
//	recordType: DNS record type (e.g., "A", "AAAA", "CNAME")
//
// Returns:
//
//	error: Non-nil if validation failed
func ValidateRecordType(recordType RecordType) error {
	validTypes := map[RecordType]bool{
		RecordTypeA:     true,
		RecordTypeAAAA:  true,
		RecordTypeCNAME: true,
		RecordTypeMX:    true,
		RecordTypeTXT:   true,
		RecordTypeNS:    true,
		RecordTypeSRV:   true,
		RecordTypeCAA:   true,
	}

	if !validTypes[recordType] {
		return eos_err.NewUserError(
			"invalid DNS record type: %q\n"+
				"Valid types: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA",
			recordType)
	}

	return nil
}
