// pkg/hetzner/subdomain.go
//
// Core subdomain management for Hetzner DNS.
// Implements idempotent subdomain creation, DNS propagation verification,
// and multi-nameserver validation to prevent false positives.

package hetzner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ProgressCallback is called during long-running operations to provide user feedback.
//
// Parameters:
//
//	message: Human-readable progress message
//	remaining: Time remaining until timeout
//	attempt: Current attempt number (1-indexed)
type ProgressCallback func(message string, remaining time.Duration, attempt int)

// CheckSubdomainExists checks if an A record exists for the subdomain in Hetzner DNS.
//
// Behavior:
//   - ASSESS: Validate subdomain name per RFC 1035/1123
//   - ASSESS: Get zone ID for domain
//   - ASSESS: Query all DNS records for the zone
//   - EVALUATE: Filter for matching A record
//
// Error Handling:
//   - Returns eos_err.NewUserError for invalid subdomain name (user can fix)
//   - Returns error for API failures (network, auth, etc.)
//   - Returns (false, nil, nil) if subdomain doesn't exist (not an error)
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	token: Hetzner DNS API token wrapped in SecureString
//	domain: Fully qualified domain name (e.g., "app.example.com")
//
// Returns:
//
//	bool: True if subdomain exists
//	*DNSRecord: The existing DNS record (nil if doesn't exist)
//	error: Non-nil if operation failed
func CheckSubdomainExists(rc *eos_io.RuntimeContext, token *crypto.SecureString, domain string) (bool, *DNSRecord, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate inputs
	if err := ValidateSubdomainName(domain); err != nil {
		return false, nil, err // Already wrapped as UserError by ValidateSubdomainName
	}

	// ASSESS: Get zone ID
	zoneName := ExtractZoneName(domain)
	zoneID, err := GetZoneIDForDomain(rc, token.Value(), zoneName)
	if err != nil {
		return false, nil, fmt.Errorf("zone lookup failed for %s: %w", zoneName, err)
	}

	// ASSESS: Get all records for zone
	client := NewClient(token.Value(), logger.Logger().Logger)
	records, err := client.GetRecords(rc, zoneID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get DNS records for zone %s: %w", zoneName, err)
	}

	// ASSESS: Extract subdomain label (e.g., "app" from "app.example.com" with zone "example.com")
	subdomainLabel, err := ExtractSubdomainLabel(domain, zoneName)
	if err != nil {
		return false, nil, fmt.Errorf("failed to extract subdomain label: %w", err)
	}

	// EVALUATE: Filter for matching A record
	for _, record := range records {
		if record.Type == string(RecordTypeA) && record.Name == subdomainLabel {
			logger.Debug("Subdomain exists",
				zap.String("domain", domain),
				zap.String("record_id", record.ID),
				zap.String("ip", record.Value))
			return true, &record, nil
		}
	}

	logger.Debug("Subdomain does not exist",
		zap.String("domain", domain),
		zap.String("zone", zoneName))
	return false, nil, nil
}

// CreateSubdomainIfMissing creates an A record for the subdomain if it doesn't exist.
//
// This function is IDEMPOTENT: If the subdomain already exists, it returns the
// existing record without modification.
//
// Behavior:
//   - ASSESS: Validate subdomain name and IP address
//   - ASSESS: Check if subdomain already exists
//   - INTERVENE: Create A record if missing (skip if exists)
//   - EVALUATE: Verify creation succeeded
//
// Partial Failure Policy:
//
//	If subdomain is created but verification fails, the subdomain REMAINS in Hetzner DNS.
//	This is acceptable because:
//	- Next call will be idempotent and skip creation
//	- Subdomain is usable even if verification fails
//	- Manual cleanup available via DeleteSubdomainOnFailure()
//
// Error Handling:
//   - Returns eos_err.NewUserError for validation failures (user can fix)
//   - Returns error for API failures (network, auth, rate limit)
//   - Returns existing record if subdomain already exists (idempotent)
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	token: Hetzner DNS API token wrapped in SecureString
//	domain: Fully qualified domain name (e.g., "app.example.com")
//	ipAddress: IPv4 or IPv6 address for A/AAAA record
//
// Returns:
//
//	*DNSRecord: Created or existing DNS record
//	error: Non-nil if operation failed
func CreateSubdomainIfMissing(
	rc *eos_io.RuntimeContext,
	token *crypto.SecureString,
	domain string,
	ipAddress net.IP,
) (*DNSRecord, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate inputs
	if err := ValidateSubdomainName(domain); err != nil {
		return nil, err // Already wrapped as UserError
	}

	if ipAddress == nil {
		return nil, eos_err.NewUserError("IP address cannot be nil")
	}

	// ASSESS: Check if subdomain already exists (idempotency)
	exists, record, err := CheckSubdomainExists(rc, token, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to check subdomain existence: %w", err)
	}

	if exists {
		logger.Info("Subdomain already exists (idempotent skip)",
			zap.String("domain", domain),
			zap.String("ip", record.Value),
			zap.String("record_id", record.ID))
		return record, nil
	}

	// INTERVENE: Create A record
	logger.Info("Creating subdomain A record",
		zap.String("domain", domain),
		zap.String("ip", ipAddress.String()))

	zoneName := ExtractZoneName(domain)
	zoneID, err := GetZoneIDForDomain(rc, token.Value(), zoneName)
	if err != nil {
		return nil, fmt.Errorf("zone lookup failed: %w", err)
	}

	subdomainLabel, err := ExtractSubdomainLabel(domain, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract subdomain label: %w", err)
	}

	// Create the DNS record via Hetzner API
	if err := CreateRecord(rc, token.Value(), zoneID, subdomainLabel, ipAddress.String()); err != nil {
		return nil, fmt.Errorf("failed to create DNS record: %w", err)
	}

	// EVALUATE: Verify creation succeeded
	logger.Debug("Verifying subdomain creation")
	exists, record, err = CheckSubdomainExists(rc, token, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to verify subdomain creation: %w", err)
	}

	if !exists {
		return nil, fmt.Errorf(
			"subdomain created but not found in subsequent check (API inconsistency)\n"+
				"Domain: %s\nThis may be a temporary API delay. Try again in a few seconds.",
			domain)
	}

	logger.Info("Subdomain created successfully",
		zap.String("domain", domain),
		zap.String("record_id", record.ID),
		zap.String("ip", record.Value))

	return record, nil
}

// VerifySubdomainPropagated waits for DNS propagation with multi-nameserver verification.
//
// Strategy:
//   - Query multiple public DNS servers (system, Google, Cloudflare, OpenDNS)
//   - Require ≥3 nameservers to agree on the IP address
//   - Use exponential backoff: 5s → 10s → 20s → 30s (max)
//   - Timeout after specified duration (default: 60 seconds)
//
// Multi-Nameserver Rationale:
//   - Prevents false positives from cached/stale responses
//   - System DNS may have different TTL than public servers
//   - Global consistency check (important for geo-distributed deployments)
//
// Behavior:
//   - ASSESS: Query system DNS and 3 public DNS servers
//   - EVALUATE: Count how many nameservers agree on expected IP
//   - INTERVENE: Call progress callback for user feedback
//   - INTERVENE: Wait with exponential backoff between attempts
//
// Progress Indication:
//
//	If onProgress callback is provided, it's called on each attempt:
//	  message: "Checking DNS (attempt N)"
//	  remaining: Time until timeout
//	  attempt: Current attempt number
//
// Error Handling:
//   - Returns error if timeout exceeded before propagation
//   - Individual nameserver failures are logged but non-fatal
//   - Requires ≥3 nameservers to succeed (DNSPropagationMinAgreement)
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	domain: Fully qualified domain name to verify
//	expectedIP: Expected IP address for the domain
//	timeout: Maximum time to wait for propagation
//	onProgress: Optional callback for progress updates (nil = no updates)
//
// Returns:
//
//	error: Non-nil if propagation failed or timeout exceeded
func VerifySubdomainPropagated(
	rc *eos_io.RuntimeContext,
	domain string,
	expectedIP net.IP,
	timeout time.Duration,
	onProgress ProgressCallback,
) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Waiting for DNS propagation",
		zap.String("domain", domain),
		zap.String("expected_ip", expectedIP.String()),
		zap.Duration("timeout", timeout))

	startTime := time.Now()
	attempt := 0
	backoff := DNSPropagationPollInterval

	for {
		attempt++
		elapsed := time.Since(startTime)
		remaining := timeout - elapsed

		// Check timeout
		if remaining <= 0 {
			return fmt.Errorf(
				"DNS propagation timeout after %v for domain %s\n"+
					"Expected IP: %s\n"+
					"Remediation: Check DNS configuration at https://dns.hetzner.com",
				timeout, domain, expectedIP.String())
		}

		// Progress indication
		if onProgress != nil {
			onProgress(
				fmt.Sprintf("Checking DNS (attempt %d)", attempt),
				remaining,
				attempt)
		}

		// Query multiple nameservers
		agreementCount := 0
		nameserverResults := make(map[string]bool)

		// 1. System DNS
		if systemIP := querySystemDNS(rc, domain); systemIP != nil && systemIP.Equal(expectedIP) {
			agreementCount++
			nameserverResults["system"] = true
			logger.Debug("System DNS agrees",
				zap.String("domain", domain),
				zap.String("ip", systemIP.String()))
		}

		// 2. Public DNS servers
		for _, dnsServer := range PublicDNSServers {
			if resolvedIP := querySpecificDNS(rc, domain, dnsServer); resolvedIP != nil && resolvedIP.Equal(expectedIP) {
				agreementCount++
				nameserverResults[dnsServer] = true
				logger.Debug("Public DNS server agrees",
					zap.String("server", dnsServer),
					zap.String("domain", domain),
					zap.String("ip", resolvedIP.String()))
			}
		}

		logger.Debug("DNS verification attempt",
			zap.Int("attempt", attempt),
			zap.Int("agreement_count", agreementCount),
			zap.Int("required", DNSPropagationMinAgreement),
			zap.Duration("elapsed", elapsed))

		// Success when ≥3 nameservers agree
		if agreementCount >= DNSPropagationMinAgreement {
			logger.Info("DNS propagated successfully",
				zap.String("domain", domain),
				zap.Duration("elapsed", elapsed),
				zap.Int("nameservers_agreeing", agreementCount))
			return nil
		}

		// Exponential backoff: 5s → 10s → 20s → 30s (max)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > RateLimitMaxBackoff {
			backoff = RateLimitMaxBackoff
		}
	}
}

// querySystemDNS queries the system's default DNS resolver.
func querySystemDNS(rc *eos_io.RuntimeContext, domain string) net.IP {
	logger := otelzap.Ctx(rc.Ctx)

	ips, err := net.LookupIP(domain)
	if err != nil {
		logger.Debug("System DNS lookup failed",
			zap.String("domain", domain),
			zap.Error(err))
		return nil
	}

	if len(ips) == 0 {
		return nil
	}

	// Return first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}

	return nil
}

// querySpecificDNS queries a specific DNS server.
func querySpecificDNS(rc *eos_io.RuntimeContext, domain, dnsServer string) net.IP {
	logger := otelzap.Ctx(rc.Ctx)

	// Create custom resolver with specific DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	ips, err := resolver.LookupIP(rc.Ctx, "ip4", domain)
	if err != nil {
		logger.Debug("Specific DNS lookup failed",
			zap.String("server", dnsServer),
			zap.String("domain", domain),
			zap.Error(err))
		return nil
	}

	if len(ips) == 0 {
		return nil
	}

	// Return first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}

	return nil
}

// GetSubdomainRecord retrieves the full DNS record for a subdomain.
//
// Behavior:
//   - ASSESS: Check if subdomain exists via CheckSubdomainExists
//   - EVALUATE: Return full record details or error
//
// Error Handling:
//   - Returns error if subdomain doesn't exist
//   - Returns error if API query fails
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	token: Hetzner DNS API token wrapped in SecureString
//	domain: Fully qualified domain name
//
// Returns:
//
//	*DNSRecord: Full DNS record with ID, TTL, IP, etc.
//	error: Non-nil if subdomain not found or query failed
func GetSubdomainRecord(rc *eos_io.RuntimeContext, token *crypto.SecureString, domain string) (*DNSRecord, error) {
	exists, record, err := CheckSubdomainExists(rc, token, domain)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, fmt.Errorf("subdomain not found: %s", domain)
	}

	return record, nil
}

// DeleteSubdomainOnFailure cleans up a partially created subdomain.
//
// Use Case:
//
//	Call this in a defer block if you want to clean up on failure:
//	  var record *DNSRecord
//	  defer func() {
//	      if err != nil && record != nil {
//	          _ = DeleteSubdomainOnFailure(rc, token, domain)
//	      }
//	  }()
//
// Behavior:
//   - ASSESS: Check if subdomain exists
//   - INTERVENE: Delete record if found
//   - EVALUATE: Log success or failure
//
// Idempotency:
//   - Returns nil if subdomain doesn't exist (already cleaned up)
//   - Can be called multiple times safely
//
// Error Handling:
//   - Returns nil if subdomain doesn't exist (not an error)
//   - Returns error if deletion fails
//   - Logs warning on failure
//
// Parameters:
//
//	rc: RuntimeContext with logger and tracing
//	token: Hetzner DNS API token wrapped in SecureString
//	domain: Fully qualified domain name to delete
//
// Returns:
//
//	error: Non-nil if deletion failed
func DeleteSubdomainOnFailure(rc *eos_io.RuntimeContext, token *crypto.SecureString, domain string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Warn("Cleaning up subdomain due to failure",
		zap.String("domain", domain))

	// Check if subdomain exists
	record, err := GetSubdomainRecord(rc, token, domain)
	if err != nil {
		// Subdomain doesn't exist - cleanup successful
		logger.Debug("Subdomain already absent during cleanup",
			zap.String("domain", domain))
		return nil
	}

	// Delete the DNS record
	client := NewClient(token.Value(), logger.Logger().Logger)
	if err := client.DeleteRecord(rc, record.ID); err != nil {
		return fmt.Errorf("failed to delete subdomain during cleanup: %w", err)
	}

	logger.Info("Subdomain cleaned up successfully",
		zap.String("domain", domain),
		zap.String("record_id", record.ID))

	return nil
}
