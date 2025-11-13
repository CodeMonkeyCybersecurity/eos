// pkg/hetzner/constants.go
//
// SINGLE SOURCE OF TRUTH for all Hetzner configuration constants.
// Consolidates scattered constants from types.go:5 and dns_servers.go:121
// to fix P0 CRITICAL duplication violation.

package hetzner

import (
	"time"
)

// API Endpoints
// Consolidated from:
//   - types.go:5:        const hetznerDNSBaseURL = "https://dns.hetzner.com/api/v1"
//   - types.go:25:       const recordsBaseURL = "https://dns.hetzner.com/api/v1/records"
//   - types.go:50:       const zonesBaseURL = "https://dns.hetzner.com/api/v1/zones"
//   - dns_servers.go:121: const hetznerAPIBase = "https://dns.hetzner.com/api/v1"
const (
	// HetznerDNSAPIBase is the base URL for Hetzner DNS API v1
	HetznerDNSAPIBase = "https://dns.hetzner.com/api/v1"

	// HetznerDNSRecordsURL is the full URL for DNS records endpoint
	HetznerDNSRecordsURL = "https://dns.hetzner.com/api/v1/records"

	// HetznerDNSZonesURL is the full URL for DNS zones endpoint
	HetznerDNSZonesURL = "https://dns.hetzner.com/api/v1/zones"

	// HetznerCloudAPIBase is the base URL for Hetzner Cloud API v1
	HetznerCloudAPIBase = "https://api.hetzner.cloud/v1"

	// HetznerDNSAPIVersion is the API version for DNS operations
	HetznerDNSAPIVersion = "v1"
)

// DNS Configuration
const (
	// DefaultDNSTTL is the default TTL for DNS records (5 minutes)
	// RATIONALE: Balance between propagation speed and DNS server load
	DefaultDNSTTL = 300

	// DNSPropagationTimeout is max time to wait for DNS propagation (60 seconds)
	// RATIONALE: Most DNS updates propagate within 30-60s, beyond this suggests misconfiguration
	DNSPropagationTimeout = 60 * time.Second

	// DNSPropagationPollInterval is initial interval between DNS checks (5 seconds)
	// RATIONALE: Starts at 5s, increases with exponential backoff to reduce API load
	DNSPropagationPollInterval = 5 * time.Second

	// DNSPropagationMinAgreement is minimum nameservers that must agree (3)
	// RATIONALE: Prevents false positives from cached/stale responses
	// Strategy: System DNS + Google (8.8.8.8) + Cloudflare (1.1.1.1) + OpenDNS
	DNSPropagationMinAgreement = 3
)

// DNS Record Types
// See: https://en.wikipedia.org/wiki/List_of_DNS_record_types
type RecordType string

const (
	RecordTypeA     RecordType = "A"     // IPv4 address
	RecordTypeAAAA  RecordType = "AAAA"  // IPv6 address
	RecordTypeCNAME RecordType = "CNAME" // Canonical name
	RecordTypeMX    RecordType = "MX"    // Mail exchange
	RecordTypeTXT   RecordType = "TXT"   // Text record
	RecordTypeNS    RecordType = "NS"    // Name server
	RecordTypeSRV   RecordType = "SRV"   // Service locator
	RecordTypeCAA   RecordType = "CAA"   // Certificate authority authorization
)

// Rate Limiting
// Hetzner API rate limits are enforced via response headers:
//   - Ratelimit-Limit: Total requests per hour
//   - Ratelimit-Remaining: Requests remaining in current window
//   - Ratelimit-Reset: UNIX timestamp when limit resets
//
// RATIONALE: Conservative limits to avoid hitting undocumented DNS API limits
const (
	// RateLimitUnknown indicates rate limit info unavailable
	RateLimitUnknown = 0

	// RateLimitMaxRetries is max retry attempts for rate-limited requests
	// RATIONALE: 5 retries with exponential backoff = ~3 minutes total
	RateLimitMaxRetries = 5

	// RateLimitInitialBackoff is initial wait time after rate limit (5 seconds)
	RateLimitInitialBackoff = 5 * time.Second

	// RateLimitMaxBackoff is maximum wait time between retries (30 seconds)
	// RATIONALE: Prevents indefinite waiting, signals user intervention needed
	RateLimitMaxBackoff = 30 * time.Second
)

// PublicDNSServers are authoritative public DNS servers for multi-nameserver verification
// Used by VerifySubdomainPropagated to prevent false positives from local DNS caching
var PublicDNSServers = []string{
	"8.8.8.8:53",        // Google Public DNS
	"1.1.1.1:53",        // Cloudflare DNS
	"208.67.222.222:53", // OpenDNS
}

// Subdomain Validation
// Per RFC 1035 (Domain Names) and RFC 1123 (Internet Host Requirements)
const (
	// MaxSubdomainLabelLength is max chars per label (e.g., "app" in "app.example.com")
	// RFC 1035 Section 2.3.4: Labels limited to 63 octets
	MaxSubdomainLabelLength = 63

	// MaxDomainLength is max total FQDN length
	// RFC 1035 Section 2.3.4: Domain names limited to 255 octets
	MaxDomainLength = 253

	// SubdomainValidationPattern matches valid subdomain labels
	// Pattern: [a-z0-9]([a-z0-9-]*[a-z0-9])?
	// RATIONALE: Lowercase only (case-insensitive DNS), no leading/trailing hyphens
	SubdomainValidationPattern = `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
)

// HTTP Client Configuration
const (
	// HTTPClientTimeout is timeout for Hetzner API requests
	HTTPClientTimeout = 30 * time.Second

	// HTTPMaxIdleConns is max idle connections in pool
	HTTPMaxIdleConns = 100

	// HTTPMaxIdleConnsPerHost is max idle connections per host
	HTTPMaxIdleConnsPerHost = 10

	// HTTPIdleConnTimeout is timeout for idle connections
	HTTPIdleConnTimeout = 90 * time.Second
)
