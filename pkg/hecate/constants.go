// pkg/hecate/constants.go
// Centralized constants for Hecate reverse proxy infrastructure
// This file is the SINGLE SOURCE OF TRUTH for all Hecate-related constants
// CRITICAL: All hardcoded values MUST be defined here (CLAUDE.md Rule #12)

package hecate

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// ============================================================================
// SERVICE AND CONTAINER NAMES
// ============================================================================

const (
	// CaddyContainerName is the name of the Caddy reverse proxy container in docker-compose
	// RATIONALE: Standardized container name for service discovery and management
	// SECURITY: Prevents container name confusion in multi-tenant environments
	CaddyContainerName = "hecate-caddy"

	// HecateServiceName is the canonical name for the Hecate service
	HecateServiceName = "hecate"
)

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

const (
	// CaddyAdminAPIHost is the hostname where Caddy Admin API is accessible
	// RATIONALE: Caddy Admin API runs on localhost for security (not exposed to network)
	// SECURITY: Localhost-only prevents remote API access without authentication
	CaddyAdminAPIHost = "localhost"

	// CaddyAdminAPIPort is the port where Caddy Admin API listens
	// RATIONALE: Port 2019 is Caddy's default Admin API port
	// SECURITY: Must be exposed as "127.0.0.1:2019:2019" in docker-compose.yml for host access
	//           Binding to 127.0.0.1 ensures Admin API is ONLY accessible from localhost, not network
	// USAGE: Used for zero-downtime config reloads via `eos update hecate --add`
	//        If port not exposed, Eos falls back to container restart (brief downtime)
	// REFERENCE: https://caddyserver.com/docs/api
	// TEMPLATE: pkg/hecate/yaml_generator.go line ~256 exposes this port in docker-compose.yml
	CaddyAdminAPIPort = 2019

	// AuthentikHost is the hostname where Authentik SSO service is accessible
	// RATIONALE: Authentik runs on localhost in Hecate docker-compose stack
	// SECURITY: Internal-only access, proxied externally via Caddy
	AuthentikHost = "localhost"

	// AuthentikPort is the port where Authentik SSO service listens
	// RATIONALE: Port 9000 is Authentik's default HTTP port in Hecate deployment
	// REFERENCE: /opt/hecate/docker-compose.yml
	AuthentikPort = 9000
)

// ============================================================================
// FILE PATHS
// ============================================================================

const (
	// HecateInstallDir is the root directory for Hecate installation
	// RATIONALE: /opt/ is standard for third-party software on Ubuntu/Debian
	// SECURITY: Requires root access, prevents user-space tampering
	HecateInstallDir = "/opt/hecate"

	// CaddyfilePath is the absolute path to the main Caddyfile
	// RATIONALE: Primary configuration file for Caddy reverse proxy
	// SECURITY: Must be root-owned with 0644 permissions
	CaddyfilePath = "/opt/hecate/Caddyfile"

	// BackupDir is where Caddyfile backups are stored
	// RATIONALE: Timestamped backups enable rollback on configuration errors
	// SECURITY: Must be root-owned with 0755 permissions
	BackupDir = "/opt/hecate/backups"

	// EnvFilePath is the path to the .env file with service credentials
	// RATIONALE: Standard location for docker-compose environment variables
	// SECURITY: Must be root-owned with 0600 permissions (contains secrets)
	EnvFilePath = "/opt/hecate/.env"

	// DockerComposeFilePath is the path to the docker-compose.yml file
	// RATIONALE: Defines Hecate service stack (Caddy, Authentik, Redis, PostgreSQL)
	DockerComposeFilePath = "/opt/hecate/docker-compose.yml"
)

// ============================================================================
// TIMEOUTS AND DURATIONS
// ============================================================================

const (
	// CaddyAdminAPITimeout is the HTTP client timeout for Admin API calls
	// RATIONALE: 30 seconds allows for large config adaptations without premature timeout
	// THREAT MODEL: Prevents indefinite hangs if Caddy is unresponsive
	CaddyAdminAPITimeout = 30 * time.Second

	// CaddyReloadWaitDuration is how long to wait after reload before verification
	// RATIONALE: Caddy reload is asynchronous; wait ensures config is fully applied
	// EMPIRICAL: 2 seconds is sufficient for most configs on modern hardware
	CaddyReloadWaitDuration = 2 * time.Second

	// RouteVerificationWaitDuration is how long to wait before testing new route
	// RATIONALE: Allows DNS propagation, TLS cert provisioning, backend warmup
	// EMPIRICAL: 5 seconds balances responsiveness vs. false negatives
	RouteVerificationWaitDuration = 5 * time.Second

	// RouteVerificationTimeout is the HTTP client timeout for route testing
	// RATIONALE: 10 seconds is reasonable for backend that may be cold-starting
	// THREAT MODEL: Prevents indefinite hangs on unresponsive backends
	RouteVerificationTimeout = 10 * time.Second

	// BackupMinimumAgeBeforeCleanup is the minimum age of backups before they're eligible for cleanup
	// RATIONALE: Prevents deleting backups that are still in use by concurrent operations
	// THREAT MODEL: Race condition where operation A's backup is deleted by operation B's cleanup
	BackupMinimumAgeBeforeCleanup = 1 * time.Hour
)

// ============================================================================
// FILE PERMISSIONS
// ============================================================================

const (
	// CaddyfilePerm is the permission mode for Caddyfile
	// RATIONALE: 0644 (rw-r--r--) allows root write, all read (needed for Caddy process)
	// SECURITY: Not secret data, but write-protection prevents unauthorized changes
	// THREAT MODEL: Prevents non-root users from injecting malicious routes
	CaddyfilePerm = 0644

	// BackupDirPerm is the permission mode for backup directory
	// RATIONALE: 0755 (rwxr-xr-x) allows root write, all read/execute (needed for listing)
	// SECURITY: Backups contain same data as Caddyfile (non-secret, but integrity-critical)
	BackupDirPerm = 0755

	// BackupFilePerm is the permission mode for individual backup files
	// RATIONALE: 0644 (rw-r--r--) matches Caddyfile permissions
	// SECURITY: Consistent permissions simplify audit and troubleshooting
	BackupFilePerm = 0644

	// EnvFilePerm is the permission mode for .env file
	// RATIONALE: 0600 (rw-------) allows root read/write only
	// SECURITY: Contains secrets (Authentik API token, database passwords)
	// THREAT MODEL: Prevents non-root users from reading credentials
	// COMPLIANCE: Required for SOC2, PCI-DSS, HIPAA
	EnvFilePerm = 0600

	// TempFilePerm is the permission mode for temporary files during atomic writes
	// RATIONALE: 0600 (rw-------) ensures temp files are not readable during write
	// SECURITY: Prevents race conditions where partial config is read by another process
	TempFilePerm = 0600
)

// ============================================================================
// RETRY AND BACKOFF
// ============================================================================

const (
	// CaddyAdminAPIMaxRetries is the maximum number of retry attempts for transient failures
	// RATIONALE: Retries connection refused, timeout (transient). Fails fast on 4xx/5xx (deterministic)
	// REFERENCE: CLAUDE.md "Retry Logic (P1 - CRITICAL)"
	CaddyAdminAPIMaxRetries = 3

	// CaddyAdminAPIRetryBaseDelay is the initial delay before first retry
	// RATIONALE: Exponential backoff: 1s, 2s, 4s (total 7s max)
	CaddyAdminAPIRetryBaseDelay = 1 * time.Second

	// FileLockTimeout is the maximum time to wait for file lock acquisition
	// RATIONALE: Prevents deadlock if another process holds lock indefinitely
	// THREAT MODEL: Concurrent 'eos update hecate --add' invocations
	FileLockTimeout = 30 * time.Second
)

// ============================================================================
// VALIDATION LIMITS
// ============================================================================

const (
	// MaxServiceNameLength is the maximum allowed length for service names
	// RATIONALE: Prevents excessively long filenames, log paths, Caddyfile entries
	// SECURITY: Mitigates DoS via resource exhaustion
	MaxServiceNameLength = 128

	// MaxDNSLength is the maximum allowed length for DNS names
	// RATIONALE: RFC 1035 limits DNS names to 253 characters
	// REFERENCE: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
	MaxDNSLength = 253

	// MaxBackendLength is the maximum allowed length for backend addresses
	// RATIONALE: Prevents buffer overflow in logs, prevents injection attacks
	MaxBackendLength = 256

	// MaxCustomDirectivesCount is the maximum number of custom directives allowed
	// RATIONALE: Prevents Caddyfile bloat, simplifies validation
	MaxCustomDirectivesCount = 10

	// MaxCustomDirectiveLength is the maximum length for a single custom directive
	// RATIONALE: Prevents injection of excessively large config blocks
	MaxCustomDirectiveLength = 1024
)

// ============================================================================
// LOG PATHS
// ============================================================================

const (
	// CaddyLogDir is the directory where Caddy stores service-specific logs
	// RATIONALE: Separate log file per service for easier troubleshooting
	// SECURITY: Logs may contain sensitive request data (PII, auth headers)
	CaddyLogDir = "/var/log/caddy"
)

// ============================================================================
// DEFAULT VALUES
// ============================================================================

const (
	// DefaultBackupRetentionDays is the default number of days to keep backups
	// RATIONALE: 30 days balances disk space vs. recovery window
	// EMPIRICAL: Most config issues are discovered within days, not weeks
	DefaultBackupRetentionDays = 30

	// DefaultSSOProvider is the default SSO provider when --sso flag is used
	// RATIONALE: Authentik is the only SSO provider currently integrated with Hecate
	DefaultSSOProvider = "authentik"
)

// ============================================================================
// BIONICGPT SERVICE-SPECIFIC CONSTANTS
// ============================================================================

const (
	// BionicGPTDefaultPort is the port where BionicGPT application listens
	// RATIONALE: Use centralized port from pkg/shared/ports.go for consistency (CLAUDE.md Rule #12)
	// SINGLE SOURCE OF TRUTH: shared.PortBionicGPT = 8513
	// REFERENCE: https://github.com/bionic-gpt/bionic-gpt
	BionicGPTDefaultPort = shared.PortBionicGPT // 8513

	// BionicGPTHealthEndpoint - DEPRECATED - This endpoint does NOT exist in BionicGPT
	// VENDOR RESEARCH: Verified via source code analysis - NO /health, /healthz, /ready endpoints
	// SOURCE: https://github.com/bionic-gpt/bionic-gpt (crates/web-server/main.rs)
	// ACTUAL BEHAVIOR: Root path "/" requires JWT authentication, returns 401 without token
	// VALIDATION STRATEGY: Check root path, accept 401/403 as proof service is running
	// TODO: Remove this constant in future refactor (currently unused)
	BionicGPTHealthEndpoint = "" // Empty string - no health endpoint exists
)

// ============================================================================
// WAZUH SERVICE-SPECIFIC CONSTANTS
// ============================================================================

const (
	// WazuhDefaultPort is the port where Wazuh Dashboard listens
	// RATIONALE: Wazuh Dashboard typically runs on HTTPS port 443
	// REFERENCE: https://documentation.wazuh.com/current/installation-guide/
	// NOTE: This is for the dashboard, not the manager ports (1514, 1515, 55000)
	WazuhDefaultPort = 443
)

// ============================================================================
// AUTHENTIK FORWARD AUTH CONSTANTS
// ============================================================================

const (
	// AuthentikOutpostPath is the path prefix for Authentik outpost endpoints
	// RATIONALE: Authentik uses /outpost.goauthentik.io/* for forward auth communication
	// SECURITY: This path must be proxied to Authentik for forward auth to work
	// REFERENCE: https://docs.goauthentik.io/add-secure-apps/providers/proxy/
	AuthentikOutpostPath = "/outpost.goauthentik.io"

	// AuthentikForwardAuthPath is the forward auth validation endpoint
	// RATIONALE: Caddy forward_auth directive calls this endpoint to validate requests
	// FLOW: Caddy → Authentik (validates session) → Returns headers → Caddy forwards to app
	// REFERENCE: https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_caddy
	AuthentikForwardAuthPath = "/outpost.goauthentik.io/auth/caddy"

	// AuthentikEmbeddedOutpostName is the name of Authentik's default embedded outpost
	// RATIONALE: Used to find and assign proxy providers to the embedded outpost
	// NOTE: This is Authentik's default outpost name, created during installation
	AuthentikEmbeddedOutpostName = "authentik Embedded Outpost"
)
