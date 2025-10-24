// pkg/consultemplate/constants.go
//
// Consul Template Constants - Single Source of Truth
//
// All Consul Template paths, permissions, ports, and values defined here.
// ZERO hardcoded values allowed elsewhere in the codebase.

package consultemplate

import "time"

// Product identification
const (
	ProductName     = "consul-template"
	ServiceBaseName = "consul-template"
	SystemUser      = "consul-template"
	SystemGroup     = "consul-template"
)

// Binary paths and installation locations
const (
	// BinaryPath is the installed consul-template binary location
	// RATIONALE: /usr/local/bin is standard for locally-installed binaries
	BinaryPath = "/usr/local/bin/consul-template"

	// ConfigDir is the directory containing all consul-template configs
	// RATIONALE: Follows HashiCorp convention (/etc/vault.d, /etc/consul.d)
	ConfigDir = "/etc/consul-template.d"

	// TemplateDir is the directory containing template files
	// RATIONALE: Separate from config for clarity and permissions
	TemplateDir = "/etc/consul-template.d/templates"

	// DataDir is the working directory for consul-template
	// RATIONALE: /opt is standard for application data
	DataDir = "/opt/consul-template"

	// LogDir is the directory for logs (if not using systemd journal)
	// RATIONALE: Standard log location
	LogDir = "/var/log/consul-template"

	// PIDFile is the location of the PID file
	PIDFile = "/var/run/consul-template.pid"
)

// File permissions
// RATIONALE: Security-hardened permissions for production deployment
// SECURITY: Prevents unauthorized access to templates and configs
// THREAT MODEL: Mitigates privilege escalation and lateral movement
const (
	// ConfigDirPerm is the permission for config directory
	// RATIONALE: 0755 allows reading by all, writing only by root
	ConfigDirPerm = 0755

	// ConfigFilePerm is the permission for config files
	// RATIONALE: 0640 allows reading by consul-template user, writing by root
	// SECURITY: Prevents other users from reading potentially sensitive config
	ConfigFilePerm = 0640

	// TemplateDirPerm is the permission for template directory
	// RATIONALE: 0755 allows reading by all (templates may be reviewed)
	TemplateDirPerm = 0755

	// TemplateFilePerm is the permission for template files
	// RATIONALE: 0644 allows reading by all (templates contain no secrets)
	TemplateFilePerm = 0644

	// DataDirPerm is the permission for data directory
	// RATIONALE: 0750 restricts to user and group only
	// SECURITY: Runtime data should not be world-readable
	DataDirPerm = 0750

	// RenderedConfigPerm is the permission for rendered config files
	// RATIONALE: 0640 restricts to user and group (may contain secrets)
	// SECURITY: Rendered configs may contain secrets from Vault
	// THREAT MODEL: Prevents credential theft via filesystem access
	RenderedConfigPerm = 0640

	// RenderedConfigSecretPerm is for highly sensitive rendered configs
	// RATIONALE: 0600 restricts to owner only (database passwords, API keys)
	// SECURITY: Strictest permission for maximum protection
	RenderedConfigSecretPerm = 0600
)

// Default configuration values
const (
	// DefaultLogLevel is the default logging level
	DefaultLogLevel = "info"

	// DefaultMaxStale is the maximum staleness for Consul queries
	// RATIONALE: 10s allows some staleness for performance
	DefaultMaxStale = 10 * time.Second

	// DefaultWaitTime is the default wait time for blocking queries
	// RATIONALE: 5 minutes is standard for HashiCorp blocking queries
	DefaultWaitTime = 5 * time.Minute

	// DefaultRetryInterval is the retry interval on errors
	// RATIONALE: 5s provides good balance between responsiveness and load
	DefaultRetryInterval = 5 * time.Second

	// DefaultGracePeriod is the grace period before sending SIGKILL
	// RATIONALE: 15s allows most processes to gracefully shutdown
	DefaultGracePeriod = 15 * time.Second

	// DefaultKillTimeout is the timeout before killing a command
	// RATIONALE: 30s handles slow shutdowns
	DefaultKillTimeout = 30 * time.Second
)

// Consul Template version and download
const (
	// DefaultVersion is the default Consul Template version to install
	// NOTE: Update this when new stable versions are released
	DefaultVersion = "0.37.4"

	// DownloadURLTemplate is the template for downloading Consul Template
	// Variables: {version}, {os}, {arch}
	DownloadURLTemplate = "https://releases.hashicorp.com/consul-template/{version}/consul-template_{version}_{os}_{arch}.zip"

	// ChecksumURLTemplate is the template for downloading checksums
	ChecksumURLTemplate = "https://releases.hashicorp.com/consul-template/{version}/consul-template_{version}_SHA256SUMS"

	// SignatureURLTemplate is the template for downloading GPG signatures
	SignatureURLTemplate = "https://releases.hashicorp.com/consul-template/{version}/consul-template_{version}_SHA256SUMS.sig"
)

// Connection defaults
const (
	// DefaultConsulAddr is the default Consul address
	DefaultConsulAddr = "http://localhost:8500"

	// DefaultVaultAddr is the default Vault address
	DefaultVaultAddr = "https://localhost:8200"

	// DefaultVaultTokenPath is the default path to Vault token
	// RATIONALE: Reuses Vault Agent token for authentication
	DefaultVaultTokenPath = "/run/eos/vault_agent_eos.token"
)

// Template rendering defaults
const (
	// DefaultMinWait is the minimum wait before rendering
	// RATIONALE: Debounces rapid changes
	DefaultMinWait = 2 * time.Second

	// DefaultMaxWait is the maximum wait before rendering
	// RATIONALE: Forces render even if changes keep coming
	DefaultMaxWait = 10 * time.Second

	// DefaultBackupExtension is the file extension for backups
	DefaultBackupExtension = ".bak"

	// DefaultCreateDestDirs creates destination directories if missing
	DefaultCreateDestDirs = true
)

// Systemd service defaults
const (
	// SystemdServiceFile is the base systemd service file location
	// Services are named: consul-template-{service}.service
	SystemdServiceDir = "/etc/systemd/system"

	// SystemdWantedByTarget is the systemd target for auto-start
	SystemdWantedByTarget = "multi-user.target"

	// SystemdRestartSec is the delay between service restarts
	// RATIONALE: 5s prevents restart storms
	SystemdRestartSec = 5

	// SystemdRestartPolicy is the restart policy
	// RATIONALE: "always" ensures high availability
	SystemdRestartPolicy = "always"

	// SystemdKillMode is the kill mode for systemd
	// RATIONALE: "process" only kills main process, not child commands
	SystemdKillMode = "process"

	// SystemdKillSignal is the signal to send on stop
	// RATIONALE: SIGTERM allows graceful shutdown
	SystemdKillSignal = "SIGTERM"
)

// Health check timeouts
const (
	// HealthCheckTimeout is the timeout for health checks
	HealthCheckTimeout = 10 * time.Second

	// HealthCheckInterval is the interval between health checks
	HealthCheckInterval = 30 * time.Second
)
