/* pkg/wazuh/types.go */

package wazuh

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// DefaultPorts holds the standard Wazuh ports used by the CLI.
var DefaultPorts = []string{
	"443/tcp",
	"1514/tcp",  // Filebeat/agent TCP
	"1515/tcp",  // Agent registration
	"55000/tcp", // API
}

var (
	WazuhConfigPath = xdg.XDGConfigPath(shared.EosID, "wazuh.json")
	ShowSecrets     bool // toggle to display password in ConfirmWazuhConfig
)

// User represents a Wazuh API user object
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// APICreds holds the Wazuh/Wazuh API credentials.
type APICreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	// #nosec G101 - This is a Vault path for credentials, not a hardcoded credential
	VaultWazuhCreds  = "eos/wazuh/api_creds"
	VaultWazuhConfig = "eos/wazuh/config"
	// #nosec G101 - This is a URL for a password tool, not a hardcoded credential
	WazuhPasswdToolURL = "https://packages.wazuh.com/4.11/wazuh-passwords-tool.sh"
	// #nosec G101 - This is a file path for a password tool, not a hardcoded credential
	WazuhPasswdToolPath = "/usr/local/bin/wazuh-passwords-tool.sh"
)

// Config represents the configuration stored in wazuh.json
type Config struct {
	APIUser            string `json:"API_User"`
	APIPassword        string `json:"API_Password"`
	Endpoint           string `json:"endpoint"`
	FQDN               string `json:"FQDN"`
	LatestVersion      string `json:"LatestVersion,omitempty"`
	Port               string `json:"port"`
	Protocol           string `json:"protocol"`
	Token              string `json:"token,omitempty"`
	VerifyCertificates bool   `json:"verify_certificates"`
}

type LDAPConfig struct {
	FQDN         string
	BindDN       string
	Password     string
	UserBase     string
	RoleBase     string
	AdminRole    string
	ReadonlyRole string
}

const ApplyConfiguration = `
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
 -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml \
 -icl \
 -key /etc/wazuh-indexer/certs/admin-key.pem \
 -cert /etc/wazuh-indexer/certs/admin.pem \
 -cacert /etc/wazuh-indexer/certs/root-ca.pem \
 -h shared.GetInternalHostname \
 -nhnv
`

const (
	// Indexer configs
	OpenSearchIndexerDir    = "/etc/wazuh-indexer/opensearch-security/"
	OpenSearchRoleMappings  = OpenSearchIndexerDir + "roles_mapping.yml"
	OpenSearchRoles         = OpenSearchIndexerDir + "roles.yml"
	OpenSearchConfig        = OpenSearchIndexerDir + "config.yml"
	OpenSearchInternalUsers = OpenSearchIndexerDir + "internal_users.yml"
	OpenSearchActionGroups  = OpenSearchIndexerDir + "action_groups.yml"

	// SSO/SAML configs
	// RATIONALE: Metadata file location for Authentik SAML IdP
	// SECURITY: World-readable (0644) as it contains public metadata only
	OpenSearchSAMLMetadataFile = OpenSearchIndexerDir + "authentik-metadata.xml"

	// RATIONALE: SAML exchange key for encrypted assertions
	// SECURITY: Must be 0600 (read-only by indexer user) as it contains private key material
	// THREAT MODEL: Prevents unauthorized access to decrypt SAML assertions
	OpenSearchSAMLExchangeKey = OpenSearchIndexerDir + "exchange.key"

	// Dashboard configs
	OpenSearchDashboardYml = "/etc/wazuh-dashboard/opensearch_dashboards.yml"

	APIAgentConfig = "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

	// Security admin tool
	// RATIONALE: OpenSearch security configuration tool location
	SecurityAdminTool = "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"

	// Certificate paths
	// RATIONALE: TLS certificates for OpenSearch Security admin operations
	// SECURITY: Used for mTLS authentication when applying security config
	OpenSearchCertsDir  = "/etc/wazuh-indexer/certs/"
	OpenSearchRootCA    = OpenSearchCertsDir + "root-ca.pem"
	OpenSearchAdminCert = OpenSearchCertsDir + "admin.pem"
	OpenSearchAdminKey  = OpenSearchCertsDir + "admin-key.pem"

	// Backup directory
	// RATIONALE: Centralized location for Eos-managed Wazuh backups
	WazuhBackupDir = "/opt/eos/backups/"
)

// File permissions constants
// SECURITY CRITICAL: These permissions are required for compliance and threat mitigation
const (
	// RATIONALE: SAML metadata is public information, world-readable
	// SECURITY: Contains only public IdP metadata (certificates, endpoints)
	// THREAT MODEL: No confidential data, safe for broad read access
	SAMLMetadataFilePerm = 0644

	// RATIONALE: Exchange key is private key material, must be owner-only
	// SECURITY: Protects SAML assertion decryption key
	// THREAT MODEL: Prevents unauthorized decryption of SAML assertions
	// COMPLIANCE: Required for SOC2, PCI-DSS (restrict key access)
	SAMLExchangeKeyPerm = 0600

	// RATIONALE: Security config files are system configs, admin-writable only
	// SECURITY: Prevents unauthorized modification of security policies
	// THREAT MODEL: Mitigates privilege escalation via config tampering
	SecurityConfigPerm = 0644

	// RATIONALE: Backup directory needs admin write, group read for restore ops
	// SECURITY: Allows backup operations by admin, read by operators
	BackupDirPerm = 0755
)

// Service operation timeouts
// RATIONALE: Empirically determined safe wait times for service operations
const (
	// RATIONALE: Wait time for wazuh-indexer to be ready after restart
	// SECURITY: Prevents race condition where config is applied before indexer is ready
	// EMPIRICAL: 10 seconds sufficient for indexer startup on modern hardware
	// THREAT MODEL: Too short = config fails; too long = unnecessary wait
	WazuhIndexerStartupWait = 10 * time.Second

	// RATIONALE: Retry delay for indexer health check
	// THREAT MODEL: Prevents tight loop CPU exhaustion if indexer is slow
	// EMPIRICAL: 2 seconds balances responsiveness with resource usage
	WazuhIndexerHealthCheckRetryDelay = 2 * time.Second

	// RATIONALE: Wait time for wazuh-dashboard to be ready after restart
	// EMPIRICAL: 5 seconds sufficient for dashboard startup
	WazuhDashboardStartupWait = 5 * time.Second
)

// SAML attribute names
const (
	// RATIONALE: SAML role attribute name for OpenSearch Security role mapping
	// CRITICAL: Must be capital "Roles" (not "roles") for Wazuh to recognize
	// SECURITY: Case-sensitive - incorrect case prevents role mapping (authorization bypass)
	// REFERENCE: Wazuh OpenSearch Security SAML configuration docs
	SAMLRolesAttributeName = "Roles"
)

// PlatformConfig represents the overall Wazuh platform configuration
// Migrated from wazuh_mssp - Wazuh and Wazuh are interchangeable
type PlatformConfig struct {
	Name        string          `json:"platform_name"`
	Environment string          `json:"environment"` // dev, staging, production
	Datacenter  string          `json:"datacenter"`
	Domain      string          `json:"platform_domain"`
	Network     NetworkConfig   `json:"network_config"`
	Storage     StorageConfig   `json:"storage_config"`
	Nomad       NomadConfig     `json:"nomad_config"`
	Temporal    TemporalConfig  `json:"temporal_config"`
	NATS        NATSConfig      `json:"nats_config"`
	CCS         CCSConfig       `json:"ccs_config"`
	Authentik   AuthentikConfig `json:"authentik_config"`
}

// NetworkConfig defines network configuration for the platform
type NetworkConfig struct {
	PlatformCIDR string    `json:"platform_cidr"`
	CustomerCIDR string    `json:"customer_cidr"`
	VLANRange    VLANRange `json:"vlan_range"`
}

// VLANRange defines the VLAN range for customer isolation
type VLANRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// StorageConfig defines storage pool configuration
type StorageConfig struct {
	Pools map[string]StoragePool `json:"pools"`
}

// StoragePool represents a storage pool configuration
type StoragePool struct {
	Path string `json:"path"`
	Size string `json:"size"`
}

// NomadConfig defines Nomad cluster configuration
type NomadConfig struct {
	ServerCount     int            `json:"server_count"`
	ClientCount     int            `json:"client_count"`
	DatacenterName  string         `json:"datacenter_name"`
	EncryptionKey   string         `json:"encryption_key"`
	ACLBootstrap    bool           `json:"acl_bootstrap"`
	TLSConfig       TLSConfig      `json:"tls_config"`
	StoragePools    []string       `json:"storage_pools"`
	ClientConfig    ClientConfig   `json:"client_config"`
	ServerResources ResourceConfig `json:"server_resources"`
	ClientResources ResourceConfig `json:"client_resources"`
}

// TLSConfig defines TLS configuration
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CAFile   string `json:"ca_file"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// ClientConfig defines Nomad client configuration
type ClientConfig struct {
	EnableDocker bool              `json:"enable_docker"`
	EnableRaw    bool              `json:"enable_raw_exec"`
	MetaData     map[string]string `json:"meta_data"`
}

// TemporalConfig defines Temporal workflow engine configuration
type TemporalConfig struct {
	ServerCount       int                    `json:"server_count"`
	Namespace         string                 `json:"namespace"`
	RetentionDays     int                    `json:"retention_days"`
	DatabaseConfig    TemporalDatabaseConfig `json:"database_config"`
	ServerResources   ResourceConfig         `json:"server_resources"`
	DatabaseResources ResourceConfig         `json:"database_resources"`
}

// TemporalDatabaseConfig defines database configuration for Temporal
type TemporalDatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// NATSConfig defines NATS messaging configuration
type NATSConfig struct {
	ServerCount     int             `json:"server_count"`
	ClusterID       string          `json:"cluster_id"`
	Subjects        []string        `json:"subjects"`
	EnableJetStream bool            `json:"enable_jetstream"`
	ServerResources ResourceConfig  `json:"server_resources"`
	JetStreamConfig JetStreamConfig `json:"jetstream_config"`
}

// CCSConfig defines Cross-Cluster Search configuration
type CCSConfig struct {
	IndexerNodes       []string                 `json:"indexer_nodes"`
	RemoteClusters     map[string]RemoteCluster `json:"remote_clusters"`
	IndexerResources   ResourceConfig           `json:"indexer_resources"`
	DashboardResources ResourceConfig           `json:"dashboard_resources"`
}

// RemoteCluster defines remote cluster configuration for CCS
type RemoteCluster struct {
	Seeds           []string `json:"seeds"`
	SkipUnavailable bool     `json:"skip_unavailable"`
}

// AuthentikConfig defines Authentik SSO configuration
type AuthentikConfig struct {
	URL     string `json:"url"`
	Token   string `json:"token"`
	Enabled bool   `json:"enabled"`
}

// JetStreamConfig defines NATS JetStream configuration
type JetStreamConfig struct {
	MaxMemory string `json:"max_memory"`
	MaxFile   string `json:"max_file"`
}
