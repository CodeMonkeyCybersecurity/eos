/* pkg/wazuh/types.go */

package wazuh

import (
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

const configFile = ".wazuh.json"

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
 -h 127.0.0.1 \
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

	// Dashboard configs
	OpenSearchDashboardYml = "/etc/wazuh-dashboard/opensearch_dashboards.yml"

	APIAgentConfig = "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
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
