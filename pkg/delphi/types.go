/* pkg/delphi/types.go */

package delphi

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
	DelphiConfigPath = xdg.XDGConfigPath(shared.EosID, "delphi.json")
	ShowSecrets      bool // toggle to display password in ConfirmDelphiConfig
)

// User represents a Wazuh API user object
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// APICreds holds the Delphi/Wazuh API credentials.
type APICreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	// #nosec G101 - This is a Vault path for credentials, not a hardcoded credential
	VaultDelphiCreds     = "eos/delphi/api_creds"
	VaultDelphiConfig    = "eos/delphi/config"
	// #nosec G101 - This is a URL for a password tool, not a hardcoded credential
	DelphiPasswdToolURL  = "https://packages.wazuh.com/4.11/wazuh-passwords-tool.sh"
	// #nosec G101 - This is a file path for a password tool, not a hardcoded credential
	DelphiPasswdToolPath = "/usr/local/bin/wazuh-passwords-tool.sh"
)

const configFile = ".delphi.json"

// Config represents the configuration stored in delphi.json
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
