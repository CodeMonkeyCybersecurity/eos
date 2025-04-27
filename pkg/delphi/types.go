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
	VaultDelphiCreds     = "eos/delphi/api_creds"
	VaultDelphiConfig    = "eos/delphi/config"
	DelphiPasswdToolURL  = "https://packages.wazuh.com/4.11/wazuh-passwords-tool.sh"
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
