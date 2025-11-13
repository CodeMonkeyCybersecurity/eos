/* pkg/ldap/types.go */

package ldap

import "github.com/CodeMonkeyCybersecurity/eos/pkg/schema"

const VaultLDAPPath = "eos/ldap/config"

type LDAPConfig struct {
	FQDN         string `yaml:"fqdn"`
	Port         int    `yaml:"port"`
	UseTLS       bool   `yaml:"use_tls"`
	BindDN       string `yaml:"bind_dn"`
	Password     string `yaml:"password"`
	UserBase     string `yaml:"user_base"`
	RoleBase     string `yaml:"role_base"`
	AdminRole    string `yaml:"admin_role"`
	ReadonlyRole string `yaml:"readonly_role"`
}

type LDAPUser struct {
	UID  string
	CN   string
	Mail string
	DN   string
}

type LDAPGroup struct {
	CN      string
	DN      string
	Members []string
}

var defaultBaseDN = "dc=domain,dc=com"

func DefaultLDAPConfig() *LDAPConfig {
	return &LDAPConfig{
		FQDN:         "localhost",
		Port:         389,
		UseTLS:       false,
		BindDN:       "cn=admin,dc=domain,dc=com",
		Password:     "",
		UserBase:     "ou=Users,dc=domain,dc=com",
		RoleBase:     "ou=Groups,dc=domain,dc=com",
		AdminRole:    "AdminRole",
		ReadonlyRole: "ReadonlyRole",
	}
}

var LDAPFieldMeta = map[string]schema.FieldMeta{
	"FQDN": {
		Label:     "FQDN",
		Help:      "FQDN of your LDAP server",
		Required:  true,
		Sensitive: false,
	},
	"BindDN": {
		Label:     "BindDN",
		Help:      "Bind DN",
		Required:  true,
		Sensitive: false,
	},
	"Password": {
		Label:     "Password",
		Help:      "Bind password",
		Required:  true,
		Sensitive: true,
	},
	"UserBase": {
		Label:     "UserBase",
		Help:      "User base DN",
		Required:  true,
		Sensitive: false,
	},
	"RoleBase": {
		Label:     "RoleBase",
		Help:      "Role base DN",
		Required:  true,
		Sensitive: false,
	},
	"AdminRole": {
		Label:     "AdminRole",
		Help:      "Admin group name",
		Required:  false,
		Sensitive: false,
	},
	"ReadonlyRole": {
		Label:     "ReadonlyRole",
		Help:      "Readonly group name",
		Required:  false,
		Sensitive: false,
	},
}
