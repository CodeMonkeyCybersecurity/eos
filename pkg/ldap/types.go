// pkg/ldap/types.go
package ldap

type LDAPConfig struct {
	FQDN         string `yaml:"fqdn"`    // e.g. ldap.cybermonkey.dev
	Port         int    `yaml:"port"`    // default: 389 or 636
	UseTLS       bool   `yaml:"use_tls"` // enable StartTLS or LDAPS
	BindDN       string `yaml:"bind_dn"`
	Password     string `yaml:"password"`
	UserBase     string `yaml:"user_base"`     // e.g. ou=Users,dc=cybermonkey,dc=dev
	RoleBase     string `yaml:"role_base"`     // e.g. ou=Groups,dc=cybermonkey,dc=dev
	AdminRole    string `yaml:"admin_role"`    // e.g. AdminRole
	ReadonlyRole string `yaml:"readonly_role"` // e.g. ReadonlyRole
}

// LDAPUser represents an LDAP user
type LDAPUser struct {
	UID string
	DN  string
}

// LDAPGroup represents an LDAP group
type LDAPGroup struct {
	CN      string
	DN      string
	Members []string
}
