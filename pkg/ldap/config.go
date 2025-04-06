// pkg/ldap/config.go
package ldap

type LDAPConfig struct {
	FQDN         string `yaml:"fqdn"`
	BindDN       string `yaml:"bind_dn"`
	Password     string `yaml:"password"`
	UserBase     string `yaml:"user_base"`
	RoleBase     string `yaml:"role_base"`
	AdminRole    string `yaml:"admin_role"`
	ReadonlyRole string `yaml:"readonly_role"`
}
