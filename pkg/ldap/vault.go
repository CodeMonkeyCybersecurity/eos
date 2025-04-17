/* pkg/ldap/vault.go */

package ldap

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"go.uber.org/zap"
)

// rememberLDAPField prompts for a remembered value stored under the "ldap" path.
func rememberLDAPField(key, prompt, def string, log *zap.Logger) (string, error) {
	return vault.Remember("ldap", key, prompt, def, log)
}

// LDAP field prompts
func RememberFQDN(log *zap.Logger) (string, error) {
	return rememberLDAPField("fqdn", "Enter the LDAP server FQDN (e.g. ldap.domain.com):", "ldap.domain.com", log)
}

func RememberBindDN(log *zap.Logger) (string, error) {
	return rememberLDAPField("bind_dn", "Enter the LDAP Bind DN (e.g. cn=admin,dc=domain,dc=com):", "cn=admin,dc=domain,dc=com", log)
}

func RememberPassword(log *zap.Logger) (string, error) {
	return rememberLDAPField("password", "Enter the LDAP bind password:", "", log)
}

func RememberUserBase(log *zap.Logger) (string, error) {
	return rememberLDAPField("user_base", "Enter the LDAP User Base DN (e.g. ou=Users,dc=domain,dc=com):", "ou=Users,dc=domain,dc=com", log)
}

func RememberGroupBase(log *zap.Logger) (string, error) {
	return rememberLDAPField("group_base", "Enter the LDAP Group Base DN (e.g. ou=Groups,dc=domain,dc=com):", "ou=Groups,dc=domain,dc=com", log)
}

func RememberAdminRole(log *zap.Logger) (string, error) {
	return rememberLDAPField("admin_role", "Enter the LDAP Admin Role CN:", "AdminRole", log)
}

func RememberReadonlyRole(log *zap.Logger) (string, error) {
	return rememberLDAPField("readonly_role", "Enter the LDAP Readonly Role CN:", "ReadonlyRole", log)
}
