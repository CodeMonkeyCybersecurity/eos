/* pkg/ldap/vault.go */

package ldap

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// rememberLDAPField prompts for a remembered value stored under the "ldap" path.
func rememberLDAPField(rc *eos_io.RuntimeContext, key, prompt, def string) (string, error) {
	return vault.Remember(rc, "ldap", key, prompt, def)
}

// LDAP field prompts
func RememberFQDN(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "fqdn", "Enter the LDAP server FQDN (e.g. ldap.domain.com):", "ldap.domain.com")
}

func RememberBindDN(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "bind_dn", "Enter the LDAP Bind DN (e.g. cn=admin,dc=domain,dc=com):", "cn=admin,dc=domain,dc=com")
}

func RememberPassword(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "password", "Enter the LDAP bind password:", "")
}

func RememberUserBase(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "user_base", "Enter the LDAP User Base DN (e.g. ou=Users,dc=domain,dc=com):", "ou=Users,dc=domain,dc=com")
}

func RememberGroupBase(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "group_base", "Enter the LDAP Group Base DN (e.g. ou=Groups,dc=domain,dc=com):", "ou=Groups,dc=domain,dc=com")
}

func RememberAdminRole(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "admin_role", "Enter the LDAP Admin Role CN:", "AdminRole")
}

func RememberReadonlyRole(rc *eos_io.RuntimeContext) (string, error) {
	return rememberLDAPField(rc, "readonly_role", "Enter the LDAP Readonly Role CN:", "ReadonlyRole")
}
