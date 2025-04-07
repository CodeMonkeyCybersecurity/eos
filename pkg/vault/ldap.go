// pkg/vault/ldap.go
package vault

// rememberLDAPField prompts for a remembered value stored under the "ldap" path.
func rememberLDAPField(key, prompt, def string) (string, error) {
	return rememberedPrompt("ldap", key, prompt, def)
}

// LDAP field prompts
func RememberFQDN() (string, error) {
	return rememberLDAPField("fqdn", "Enter the LDAP server FQDN (e.g. ldap.domain.com):", "ldap.domain.com")
}

func RememberBindDN() (string, error) {
	return rememberLDAPField("bind_dn", "Enter the LDAP Bind DN (e.g. cn=admin,dc=domain,dc=com):", "cn=admin,dc=domain,dc=com")
}

func RememberPassword() (string, error) {
	return rememberLDAPField("password", "Enter the LDAP bind password:", "")
}

func RememberUserBase() (string, error) {
	return rememberLDAPField("user_base", "Enter the LDAP User Base DN (e.g. ou=Users,dc=domain,dc=com):", "ou=Users,dc=domain,dc=com")
}

func RememberGroupBase() (string, error) {
	return rememberLDAPField("group_base", "Enter the LDAP Group Base DN (e.g. ou=Groups,dc=domain,dc=com):", "ou=Groups,dc=domain,dc=com")
}

func RememberAdminRole() (string, error) {
	return rememberLDAPField("admin_role", "Enter the LDAP Admin Role CN:", "AdminRole")
}

func RememberReadonlyRole() (string, error) {
	return rememberLDAPField("readonly_role", "Enter the LDAP Readonly Role CN:", "ReadonlyRole")
}
