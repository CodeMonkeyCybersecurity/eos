// pkg/vault/ldap.go
package vault

// RememberFQDN prompts for the LDAP FQDN and stores it
func RememberFQDN() (string, error) {
	return RememberedPrompt(
		"ldap",
		"fqdn",
		"Enter the LDAP server FQDN (e.g. ldap.domain.com):",
		"ldap.domain.com",
	)
}

// RememberBindDN prompts for the LDAP Bind DN and stores it
func RememberBindDN() (string, error) {
	return RememberedPrompt(
		"ldap",
		"bind_dn",
		"Enter the LDAP Bind DN (e.g. cn=admin,dc=domain,dc=com):",
		"cn=admin,dc=domain,dc=com",
	)
}

// RememberPassword prompts for the LDAP password and stores it securely
func RememberPassword() (string, error) {
	return RememberedPrompt(
		"ldap",
		"password",
		"Enter the LDAP bind password:",
		"",
	)
}

// RememberUserBase prompts for user base DN
func RememberUserBase() (string, error) {
	return RememberedPrompt(
		"ldap",
		"user_base",
		"Enter the LDAP User Base DN (e.g. ou=Users,dc=domain,dc=com):",
		"ou=Users,dc=domain,dc=com",
	)
}

// RememberGroupBase prompts for group base DN
func RememberGroupBase() (string, error) {
	return RememberedPrompt(
		"ldap",
		"group_base",
		"Enter the LDAP Group Base DN (e.g. ou=Groups,dc=domain,dc=com):",
		"ou=Groups,dc=domain,dc=com",
	)
}

// RememberAdminRole prompts for the admin role CN
func RememberAdminRole() (string, error) {
	return RememberedPrompt(
		"ldap",
		"admin_role",
		"Enter the LDAP Admin Role CN:",
		"AdminRole",
	)
}

// RememberReadonlyRole prompts for the readonly role CN
func RememberReadonlyRole() (string, error) {
	return RememberedPrompt(
		"ldap",
		"readonly_role",
		"Enter the LDAP Readonly Role CN:",
		"ReadonlyRole",
	)
}
