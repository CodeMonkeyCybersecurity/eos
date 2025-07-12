/* pkg/ldap/ldap.go */

package ldap

// TODO: Add LDAP injection protection and input validation functions
// - constructLDAPFilter: Build filters with proper escaping per RFC 4515
// - validateLDAPFilter: Validate filter syntax and detect injection patterns
// - escapeLDAPAttribute: Escape special chars (*, (, ), \, null) in search filters
// - escapeLDAPDN: Escape DN components per RFC 4514
// - validateLDAPCredentials: Validate usernames/passwords for LDAP operations
// See pkg/ldap/ldap_fuzz_test.go for comprehensive injection attack testing

var (
	DeleteGroup          = deleteGroup
	DeleteUser           = deleteUser
	UpdateUserAttributes = updateUserAttributes
	AddUserToGroup       = addUserToGroup
	RemoveUserFromGroup  = removeUserFromGroup
	PrintUser            = printUser
	PrintGroup           = printGroup
	RunLDAPAuthProbe     = runLDAPAuthProbe
	RunLDAPProbe         = runLDAPProbe
	ReadUser             = readUser
	ReadGroup            = readGroup
	CreateUser           = createUser
	CreateGroup          = createGroup
)
