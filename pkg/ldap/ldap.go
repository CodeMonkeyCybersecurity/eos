/* pkg/ldap/ldap.go */

package ldap

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
	PromptLDAPDetails    = promptLDAPDetails
)
