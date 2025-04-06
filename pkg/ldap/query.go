// pkg/ldap/types.go

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// PrintUsers displays LDAP users in a user-friendly format
func PrintUsers() error {
	users, err := ListUsers()
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}
	for _, user := range users {
		fmt.Println("👤", user.UID, "-", user.DN)
	}
	return nil
}

func GetUserByUID(uid string) (*LDAPUser, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	baseDN := "ou=Users,dc=cybermonkey,dc=dev"
	filter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(uid))
	attrs := []string{"dn", "uid"}

	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		attrs,
		nil,
	))
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", uid)
	}

	entry := res.Entries[0]
	return &LDAPUser{
		UID: uid,
		DN:  entry.DN,
	}, nil
}

// PrintGroups displays LDAP groups and their members
func PrintGroups() error {
	groups, err := ListGroups()
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}
	for _, group := range groups {
		fmt.Println("🛡️", group.CN, "→ Members:", group.Members)
	}
	return nil
}

func GetGroupByCN(cn string) (*LDAPGroup, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	baseDN := "ou=Groups,dc=domain,dc=com"
	filter := fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(cn))
	attrs := []string{"cn", "member"}

	res, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		attrs,
		nil,
	))
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("group %s not found", cn)
	}

	entry := res.Entries[0]
	members := entry.GetAttributeValues("member")

	return &LDAPGroup{
		CN:      cn,
		DN:      entry.DN,
		Members: members,
	}, nil
}
