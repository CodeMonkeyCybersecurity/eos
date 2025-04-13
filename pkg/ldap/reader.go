// pkg/ldap/reader.go

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// --- Read helpers ---

func readUser() ([]LDAPUser, error) {
	cfg, _, err := LoadLDAPConfig()
	if err != nil {
		return nil, err
	}

	return searchAndMapUsers(cfg.UserBase, "(objectClass=inetOrgPerson)")
}

func readGroup() ([]LDAPGroup, error) {
	cfg, _, err := LoadLDAPConfig()
	if err != nil {
		return nil, err
	}

	return searchAndMapGroups(cfg.RoleBase, "(objectClass=groupOfNames)")
}

func getUserByUID(uid string) (*LDAPUser, error) {
	results, err := searchAndMapUsers(defaultBaseDN, fmt.Sprintf("(uid=%s)", uid))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no user found with uid=%s", uid)
	}
	return &results[0], nil
}

func getGroupByCN(cn string) (*LDAPGroup, error) {
	results, err := searchAndMapGroups(defaultBaseDN, fmt.Sprintf("(cn=%s)", cn))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no group found with cn=%s", cn)
	}
	return &results[0], nil
}

// --- Internal mappers ---

// searchAndMapUsers performs an LDAP search and maps results to LDAPUser structs.
func searchAndMapUsers(baseDN, filter string) ([]LDAPUser, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"uid", "cn", "mail", "dn"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	users := make([]LDAPUser, 0, len(res.Entries))
	for _, e := range res.Entries {
		users = append(users, LDAPUser{
			UID:  e.GetAttributeValue("uid"),
			CN:   e.GetAttributeValue("cn"),
			Mail: e.GetAttributeValue("mail"),
			DN:   e.DN,
		})
	}
	return users, nil
}

func searchAndMapGroups(baseDN, filter string) ([]LDAPGroup, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"cn", "member"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	groups := make([]LDAPGroup, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, LDAPGroup{
			CN:      e.GetAttributeValue("cn"),
			Members: e.GetAttributeValues("member"),
		})
	}
	return groups, nil
}
