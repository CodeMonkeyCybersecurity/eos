// pkg/ldap/list.go

package ldap

import (
	"github.com/go-ldap/ldap/v3"
)

func ListUsers() ([]LDAPUser, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cfg, err := LoadLDAPConfig()
	if err != nil {
		return nil, err
	}

	filter := "(objectClass=inetOrgPerson)"
	attrs := []string{"uid", "dn"}

	req := ldap.NewSearchRequest(
		cfg.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	var users []LDAPUser
	for _, entry := range res.Entries {
		users = append(users, LDAPUser{
			UID: entry.GetAttributeValue("uid"),
			DN:  entry.DN,
		})
	}
	return users, nil
}

func ListGroups() ([]LDAPGroup, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cfg, err := LoadLDAPConfig()
	if err != nil {
		return nil, err
	}

	filter := "(objectClass=groupOfNames)"
	attrs := []string{"cn", "member"}

	req := ldap.NewSearchRequest(
		cfg.RoleBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	var groups []LDAPGroup
	for _, entry := range res.Entries {
		groups = append(groups, LDAPGroup{
			CN:      entry.GetAttributeValue("cn"),
			Members: entry.GetAttributeValues("member"),
		})
	}
	return groups, nil
}
