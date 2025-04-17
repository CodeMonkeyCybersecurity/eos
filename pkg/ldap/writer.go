/* pkg/ldap/write.go */

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// AddUser creates a new LDAP user entry
func createUser(config *LDAPConfig, user LDAPUser, password string, log *zap.Logger) error {
	conn, err := ConnectWithGivenConfig(config, log)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	req := ldap.NewAddRequest(user.DN, nil)
	req.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
	req.Attribute("uid", []string{user.UID})
	req.Attribute("sn", []string{user.UID}) // Required field
	req.Attribute("cn", []string{user.UID})
	req.Attribute("userPassword", []string{password})

	if err := conn.Add(req); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}
	return nil
}

// CreateGroup adds a new LDAP group (groupOfNames) with no members yet
func createGroup(config *LDAPConfig, group LDAPGroup, log *zap.Logger) error {
	conn, err := ConnectWithGivenConfig(config, log)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := ldap.NewAddRequest(group.DN, nil)
	req.Attribute("objectClass", []string{"groupOfNames", "top"})
	req.Attribute("cn", []string{group.CN})

	// groupOfNames requires at least one member
	if len(group.Members) == 0 {
		// fallback to a placeholder DN (can be cleaned later)
		req.Attribute("member", []string{"cn=dummy,dc=example,dc=com"})
	} else {
		req.Attribute("member", group.Members)
	}

	if err := conn.Add(req); err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	return nil
}
