/* pkg/ldap/write.go */

package ldap

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/go-ldap/ldap/v3"
)

// AddUser creates a new LDAP user entry
func createUser(config *LDAPConfig, user LDAPUser, password string) error {
	conn, err := ConnectWithGivenConfig(config)
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
func createGroup(rc *eos_io.RuntimeContext, config *LDAPConfig, group LDAPGroup) error {
	conn, err := ConnectWithGivenConfig(config)
	if err != nil {
		return err
	}
	defer shared.SafeClose(rc.Ctx, conn)

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
