/* pkg/ldap/delete.go */

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// DeleteUser removes a user from LDAP
func deleteUser(dn string, config *LDAPConfig) error {
	conn, err := ConnectWithGivenConfig(config)
	if err != nil {
		return err
	}
	defer conn.Close()

	del := ldap.NewDelRequest(dn, nil)
	if err := conn.Del(del); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// DeleteGroup removes a group entry by DN
func deleteGroup(dn string, config *LDAPConfig) error {
	conn, err := ConnectWithGivenConfig(config)
	if err != nil {
		return err
	}
	defer conn.Close()

	del := ldap.NewDelRequest(dn, nil)
	if err := conn.Del(del); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}
