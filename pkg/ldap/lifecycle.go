/* pkg/ldap/lifecycle.go */

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func deleteUser(dn string, config *LDAPConfig) error {
	conn, err := ConnectWithGivenConfig(config)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf(" Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	del := ldap.NewDelRequest(dn, nil)
	if err := conn.Del(del); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func deleteGroup(dn string, config *LDAPConfig) error {
	conn, err := ConnectWithGivenConfig(config)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf(" Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	del := ldap.NewDelRequest(dn, nil)
	if err := conn.Del(del); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}
