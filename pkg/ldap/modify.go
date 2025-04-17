// pkg/ldap/modify.go

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// UpdateUserAttributes updates one or more attributes for a given user UID
func updateUserAttributes(uid string, attrs map[string][]string, log *zap.Logger) error {
	conn, err := Connect(log)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Failed to close LDAP connection: %v\n", cerr)
		}
	}()

	user, err := readUserByUID(uid, log)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	req := ldap.NewModifyRequest(user.DN, nil)
	for attr, values := range attrs {
		req.Replace(attr, values)
	}

	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("failed to modify user: %w", err)
	}
	return nil
}

// AddUserToGroup adds a user to an LDAP group
func addUserToGroup(uid, groupCN string, log *zap.Logger) error {
	conn, err := Connect(log)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Failed to close LDAP connection: %v\n", cerr)
		}
	}()

	user, err := readUserByUID(uid, log)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	group, err := readGroupByCN(groupCN, log)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	req := ldap.NewModifyRequest(group.DN, nil)
	req.Add("member", []string{user.DN})

	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from an LDAP group
func removeUserFromGroup(uid, groupCN string, log *zap.Logger) error {
	conn, err := Connect(log)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Failed to close LDAP connection: %v\n", cerr)
		}
	}()

	user, err := readUserByUID(uid, log)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	group, err := readGroupByCN(groupCN, log)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	req := ldap.NewModifyRequest(group.DN, nil)
	req.Delete("member", []string{user.DN})

	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}
	return nil
}
