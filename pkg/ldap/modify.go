// pkg/ldap/modify.go

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// AddUser creates a new LDAP user entry
func AddUser(config *LDAPConfig, user LDAPUser, password string) error {
	conn, err := ConnectWithGivenConfig(config)
	if err != nil {
		return err
	}
	defer conn.Close()

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

// DeleteUser removes a user from LDAP
func DeleteUser(dn string, config *LDAPConfig) error {
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

// UpdateUserAttributes updates one or more attributes for a given user UID
func UpdateUserAttributes(uid string, attrs map[string][]string) error {
	conn, err := Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	user, err := GetUserByUID(uid)
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
func AddUserToGroup(uid, groupCN string) error {
	conn, err := Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	user, err := GetUserByUID(uid)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	group, err := GetGroupByCN(groupCN)
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
func RemoveUserFromGroup(uid, groupCN string) error {
	conn, err := Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	user, err := GetUserByUID(uid)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	group, err := GetGroupByCN(groupCN)
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
