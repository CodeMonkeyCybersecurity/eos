// pkg/ldap/read.go

package ldap

import (
	"fmt"
)

// PrintGroup returns detailed info for a single group by CN
func printGroup(cn string) error {
	group, err := readGroupByCN(cn)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	fmt.Printf("🛡️  %s\nMembers:\n", group.CN)
	for _, m := range group.Members {
		fmt.Println("   -", m)
	}
	return nil
}

// PrintUser returns detailed info for a single user by UID
func printUser(uid string) error {
	user, err := readUserByUID(uid)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	fmt.Printf("👤  %s (%s)\n", user.UID, user.DN)
	return nil
}
