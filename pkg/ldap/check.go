package ldap

import "fmt"

// TestConnection attempts a bind to verify the LDAP connection works.
func CheckConnection(cfg *LDAPConfig) error {
	conn, err := ConnectWithGivenConfig(cfg)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer conn.Close()

	return nil
}
