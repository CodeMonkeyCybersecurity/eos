// pkg/ldap/connect.go

package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// Connect returns an LDAP connection using environment or Vault-backed config
func Connect() (*ldap.Conn, error) {
	// TODO: Replace hardcoded values with vault/config-driven input
	addr := "ldap://localhost:389"
	bindDN := "cn=admin,dc=cybermonkey,dc=dev"
	password := "Zesty7*Bullish3%Frosted9*Unnamable3"

	conn, err := ldap.DialURL(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	if err := conn.Bind(bindDN, password); err != nil {
		return nil, fmt.Errorf("LDAP bind failed: %w", err)
	}
	return conn, nil
}
