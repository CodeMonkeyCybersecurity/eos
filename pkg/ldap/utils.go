// pkg/ldap/utils.go

package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ExtractCN returns the CN portion from a DN string
func ExtractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if strings.HasPrefix(part, "cn=") {
			return strings.TrimPrefix(part, "cn=")
		}
	}
	return ""
}

// ExtractUID returns the UID portion from a DN string
func ExtractUID(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if strings.HasPrefix(part, "uid=") {
			return strings.TrimPrefix(part, "uid=")
		}
	}
	return ""
}

// NormalizeDN ensures a DN is lowercased and trimmed
func NormalizeDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}

func ConnectWithConfig(cfg *LDAPConfig) (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", cfg.FQDN, cfg.Port)

	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		conn, err = ldap.DialTLS("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	err = conn.Bind(cfg.BindDN, cfg.Password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	return conn, nil
}
