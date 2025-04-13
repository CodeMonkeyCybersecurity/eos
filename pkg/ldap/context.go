/* pkg/ldap/config.go */
package ldap

import (
	"errors"
	"os"
)

func loadFromEnv() (*LDAPConfig, error) {
	fqdn := os.Getenv("LDAP_FQDN")
	if fqdn == "" {
		return nil, errors.New("LDAP_FQDN not set")
	}

	return &LDAPConfig{
		FQDN:         fqdn,
		Port:         389, // optionally support LDAP_PORT env
		UseTLS:       false,
		BindDN:       os.Getenv("LDAP_BIND_DN"),
		Password:     os.Getenv("LDAP_PASSWORD"),
		UserBase:     os.Getenv("LDAP_USER_BASE"),
		RoleBase:     os.Getenv("LDAP_GROUP_BASE"),
		AdminRole:    os.Getenv("LDAP_ADMIN_ROLE"),
		ReadonlyRole: os.Getenv("LDAP_READONLY_ROLE"),
	}, nil
}

func tryDetectFromHost() (*LDAPConfig, error) {
	cfg := TryDetectFromHost()
	if cfg == nil {
		return nil, errors.New("host detection failed")
	}
	return cfg, nil
}

func tryDetectFromContainer() (*LDAPConfig, error) {
	cfg := TryDetectFromContainer()
	if cfg == nil {
		return nil, errors.New("container detection failed")
	}
	return cfg, nil
}
