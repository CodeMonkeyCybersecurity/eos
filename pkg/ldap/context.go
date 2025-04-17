/* pkg/ldap/config.go */
package ldap

import (
	"errors"
	"os"

	"go.uber.org/zap"
)

func loadFromEnv(log *zap.Logger) (*LDAPConfig, error) {
	log.Debug("🔍 Attempting to load LDAP config from environment variables")

	fqdn := os.Getenv("LDAP_FQDN")
	if fqdn == "" {
		log.Warn("❌ LDAP_FQDN environment variable not set")
		return nil, errors.New("LDAP_FQDN not set")
	}

	cfg := &LDAPConfig{
		FQDN:         fqdn,
		Port:         389, // optionally support LDAP_PORT env in future
		UseTLS:       false,
		BindDN:       os.Getenv("LDAP_BIND_DN"),
		Password:     os.Getenv("LDAP_PASSWORD"),
		UserBase:     os.Getenv("LDAP_USER_BASE"),
		RoleBase:     os.Getenv("LDAP_GROUP_BASE"),
		AdminRole:    os.Getenv("LDAP_ADMIN_ROLE"),
		ReadonlyRole: os.Getenv("LDAP_READONLY_ROLE"),
	}

	log.Info("✅ LDAP config loaded from environment", zap.String("fqdn", cfg.FQDN))
	return cfg, nil
}

func tryDetectFromHost(log *zap.Logger) (*LDAPConfig, error) {
	log.Debug("🔍 Attempting to detect LDAP config from host environment")

	cfg := TryDetectFromHost(log)
	if cfg == nil {
		log.Warn("❌ Host-based LDAP detection failed")
		return nil, errors.New("host detection failed")
	}

	log.Info("✅ Host-based LDAP config detected", zap.String("fqdn", cfg.FQDN))
	return cfg, nil
}

func tryDetectFromContainer(log *zap.Logger) (*LDAPConfig, error) {
	log.Debug("🔍 Attempting to detect LDAP config from container environment")

	cfg := TryDetectFromContainer()
	if cfg == nil {
		log.Warn("❌ Container-based LDAP detection failed")
		return nil, errors.New("container detection failed")
	}

	log.Info("✅ Container-based LDAP config detected", zap.String("fqdn", cfg.FQDN))
	return cfg, nil
}
