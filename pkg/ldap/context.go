/* pkg/ldap/config.go */
package ldap

import (
	"errors"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func loadFromEnv(rc *eos_io.RuntimeContext) (*LDAPConfig, error) {
	otelzap.Ctx(rc.Ctx).Debug(" Attempting to load LDAP config from environment variables")

	fqdn := os.Getenv("LDAP_FQDN")
	if fqdn == "" {
		otelzap.Ctx(rc.Ctx).Warn(" LDAP_FQDN environment variable not set")
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

	otelzap.Ctx(rc.Ctx).Info(" LDAP config loaded from environment", zap.String("fqdn", cfg.FQDN))
	return cfg, nil
}

func tryDetectFromHost(rc *eos_io.RuntimeContext) (*LDAPConfig, error) {
	otelzap.Ctx(rc.Ctx).Debug(" Attempting to detect LDAP config from host environment")

	cfg := TryDetectFromHost()
	if cfg == nil {
		otelzap.Ctx(rc.Ctx).Warn(" Host-based LDAP detection failed")
		return nil, errors.New("host detection failed")
	}

	otelzap.Ctx(rc.Ctx).Info(" Host-based LDAP config detected", zap.String("fqdn", cfg.FQDN))
	return cfg, nil
}

func tryDetectFromContainer(rc *eos_io.RuntimeContext) (*LDAPConfig, error) {
	otelzap.Ctx(rc.Ctx).Debug(" Attempting to detect LDAP config from container environment")

	cfg := TryDetectFromContainer()
	if cfg == nil {
		otelzap.Ctx(rc.Ctx).Warn(" Container-based LDAP detection failed")
		return nil, errors.New("container detection failed")
	}

	otelzap.Ctx(rc.Ctx).Info(" Container-based LDAP config detected", zap.String("fqdn", cfg.FQDN))
	return cfg, nil
}
