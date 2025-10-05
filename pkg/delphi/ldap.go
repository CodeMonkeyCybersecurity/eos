// pkg/delphi/ldap.go

package delphi

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"

	"github.com/go-ldap/ldap/v3"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func ReadLDAPConfig(rc *eos_io.RuntimeContext) (*LDAPConfig, error) {
	var cfg LDAPConfig
	err := vault.ReadFromVault(rc, shared.LDAPVaultPath, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func PromptLDAPDetails(rc *eos_io.RuntimeContext) (*LDAPConfig, error) {
	existing, _ := ReadLDAPConfig(rc) // best-effort load

	cfg := existing
	if cfg == nil {
		cfg = &LDAPConfig{}
	}

	// Prompt only if missing
	if cfg.FQDN == "" {
		cfg.FQDN = interaction.PromptInput(rc.Ctx, "FQDN", "FQDN of your LDAP server")
	}
	if cfg.BindDN == "" {
		cfg.BindDN = interaction.PromptInput(rc.Ctx, "BindDN", "Bind DN")
	}
	if cfg.Password == "" {
		var err error
		cfg.Password, err = crypto.PromptPassword(rc, "Bind password")
		if err != nil {
			return nil, err
		}
	}

	cfg.UserBase = interaction.PromptInput(rc.Ctx, "UserBase", "User base DN (e.g., ou=people,dc=example,dc=org)")
	cfg.RoleBase = interaction.PromptInput(rc.Ctx, "RoleBase", "Role base DN (e.g., ou=Groups,dc=example,dc=org)")
	cfg.AdminRole = interaction.PromptInput(rc.Ctx, "AdminRole", "Admin group name (e.g., Administrator)")
	cfg.ReadonlyRole = interaction.PromptInput(rc.Ctx, "ReadonlyRole", "Readonly group name (e.g., readonly)")

	// Validate required fields
	if cfg.FQDN == "" || cfg.BindDN == "" || cfg.Password == "" || cfg.UserBase == "" || cfg.RoleBase == "" {
		return nil, fmt.Errorf("missing required LDAP fields (FQDN, BindDN, Password, UserBase, or RoleBase)")
	}

	//  Save to Vault
	if err := vault.WriteToVault(rc, shared.LDAPVaultPath, cfg); err != nil {
		fmt.Printf(" Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	return cfg, nil
}

func DownloadAndPlaceCert(fqdn string) error {

	cmd := exec.Command("bash", "-c", fmt.Sprintf(
		`echo -n | openssl s_client -connect %s:636 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /etc/wazuh-indexer/opensearch-security/ldapcacert.pem`,
		fqdn,
	))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func PatchConfigYML(rc *eos_io.RuntimeContext, cfg *LDAPConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	configPath := "/etc/wazuh-indexer/opensearch-security/config.yml"
	backupPath := configPath + ".bak"

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.yml: %w", err)
	}

	if len(raw) < 10 {
		logger.Warn("config.yml appears to be mostly empty, proceeding anyway",
			zap.String("path", configPath),
			zap.Int("size_bytes", len(raw)))
	}

	var root map[string]interface{}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("failed to parse config.yml: %w", err)
	}

	// Build authc block
	ldapAuthc := map[string]interface{}{
		"description":       "Authenticate via LDAP or Active Directory",
		"http_enabled":      true,
		"transport_enabled": false,
		"order":             5,
		"http_authenticator": map[string]interface{}{
			"type":      "basic",
			"challenge": false,
		},
		"authentication_backend": map[string]interface{}{
			"type": "ldap",
			"config": map[string]interface{}{
				"enable_ssl":             true,
				"pemtrustedcas_filepath": "/etc/wazuh-indexer/opensearch-security/ldapcacert.pem",
				"enable_start_tls":       false,
				"enable_ssl_client_auth": false,
				"verify_hostnames":       true,
				"hosts":                  []string{fmt.Sprintf("%s:636", cfg.FQDN)},
				"bind_dn":                cfg.BindDN,
				"password":               cfg.Password,
				"userbase":               cfg.UserBase,
				"usersearch":             "(cn={0})",
				"username_attribute":     "cn",
			},
		},
	}

	authc, ok := root["authc"].(map[string]interface{})
	if !ok {
		authc = make(map[string]interface{})
	}
	authc["ldap"] = ldapAuthc
	root["authc"] = authc

	// Build authz block
	ldapAuthz := map[string]interface{}{
		"description":       "Authorize via LDAP or Active Directory",
		"http_enabled":      true,
		"transport_enabled": true,
		"authorization_backend": map[string]interface{}{
			"type": "ldap",
			"config": map[string]interface{}{
				"enable_ssl":             true,
				"pemtrustedcas_filepath": "/etc/wazuh-indexer/opensearch-security/ldapcacert.pem",
				"enable_start_tls":       false,
				"enable_ssl_client_auth": false,
				"verify_hostnames":       true,
				"hosts":                  []string{fmt.Sprintf("%s:636", cfg.FQDN)},
				"bind_dn":                cfg.BindDN,
				"password":               cfg.Password,
				"userbase":               cfg.UserBase,
				"usersearch":             "(cn={0})",
				"username_attribute":     "cn",
				"rolebase":               cfg.RoleBase,
				"rolesearch":             "(member={0})",
				"userrolename":           "memberof",
				"rolename":               "cn",
				"skip_users":             []string{"admin", "kibanaserver"},
			},
		},
	}

	authz, ok := root["authz"].(map[string]interface{})
	if !ok {
		authz = make(map[string]interface{})
	}
	authz["roles_from_myldap"] = ldapAuthz
	root["authz"] = authz

	// Marshal new config
	out, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("failed to re-encode config.yml: %w", err)
	}

	// Backup
	if err := os.WriteFile(backupPath, raw, 0644); err != nil {
		return fmt.Errorf("failed to write backup of config.yml: %w", err)
	}
	logger.Info("Backup created", zap.String("path", backupPath))

	// Write patched config
	if err := os.WriteFile(configPath, out, 0644); err != nil {
		return fmt.Errorf("failed to write config.yml: %w", err)
	}

	logger.Info("Patched config.yml with LDAP authc/authz blocks successfully",
		zap.String("path", configPath))
	return nil
}

func PatchRolesMappingYML(rc *eos_io.RuntimeContext, cfg *LDAPConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	path := "/etc/wazuh-indexer/opensearch-security/roles_mapping.yml"
	backupPath := path + ".bak"

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read roles_mapping.yml: %w", err)
	}

	if len(raw) < 10 {
		logger.Warn("roles_mapping.yml appears to be mostly empty, proceeding anyway",
			zap.String("path", path),
			zap.Int("size_bytes", len(raw)))
	}

	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("failed to parse roles_mapping.yml: %w", err)
	}
	// 🛡 Safeguard for empty or nil content
	if data == nil {
		data = make(map[string]interface{})
	}

	data["all_access"] = map[string]interface{}{
		"reserved":      false,
		"hidden":        false,
		"backend_roles": []string{cfg.AdminRole, "admin"},
		"description":   "Maps admin to all_access",
	}
	data["readall"] = map[string]interface{}{
		"reserved":      false,
		"hidden":        false,
		"backend_roles": []string{cfg.ReadonlyRole},
		"description":   "Maps readonly to readall",
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal roles_mapping.yml: %w", err)
	}

	// Backup
	if err := os.WriteFile(backupPath, raw, 0644); err != nil {
		return fmt.Errorf("failed to write backup of roles_mapping.yml: %w", err)
	}
	logger.Info("Backup created", zap.String("path", backupPath))

	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("failed to write roles_mapping.yml: %w", err)
	}

	logger.Info("Patched roles_mapping.yml with admin + readonly mappings successfully",
		zap.String("path", path))
	return nil
}

func RunSecurityAdmin(filename string) error {
	path := filepath.Join("/etc/wazuh-indexer/opensearch-security", filename)

	cmd := exec.Command("bash", "-c", fmt.Sprintf(
		`export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f %s -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h 127.0.0.1 -nhnv`,
		path,
	))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func RestartDashboard() error {
	cmd := exec.Command("systemctl", "restart", "wazuh-dashboard")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func CheckLDAPGroupsExist(cfg *LDAPConfig) (err error) {
	l, err := ldap.DialURL("ldaps://" + cfg.FQDN + ":636")
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer func() {
		if cerr := l.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close LDAP connection: %w", cerr)
		}
	}()

	err = l.Bind(cfg.BindDN, cfg.Password)
	if err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	groupSearch := func(groupCN string) (bool, error) {
		searchRequest := ldap.NewSearchRequest(
			cfg.RoleBase,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			fmt.Sprintf("(cn=%s)", groupCN),
			[]string{"dn"},
			nil,
		)
		sr, err := l.Search(searchRequest)
		if err != nil {
			return false, err
		}
		return len(sr.Entries) > 0, nil
	}

	adminExists, err := groupSearch(cfg.AdminRole)
	if err != nil {
		return fmt.Errorf("error searching for AdminRole group: %w", err)
	}

	readonlyExists, err := groupSearch(cfg.ReadonlyRole)
	if err != nil {
		return fmt.Errorf("error searching for ReadonlyRole group: %w", err)
	}

	if !adminExists || !readonlyExists {
		missing := []string{}
		if !adminExists {
			missing = append(missing, cfg.AdminRole)
		}
		if !readonlyExists {
			missing = append(missing, cfg.ReadonlyRole)
		}
		return fmt.Errorf("the following required groups are missing in LDAP: %v", missing)
	}

	return nil
}
