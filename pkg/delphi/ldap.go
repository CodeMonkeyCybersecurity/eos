// pkg/delphi/ldap.go

package delphi

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"gopkg.in/ldap.v3"
	"gopkg.in/yaml.v3"
)

var dryRun bool

type LDAPConfig struct {
	FQDN         string
	BindDN       string
	Password     string
	UserBase     string
	RoleBase     string
	AdminRole    string
	ReadonlyRole string
}

func PromptLDAPDetails() (*LDAPConfig, error) {
	cfg := &LDAPConfig{}
	cfg.FQDN = interaction.PromptInput("FQDN", "FQDN of your LDAP server (e.g., ldap.example.org)")
	cfg.BindDN = interaction.PromptInput("BindDN", "Bind DN (e.g., cn=admin,dc=example,dc=org)")
	var err error
	cfg.Password, err = interaction.PromptPassword("Bind password")
	if err != nil {
		return nil, fmt.Errorf("failed to get password: %w", err)
	}
	cfg.UserBase = interaction.PromptInput("UserBase", "User base DN (e.g., ou=people,dc=example,dc=org)")
	cfg.RoleBase = interaction.PromptInput("RoleBase", "Role base DN (e.g., ou=Groups,dc=example,dc=org)")
	cfg.AdminRole = interaction.PromptInput("AdminRole", "Admin group name (e.g., Administrator)")
	cfg.ReadonlyRole = interaction.PromptInput("ReadonlyRole", "Readonly group name (e.g., readonly)")

	// Validate required fields
	if cfg.FQDN == "" || cfg.BindDN == "" || cfg.Password == "" || cfg.UserBase == "" || cfg.RoleBase == "" {
		return nil, fmt.Errorf("missing required LDAP fields (FQDN, BindDN, Password, UserBase, or RoleBase)")
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

func PatchConfigYML(cfg *LDAPConfig) error {
	configPath := "/etc/wazuh-indexer/opensearch-security/config.yml"
	backupPath := configPath + ".bak"

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.yml: %w", err)
	}

	if len(raw) < 10 {
		fmt.Println("⚠️  Warning: config.yml appears to be mostly empty. Proceeding anyway.")
	}

	var root map[string]interface{}
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("failed to parse config.yml: %w", err)
	}

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

	out, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("failed to re-encode config.yml: %w", err)
	}

	if dryRun {
		fmt.Println("🧪 Dry run: changes to config.yml would look like:")
		fmt.Println(string(out))
		return nil
	}

	// Backup
	if err := os.WriteFile(backupPath, raw, 0644); err != nil {
		return fmt.Errorf("failed to write backup of config.yml: %w", err)
	}
	fmt.Printf("🧾 Backup created: %s\n", backupPath)

	if err := os.WriteFile(configPath, out, 0644); err != nil {
		return fmt.Errorf("failed to write config.yml: %w", err)
	}

	fmt.Println("✅ Patched config.yml with LDAP authc/authz blocks.")
	return nil
}

func PatchRolesMappingYML(cfg *LDAPConfig) error {
	path := "/etc/wazuh-indexer/opensearch-security/roles_mapping.yml"
	backupPath := path + ".bak"

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read roles_mapping.yml: %w", err)
	}

	var data map[string]interface{}
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("failed to parse roles_mapping.yml: %w", err)
	}

	// 🛡 Safeguard for empty or nil content
	if data == nil {
		data = make(map[string]interface{})
	}

	if len(raw) < 10 {
		fmt.Println("⚠️  Warning: roles_mapping.yml appears to be mostly empty. Proceeding anyway.")
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

	if dryRun {
		fmt.Println("🧪 Dry run: changes to roles_mapping.yml would look like:")
		fmt.Println(string(out))
		return nil
	}

	// Backup
	if err := os.WriteFile(backupPath, raw, 0644); err != nil {
		return fmt.Errorf("failed to write backup of roles_mapping.yml: %w", err)
	}
	fmt.Printf("🧾 Backup created: %s\n", backupPath)

	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("failed to write roles_mapping.yml: %w", err)
	}

	fmt.Println("✅ Patched roles_mapping.yml with admin + readonly mappings.")
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

func SetDryRun(value bool) {
	dryRun = value
}

// pkg/delphi/ldap.go (inside or near PatchConfigYML or in a new func)

func CheckLDAPGroupsExist(cfg *LDAPConfig) error {
	l, err := ldap.DialURL("ldaps://" + cfg.FQDN + ":636")
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer l.Close()

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
