// pkg/ldap/reader.go

package ldap

import (
	"errors"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/go-ldap/ldap/v3"
)

// --- Read helpers ---

func readUser() ([]LDAPUser, error) {
	return readUsersWithFilter("(objectClass=inetOrgPerson)")
}

func readGroup() ([]LDAPGroup, error) {
	return readGroupsWithFilter("(objectClass=groupOfNames)")
}

func readUsersWithFilter(filter string) ([]LDAPUser, error) {
	cfg, _, err := ReadConfig()
	if err != nil {
		return nil, err
	}
	return readAndMapUsers(cfg.UserBase, filter)
}

func readGroupsWithFilter(filter string) ([]LDAPGroup, error) {
	cfg, _, err := ReadConfig()
	if err != nil {
		return nil, err
	}
	return readAndMapGroups(cfg.RoleBase, filter)
}

func readUserByUID(uid string) (*LDAPUser, error) {
	results, err := readAndMapUsers(defaultBaseDN, fmt.Sprintf("(uid=%s)", uid))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no user found with uid=%s", uid)
	}
	return &results[0], nil
}

func readGroupByCN(cn string) (*LDAPGroup, error) {
	results, err := readAndMapGroups(defaultBaseDN, fmt.Sprintf("(cn=%s)", cn))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no group found with cn=%s", cn)
	}
	return &results[0], nil
}

// --- Internal mappers ---

// readAndMapUsers performs an LDAP search and maps results to LDAPUser structs.
func readAndMapUsers(baseDN, filter string) ([]LDAPUser, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"uid", "cn", "mail", "dn"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	users := make([]LDAPUser, 0, len(res.Entries))
	for _, e := range res.Entries {
		users = append(users, LDAPUser{
			UID:  e.GetAttributeValue("uid"),
			CN:   e.GetAttributeValue("cn"),
			Mail: e.GetAttributeValue("mail"),
			DN:   e.DN,
		})
	}
	return users, nil
}

func readAndMapGroups(baseDN, filter string) ([]LDAPGroup, error) {
	conn, err := Connect()
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close LDAP connection: %v\n", cerr)
		}
	}()

	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"cn", "member"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	groups := make([]LDAPGroup, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, LDAPGroup{
			CN:      e.GetAttributeValue("cn"),
			Members: e.GetAttributeValues("member"),
		})
	}
	return groups, nil
}

func ReadConfig() (*LDAPConfig, string, error) {
	loaders := []struct {
		name string
		load func() (*LDAPConfig, error)
	}{
		{"vault", func() (*LDAPConfig, error) {
			return readFromVault()
		}},
		{"env", func() (*LDAPConfig, error) {
			return loadFromEnv()
		}},
		{"host", func() (*LDAPConfig, error) {
			return tryDetectFromHost()
		}},
		{"container", func() (*LDAPConfig, error) {
			return tryDetectFromContainer()
		}},
		{"prompt", func() (*LDAPConfig, error) {
			return loadFromPrompt()
		}},
	}

	for _, source := range loaders {
		if cfg, err := source.load(); err == nil && cfg.FQDN != "" {
			fmt.Printf("✅ LDAP config loaded from %s: %s\n", source.name, cfg.FQDN)
			return cfg, source.name, nil
		}
	}

	// Fallback
	cfg := DefaultLDAPConfig()
	fmt.Printf("⚠️  Using fallback LDAP config: %s\n", cfg.FQDN)
	return cfg, "default", nil
}

func readFromVault() (*LDAPConfig, error) {
	client, err := vault.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	var cfg LDAPConfig
	if err := vault.Read(client, "ldap", cfg); err != nil || cfg.FQDN == "" {
		return nil, errors.New("LDAP config not found in Vault")
	}
	return &cfg, nil
}
