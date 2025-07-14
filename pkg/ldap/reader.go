// pkg/ldap/reader.go

package ldap

import (
	"errors"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/go-ldap/ldap/v3"
)

// --- Read helpers ---

func readUser(rc *eos_io.RuntimeContext) ([]LDAPUser, error) {
	return readUsersWithFilter(rc, "(objectClass=inetOrgPerson)")
}

func readGroup(rc *eos_io.RuntimeContext) ([]LDAPGroup, error) {
	return readGroupsWithFilter(rc, "(objectClass=groupOfNames)")
}

func readUsersWithFilter(rc *eos_io.RuntimeContext, filter string) ([]LDAPUser, error) {
	cfg, _, err := ReadConfig(rc)
	if err != nil {
		return nil, err
	}
	return readAndMapUsers(rc, cfg.UserBase, filter)
}

func readGroupsWithFilter(rc *eos_io.RuntimeContext, filter string) ([]LDAPGroup, error) {
	cfg, _, err := ReadConfig(rc)
	if err != nil {
		return nil, err
	}
	return readAndMapGroups(rc, cfg.RoleBase, filter)
}

func readUserByUID(rc *eos_io.RuntimeContext, uid string) (*LDAPUser, error) {
	results, err := readAndMapUsers(rc, defaultBaseDN, fmt.Sprintf("(uid=%s)", uid))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no user found with uid=%s", uid)
	}
	return &results[0], nil
}

func readGroupByCN(rc *eos_io.RuntimeContext, cn string) (*LDAPGroup, error) {
	results, err := readAndMapGroups(rc, defaultBaseDN, fmt.Sprintf("(cn=%s)", cn))
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
func readAndMapUsers(rc *eos_io.RuntimeContext, baseDN, filter string) ([]LDAPUser, error) {
	conn, err := Connect(rc)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("Warning: failed to close LDAP connection: %v\n", cerr)
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

func readAndMapGroups(rc *eos_io.RuntimeContext, baseDN, filter string) ([]LDAPGroup, error) {
	conn, err := Connect(rc)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			fmt.Printf("Warning: failed to close LDAP connection: %v\n", cerr)
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

func ReadConfig(rc *eos_io.RuntimeContext) (*LDAPConfig, string, error) {
	loaders := []struct {
		name string
		load func() (*LDAPConfig, error)
	}{
		{"vault", func() (*LDAPConfig, error) {
			return readFromVault(rc)
		}},
		{"env", func() (*LDAPConfig, error) {
			return loadFromEnv(rc)
		}},
		{"host", func() (*LDAPConfig, error) {
			return tryDetectFromHost(rc)
		}},
		{"container", func() (*LDAPConfig, error) {
			return tryDetectFromContainer(rc)
		}},
		{"prompt", func() (*LDAPConfig, error) {
			return loadFromPrompt(rc)
		}},
	}

	for _, source := range loaders {
		if cfg, err := source.load(); err == nil && cfg.FQDN != "" {
			fmt.Printf(" LDAP config loaded from %s: %s\n", source.name, cfg.FQDN)
			return cfg, source.name, nil
		}
	}

	// Fallback
	cfg := DefaultLDAPConfig()
	fmt.Printf(" Using fallback LDAP config: %s\n", cfg.FQDN)
	return cfg, "default", nil
}

func readFromVault(rc *eos_io.RuntimeContext) (*LDAPConfig, error) {
	var cfg LDAPConfig
	if err := vault.ReadFromVault(rc, "ldap", &cfg); err != nil || cfg.FQDN == "" {
		return nil, errors.New("LDAP config not found in Vault")
	}
	return &cfg, nil
}
