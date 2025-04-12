/* pkg/ldap/helper.go */

package ldap

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

func InteractiveLDAPQuery() error {
	cfg := &LDAPConfig{}

	// Try to load existing config from Vault to prefill
	_ = vault.ReadFromVaultAt(context.Background(), consts.LDAPVaultMount, consts.LDAPVaultPath, cfg)

	// Prompts
	proto := interaction.PromptInput("Connection type [ldap, ldaps, ldapi]", "ldap")
	host := interaction.PromptInput("LDAP host or IP", cfg.FQDN)
	bindDN := interaction.PromptInput("Bind DN (e.g. cn=admin,dc=domain,dc=com)", cfg.BindDN)
	if bindDN == "" {
		fmt.Println("⚠️  No BindDN provided — defaulting to cn=anonymous instead.")
		bindDN = "cn=anonymous"
	}
	password, err := interaction.PromptPassword("LDAP password")
	if password == "" {
		fmt.Println("⚠️  No password provided — binding may fail if anonymous access is not allowed.")
		password = `""`
	}
	if err != nil {
		return err
	}

	fmt.Println("Search base DN (e.g. ou=Users,dc=domain,dc=com). Leave blank to search entire tree.")
	baseDN := interaction.PromptInput("Search base DN", cfg.UserBase)
	if baseDN == "" {
		fmt.Println("⚠️  No base DN provided — defaulting to root (searching entire tree).")
		fmt.Println("⚠️  This may return a large number of entries and be slower than expected.")
		baseDN = `""`
	}

	filter := interaction.PromptInput("Search filter", "(objectClass=*)")
	attrLine := interaction.PromptInput("Attributes (comma-separated, or leave blank for all)", "")
	attrs := strings.FieldsFunc(attrLine, func(r rune) bool { return r == ',' || r == ' ' })

	// Save values into cfg
	cfg.FQDN = host
	cfg.BindDN = bindDN
	cfg.Password = password
	cfg.UserBase = baseDN

	// Save config to Vault
	if err := vault.WriteToVault(consts.LDAPVaultPath, cfg); err != nil {
		fmt.Printf("⚠️  Warning: failed to save LDAP config to Vault: %v\n", err)
	}

	// Build URI and args
	uri := proto + "://" + host
	maxResultsStr := strconv.Itoa(MaxResults) // from ldap/flags.go
	args := []string{"-x", "-H", uri, "-D", bindDN, "-w", password, "-b", baseDN, "-z", maxResultsStr, filter}
	args = append(args, attrs...)

	fmt.Println("\n➡️  Running:", "ldapsearch", strings.Join(args, " "))
	cmd := exec.Command("ldapsearch", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
