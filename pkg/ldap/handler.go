/* pkg/ldap/helper.go */

package ldap

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

func InteractiveLDAPQuery() error {
	// Prompts
	proto := interaction.PromptInput("Connection type [ldap, ldaps, ldapi]", "ldap")
	host := interaction.PromptInput("LDAP host or IP", "localhost")
	bindDN := interaction.PromptInput("Bind DN (e.g. cn=admin,dc=domain,dc=com)", "")
	password, err := interaction.PromptPassword("LDAP password")
	if err != nil {
		return err
	}
	baseDN := interaction.PromptInput("Search base DN", "e.g. ou=Users,dc=domain,dc=com (leave blank to search entire tree)")
	if baseDN == "" {
		fmt.Println("⚠️  No base DN provided — defaulting to root (searching entire tree).")
		fmt.Println("   This may return a large number of entries and be slower than expected.")
		baseDN = ""
	}

	filter := interaction.PromptInput("Search filter", "(objectClass=*)")
	attrLine := interaction.PromptInput("Attributes (comma-separated, or leave blank for all)", "")
	attrs := strings.FieldsFunc(attrLine, func(r rune) bool { return r == ',' || r == ' ' })

	// Build URI
	uri := proto + "://" + host

	// Build args
	maxResultsStr := strconv.Itoa(MaxResults) // from ldap/flags.go
	args := []string{"-x", "-H", uri, "-D", bindDN, "-w", password, "-b", baseDN, "-z", maxResultsStr, filter}
	args = append(args, attrs...)

	// Show and run
	fmt.Println("\n➡️  Running:", "ldapsearch", strings.Join(args, " "))
	cmd := exec.Command("ldapsearch", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
