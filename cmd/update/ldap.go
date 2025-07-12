// cmd/update/ldap.go
package update

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	ipSAN  string
	dryRun bool
)

var UpdateLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Regenerate LDAP TLS certificate with IP SAN",
	Long: `Regenerates the TLS certificate for your LDAP server, including the IP address
in the SAN field. Useful when clients (like Delphi/Wazuh) need to connect via IP.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if ipSAN == "" {
			return fmt.Errorf("--ip flag is required to set SAN IP")
		}

		// Validate IP address to prevent command injection
		if err := validateIPAddress(ipSAN); err != nil {
			return fmt.Errorf("invalid IP address: %w", err)
		}

		cmds := []string{
			"mkdir -p /etc/ldap/certs",
			fmt.Sprintf(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -subj "/CN=%s" \
  -keyout /etc/ldap/certs/ldap.key \
  -out /etc/ldap/certs/ldap.crt \
  -addext "subjectAltName = IP:%s"`, ipSAN, ipSAN),
		}

		for _, c := range cmds {
			fmt.Printf(" Executing: %s\n", c)
			if !dryRun {
				cmd := exec.Command("bash", "-c", c)
				cmd.Stdout = cmd.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to run command: %s: %w", c, err)
				}
			}
		}

		fmt.Println(" LDAP TLS certificate regenerated with IP SAN.")
		fmt.Println(" Path: /etc/ldap/certs/ldap.crt and ldap.key")
		fmt.Println("🧠 Reminder: Restart your LDAP server to use the new certificate.")

		return nil
	}),
}

// validateIPAddress validates that the input is a valid IP address and doesn't contain injection characters
func validateIPAddress(ip string) error {
	// Check for basic IP format
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format")
	}

	// Additional security check: ensure no shell metacharacters
	if matched, _ := regexp.MatchString(`[;&|<>$()\x00-\x1f\x7f-\x9f]`, ip); matched {
		return fmt.Errorf("IP address contains forbidden characters")
	}

	return nil
}

func init() {
	UpdateCmd.AddCommand(UpdateLDAPCmd)
	UpdateLDAPCmd.Flags().StringVar(&ipSAN, "ip", "", "IP address to include in SAN")
	UpdateLDAPCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show commands without executing them")
}
