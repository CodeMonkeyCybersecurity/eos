// cmd/update/ldap.go
package update

import (
	"fmt"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

var (
	ipSAN  string
	dryRun bool
)

var UpdateLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Regenerate LDAP TLS certificate with IP SAN",
	Long: `Regenerates the TLS certificate for your LDAP server, including the IP address
in the SAN field. Useful when clients (like Delphi/Wazuh) need to connect via IP.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		if ipSAN == "" {
			return fmt.Errorf("--ip flag is required to set SAN IP")
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
			fmt.Printf("🔧 Executing: %s\n", c)
			if !dryRun {
				cmd := exec.Command("bash", "-c", c)
				cmd.Stdout = cmd.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to run command: %s: %w", c, err)
				}
			}
		}

		fmt.Println("✅ LDAP TLS certificate regenerated with IP SAN.")
		fmt.Println("📁 Path: /etc/ldap/certs/ldap.crt and ldap.key")
		fmt.Println("🧠 Reminder: Restart your LDAP server to use the new certificate.")

		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateLDAPCmd)
	UpdateLDAPCmd.Flags().StringVar(&ipSAN, "ip", "", "IP address to include in SAN")
	UpdateLDAPCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show commands without executing them")
}
