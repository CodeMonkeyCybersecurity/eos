// cmd/update/ldap.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/spf13/cobra"
)

var (
	ldapIPSAN  string
	ldapDryRun bool
)

var UpdateLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Regenerate LDAP TLS certificate with IP SAN",
	Long: `Regenerates the TLS certificate for your LDAP server, including the IP address
in the SAN field. Useful when clients (like Wazuh/Wazuh) need to connect via IP.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Validate required flag
		if ldapIPSAN == "" {
			return fmt.Errorf("--ip flag is required to set SAN IP")
		}

		// Delegate to pkg/ldap for business logic
		config := &ldap.RegenerateTLSCertificateConfig{
			IPSAN:  ldapIPSAN,
			DryRun: ldapDryRun,
		}

		return ldap.RegenerateTLSCertificate(rc, config)
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateLDAPCmd)
	UpdateLDAPCmd.Flags().StringVar(&ldapIPSAN, "ip", "", "IP address to include in SAN")
	UpdateLDAPCmd.Flags().BoolVar(&ldapDryRun, "dry-run", false, "Show commands without executing them")
}

// All business logic has been migrated to pkg/ldap/certificate.go
// This file now contains only Cobra orchestration as per CLAUDE.md architecture rules
