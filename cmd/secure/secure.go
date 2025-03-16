// cmd/secure/secure.go
package secure

import (
	"github.com/spf13/cobra"
)

// SecureCmd is the root command for securing an application after installation-related and enabling-related tasks.
var SecureCmd = &cobra.Command{
	Use:   "secure",
	Short: "Secure various components",
	Long: `Secure commands allow you to provision additional components or dependencies.
For example:
  eos secure Trivy  - Secures the Trivy vulnerability scanner.`,
}

// In the init function, attach subcommands (for example, the Vault Secure-er).
func init() {
	SecureCmd.AddCommand(trivyCmd) // trivyCmd is defined in the same package (in trivy.go)
}
