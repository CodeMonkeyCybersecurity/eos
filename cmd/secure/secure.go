// cmd/secure/secure.go
package secure

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// log is a package-level variable for the Zap logger.

// SecureCmd is the root command for securing an application after installation-related and enabling-related tasks.
var SecureCmd = &cobra.Command{
	Use:     "secure",
	Aliases: []string{"harden"},
	Short:   "Secure various components",
	Long: `Secure commands allow you to provision additional components or dependencies.
For example:
	eos secure Trivy  - Secures the Trivy vulnerability scanner.`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Add subcommands to SecureCmd
	SecureCmd.AddCommand(NewPermissionsCmd())
	SecureCmd.AddCommand(NewSudoCheckCmd())
}
