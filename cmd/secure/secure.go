// cmd/secure/secure.go
package secure

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"go.uber.org/zap"
)

// log is a package-level variable for the Zap logger.
var log *zap.Logger

// SecureCmd is the root command for securing an application after installation-related and enabling-related tasks.
var SecureCmd = &cobra.Command{
	Use:     "secure",
	Aliases: []string{"harden"},
	Short:   "Secure various components",
	Long: `Secure commands allow you to provision additional components or dependencies.
For example:
	eos secure Trivy  - Secures the Trivy vulnerability scanner.`,

	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil 
	}),
}

func init() {
	// Initialize the shared logger for the entire install package
	log = logger.L()
}
