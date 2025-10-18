// cmd/list/list.go
// Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ListCmd is the root command for list operations
var ListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List resources (e.g., processes, users, storage)",
	Long:    `The list command list 'metadata' about various resources such as processes, users, or storage.`,
	Aliases: []string{"ls", "check"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

// log is a package-level variable for the Zap logger.

func init() {
	// The 'check' alias on ListCmd allows 'eos check' to route to 'eos list'
	// Individual check commands (like wazuh check) are added as subcommands elsewhere
}
