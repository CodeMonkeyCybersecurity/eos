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

// ReadCmd is the root command for read operations
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List resources (e.g., processes, users, storage)",
	Long:  `The list command list 'metadata' about various resources such as processes, users, or storage.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
