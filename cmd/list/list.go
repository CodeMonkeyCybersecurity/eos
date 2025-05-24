// cmd/list/list.go
// Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au

package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ReadCmd is the root command for read operations
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List resources (e.g., processes, users, storage)",
	Long:  `The list command list 'metadata' about various resources such as processes, users, or storage.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}
