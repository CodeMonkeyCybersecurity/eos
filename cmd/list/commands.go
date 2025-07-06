// cmd/list/commands.go
package list

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/command"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var commandsCmd = &cobra.Command{
	Use:   "commands",
	Short: "List custom system commands",
	Long: `List all custom commands installed via Eos.
	
This command shows all custom commands that have been installed,
including their descriptions and creation dates.`,
	RunE: eos_cli.Wrap(runListCommands),
}

var (
	showAll bool
)

func init() {
	ListCmd.AddCommand(commandsCmd)

	commandsCmd.Flags().BoolVarP(&showAll, "all", "a", false, "Show all commands, not just Eos-generated ones")
}

func runListCommands(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing custom commands")

	installer := command.NewCommandInstaller(rc)

	commands, err := installer.ListCustomCommands()
	if err != nil {
		return fmt.Errorf("failed to list commands: %w", err)
	}

	if len(commands) == 0 {
		fmt.Println("No custom commands found.")
		return nil
	}

	// Filter Eos commands if not showing all
	if !showAll {
		var eosCommands []command.CommandInfo
		for _, cmd := range commands {
			if cmd.IsEosGenerated {
				eosCommands = append(eosCommands, cmd)
			}
		}
		commands = eosCommands

		if len(commands) == 0 {
			fmt.Println("No Eos-generated commands found. Use --all to see all commands.")
			return nil
		}
	}

	// Display commands
	fmt.Printf("Found %d custom commands:\n\n", len(commands))

	for _, cmd := range commands {
		fmt.Printf("Name: %s\n", cmd.Name)
		fmt.Printf("Path: %s\n", cmd.Path)

		if cmd.Description != "" {
			fmt.Printf("Description: %s\n", strings.TrimSpace(cmd.Description))
		}

		fmt.Printf("Created: %s\n", cmd.CreatedAt.Format("2006-01-02 15:04:05"))

		if cmd.IsEosGenerated {
			fmt.Printf("Type: Eos-generated\n")
		} else {
			fmt.Printf("Type: System command\n")
		}

		fmt.Println()
	}

	logger.Info("Listed commands successfully",
		zap.Int("total_commands", len(commands)),
		zap.Bool("show_all", showAll))

	return nil
}
