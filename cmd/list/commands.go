// cmd/list/commands.go
// TODO: PATTERN 2 - Inline runListCommands function into command RunE field
package list

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/command"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security"
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
	secureOutput := security.NewSecureOutput(rc.Ctx)

	logger.Info("Listing custom commands")

	installer := command.NewCommandInstaller(rc)

	commands, err := installer.ListCustomCommands()
	if err != nil {
		return fmt.Errorf("failed to list commands: %w", err)
	}

	if len(commands) == 0 {
		secureOutput.Info("No custom commands found")
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
			secureOutput.Info("No Eos-generated commands found",
				zap.String("suggestion", "Use --all to see all commands"))
			return nil
		}
	}

	// Prepare command data for secure output
	commandNames := make([]string, len(commands))
	tableHeaders := []string{"Name", "Type", "Path", "Created", "Description"}
	tableRows := make([][]string, len(commands))

	for i, cmd := range commands {
		commandNames[i] = cmd.Name

		cmdType := "System command"
		if cmd.IsEosGenerated {
			cmdType = "Eos-generated"
		}

		description := strings.TrimSpace(cmd.Description)
		if description == "" {
			description = "(no description)"
		}

		tableRows[i] = []string{
			cmd.Name,
			cmdType,
			cmd.Path,
			cmd.CreatedAt.Format("2006-01-02 15:04:05"),
			description,
		}
	}

	// Use secure output for displaying results
	secureOutput.Result("list_commands", map[string]interface{}{
		"command_count": len(commands),
		"show_all":      showAll,
		"commands":      commandNames,
	})

	secureOutput.Table("Custom Commands", tableHeaders, tableRows,
		zap.Int("total_commands", len(commands)),
		zap.Bool("show_all", showAll))

	return nil
}
