// cmd/create/command.go
package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/command"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var commandCmd = &cobra.Command{
	Use:   "command",
	Short: "Create custom system commands",
	Long: `Install custom commands that can be executed system-wide.
	
This command allows you to create executable scripts that are accessible
from anywhere in the system PATH. Commands are installed to /usr/local/bin
by default and can be used by typing the command name.`,
	RunE: eos_cli.Wrap(runCreateCommand),
}

var (
	commandName        string
	commandContent     string
	commandDescription string
)

func init() {
	CreateCmd.AddCommand(commandCmd)

	commandCmd.Flags().StringVarP(&commandName, "name", "n", "", "Name of the command")
	commandCmd.Flags().StringVarP(&commandContent, "content", "c", "", "Command content to execute")
	commandCmd.Flags().StringVarP(&commandDescription, "description", "d", "", "Description of the command")
}

func runCreateCommand(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating custom command")

	installer := command.NewCommandInstaller(rc)

	// If no flags provided, run interactive mode
	if commandName == "" && commandContent == "" {
		logger.Info("Running interactive command installation")
		return installer.InstallInteractive()
	}

	// Validate required flags
	if commandName == "" {
		return fmt.Errorf("command name is required (use --name or run without flags for interactive mode)")
	}

	if commandContent == "" {
		return fmt.Errorf("command content is required (use --content or run without flags for interactive mode)")
	}

	// Create command definition
	def := &command.CommandDefinition{
		Name:        commandName,
		Content:     commandContent,
		Description: commandDescription,
		TargetDir:   "/usr/local/bin",
		Executable:  true,
	}

	// Install the command
	if err := installer.Install(def); err != nil {
		return fmt.Errorf("failed to install command: %w", err)
	}

	logger.Info("Command created successfully",
		zap.String("name", commandName),
		zap.String("description", commandDescription))

	return nil
}