// cmd/hecate/delete/delete.go

package delete

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeleteCmd is the root "delete" command: supports either `delete <app>` or subcommands like `delete resources`
var DeleteHecate = &cobra.Command{
	Use:   "delete",
	Short: "Delete deployed applications or resources",
	Long: `Delete applications or configuration resources managed by Hecate.

Examples:
  hecate delete jenkins
  hecate delete resources`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			logger.Info(" Please use a subcommand like 'delete resources' or specify an app name")
			return nil
		}

		app := args[0]
		logger.Info(" Deleting application", zap.String("app", app))
		// TODO: Add logic to delete individual app configuration
		return nil
	}),
}

var deleteResourcesCmd = &cobra.Command{
	Use:   "resources",
	Short: "Interactively delete configuration resources",
	Long: `This command deletes various resources for Hecate:

  1) Delete Certificates
  2) Delete docker compose modifications/backups
  3) Delete Eos backend web apps configuration files
  4) Delete (or revert) Nginx defaults
  5) Delete all specified resources`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runDeleteConfig(rc)
	}),
}

func init() {
	DeleteCmd.AddCommand(deleteResourcesCmd)
}
// TODO
// runDeleteConfig presents an interactive menu for delete actions.
func runDeleteConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Delete Resources Menu")
	logger.Info("Select the resource you want to delete:")
	logger.Info("1) Delete Certificates")
	logger.Info("2) Delete docker compose modifications/backups")
	logger.Info("3) Delete Eos backend web apps configuration files")
	logger.Info("4) Delete (or revert) Nginx defaults")
	logger.Info("5) Delete all specified resources")
	logger.Info("Enter choice (1-5): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.ToLower(strings.TrimSpace(choice))

	switch choice {
	case "1":
		deleteCertificates(rc)
	case "2":
		deleteDockerCompose(rc)
	case "3":
		deleteEosConfig(rc)
	case "4":
		deleteNginxDefaults(rc)
	case "5":
		deleteCertificates(rc)
		deleteDockerCompose(rc)
		deleteEosConfig(rc)
		deleteNginxDefaults(rc)
	default:
		logger.Error(" Invalid choice provided", zap.String("choice", choice))
		return fmt.Errorf("invalid choice: %s", choice)
	}
	return nil
}
// TODO
func deleteCertificates(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	certsDir := "/opt/hecate/certs"

	logger.Info(" Deleting Certificates", zap.String("directory", certsDir))

	err := os.RemoveAll(certsDir)
	if err != nil {
		logger.Error(" Error deleting certificates directory", zap.String("directory", certsDir), zap.Error(err))
	} else {
		logger.Info(" Certificates deleted", zap.String("directory", certsDir))
	}
}
// TODO
func deleteDockerCompose(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Deleting docker compose modifications/backups")

	matches, err := filepath.Glob("/opt/hecate/*_docker-compose.yml.bak")
	if err != nil {
		logger.Error(" Error searching for backups", zap.Error(err))
		return
	}

	for _, file := range matches {
		if err := os.Remove(file); err != nil {
			logger.Error(" Error removing backup file", zap.String("file", file), zap.Error(err))
		} else {
			logger.Info(" Removed backup file", zap.String("file", file))
		}
	}

	// Also remove the main docker-compose.yml file
	mainCompose := "/opt/hecate/docker-compose.yml"
	if err := os.Remove(mainCompose); err != nil {
		logger.Error(" Error removing docker compose file", zap.String("file", mainCompose), zap.Error(err))
	} else {
		logger.Info(" Removed main docker compose file", zap.String("file", mainCompose))
	}
}
// TODO
func deleteEosConfig(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	confDir := "/opt/hecate/assets/conf.d"

	logger.Info(" Deleting Eos backend configuration files", zap.String("directory", confDir))

	err := os.RemoveAll(confDir)
	if err != nil {
		logger.Error(" Error deleting configuration directory", zap.String("directory", confDir), zap.Error(err))
	} else {
		logger.Info(" Eos backend configuration files deleted", zap.String("directory", confDir))
	}
}
// TODO
func deleteNginxDefaults(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	configFile := "/opt/hecate/nginx.conf"
	backupFile := "/opt/hecate/nginx.conf.bak"

	logger.Info(" Deleting/reverting Nginx defaults", zap.String("file", configFile))

	if _, err := os.Stat(backupFile); err == nil {
		if err := os.Remove(configFile); err != nil {
			logger.Error(" Error removing current config", zap.String("file", configFile), zap.Error(err))
		} else if err := os.Rename(backupFile, configFile); err != nil {
			logger.Error(" Error restoring backup", zap.String("backup", backupFile), zap.String("target", configFile), zap.Error(err))
		} else {
			logger.Info(" Nginx defaults reverted from backup", zap.String("file", configFile))
		}
	} else {
		if err := os.Remove(configFile); err != nil {
			logger.Error(" Error removing config file", zap.String("file", configFile), zap.Error(err))
		} else {
			logger.Info(" Deleted config file", zap.String("file", configFile))
		}
	}
}
