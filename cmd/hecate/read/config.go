// cmd/inspect/config.go

package read

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// inspectConfigCmd represents the "inspect config" subcommand
var inspectConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect configurations",
	Long: `This command lets you inspect various configuration resources for Hecate.
You can choose from:
  1) Inspect Certificates
  2) Inspect docker-compose file
  3) Inspect Eos backend web apps configuration
  4) Inspect Nginx defaults
  5) Inspect all configurations`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runInspectConfig(rc)
	}),
}

// runInspectConfig presents an interactive menu for inspection
func runInspectConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("🔍 Inspect Configurations Menu")
	logger.Info("Select the resource you want to inspect:")
	logger.Info("1) Inspect Certificates")
	logger.Info("2) Inspect docker-compose file")
	logger.Info("3) Inspect Eos backend web apps configuration")
	logger.Info("4) Inspect Nginx defaults")
	logger.Info("5) Inspect all configurations")
	logger.Info("Enter choice (1-5): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.ToLower(strings.TrimSpace(choice))

	switch choice {
	case "1", "certificates", "certs":
		utils.InspectCertificates(rc.Ctx)
	case "2", "compose", "docker-compose":
		utils.InspectDockerCompose(rc.Ctx)
	case "3", "github.com/CodeMonkeyCybersecurity/eos":
		utils.InspectEosConfig(rc.Ctx)
	case "4", "nginx":
		utils.InspectNginxDefaults(rc.Ctx)
	case "5", "all":
		utils.InspectCertificates(rc.Ctx)
		utils.InspectDockerCompose(rc.Ctx)
		utils.InspectEosConfig(rc.Ctx)
		utils.InspectNginxDefaults(rc.Ctx)
	default:
		logger.Error(" Invalid choice provided", zap.String("choice", choice))
		return fmt.Errorf("invalid choice: %s", choice)
	}

	return nil
}
