// cmd/hecate/deploy/deploy.go

package deploy

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var log = logger.L()

// DeployCmd represents the deploy command
var DeployCmd = &cobra.Command{
	Use:   "deploy [app]",
	Short: "Deploy an application behind the Hecate reverse proxy",
	Long: `Deploy applications behind Hecate’s reverse proxy.

This command allows you to deploy pre-configured applications such as Nextcloud, Jenkins, Wazuh, and others.
Hecate will automatically configure Nginx and deploy any necessary services.

Supported applications:
  - Nextcloud
  - Jenkins
  - Wazuh
  - Mailcow
  - Grafana
  - Mattermost
  - MinIO
  - Wiki.js
  - ERPNext
  - Persephone

Examples:
  hecate deploy nextcloud
  hecate deploy jenkins`,
	Args: cobra.ExactArgs(1),
	Run:  runDeploy, // This generic function is used for non-specific deployments.
}

func runDeploy(cmd *cobra.Command, args []string) {
	app := strings.ToLower(args[0])
	if !utils.IsValidApp(app) {
		fmt.Printf("❌ Invalid application: %s. Supported: %v\n", app, config.GetSupportedAppNames())
		return
	}

	log.Info("Deploying application", zap.String("app", app))
	if err := deployApplication(app); err != nil {
		log.Error("Deployment failed", zap.String("app", app), zap.Error(err))
		fmt.Printf("❌ Deployment failed for '%s': %v\n", app, err)
		return
	}
	log.Info("Deployment completed successfully", zap.String("app", app))
	fmt.Printf("✅ Deployment completed successfully for %s\n", app)
}

func deployApplication(app string) error {
	if err := utils.DeployApp(app, false); err != nil {
		return fmt.Errorf("deployment failed for '%s': %w", app, err)
	}
	return nil
}

func init() {
	// Register the Jenkins subcommand as a child of DeployCmd.
	DeployCmd.AddCommand(NewDeployJenkinsCmd())
}
