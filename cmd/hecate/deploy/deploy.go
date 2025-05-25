// cmd/hecate/deploy/deploy.go

package deploy

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/apps"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// DeployCmd represents the deploy command.
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
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		runDeploy(cmd, args) // Call the helper function with its parameters.
		return nil
	}),
}

// runDeploy validates the app name and calls deployApplication.
func runDeploy(_ *cobra.Command, args []string) {
	app := strings.ToLower(args[0])
	if !utils.IsValidApp(app, apps.GetSupportedAppNames()) {
		fmt.Printf("❌ Invalid application: %s. Supported: %v\n", app, apps.GetSupportedAppNames())
		return
	}

	zap.L().Info("Deploying application", zap.String("app", app))
	if err := deployApplication(app); err != nil {
		zap.L().Error("Deployment failed", zap.String("app", app), zap.Error(err))
		fmt.Printf("❌ Deployment failed for '%s': %v\n", app, err)
		return
	}
	zap.L().Info("Deployment completed successfully", zap.String("app", app))
	fmt.Printf("✅ Deployment completed successfully for %s\n", app)
}

// deployApplication calls the deployment function from the utils package.
func deployApplication(app string) error {
	if err := utils.DeployApp(app, false); err != nil {
		return fmt.Errorf("deployment failed for '%s': %w", app, err)
	}
	return nil
}

func init() {
	// Register Jenkins as a subcommand of DeployCmd.
	DeployCmd.AddCommand(NewDeployJenkinsCmd())
}
