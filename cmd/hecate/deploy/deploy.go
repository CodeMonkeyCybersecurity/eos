// cmd/hecate/deploy/deploy.go

package deploy

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	apps "github.com/CodeMonkeyCybersecurity/eos/pkg/application"
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		runDeploy(rc, cmd, args) // Call the helper function with its parameters.
		return nil
	}),
}

// runDeploy validates the app name and calls deployApplication.
func runDeploy(rc *eos_io.RuntimeContext, _ *cobra.Command, args []string) {
	app := strings.ToLower(args[0])
	if !utils.IsValidApp(app, apps.GetSupportedAppNames()) {
		fmt.Printf(" Invalid application: %s. Supported: %v\n", app, apps.GetSupportedAppNames())
		return
	}

	otelzap.Ctx(rc.Ctx).Info("Deploying application", zap.String("app", app))
	if err := deployApplication(rc, app); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Deployment failed", zap.String("app", app), zap.Error(err))
		fmt.Printf(" Deployment failed for '%s': %v\n", app, err)
		return
	}
	otelzap.Ctx(rc.Ctx).Info("Deployment completed successfully", zap.String("app", app))
	fmt.Printf(" Deployment completed successfully for %s\n", app)
}

// deployApplication calls the deployment function from the utils package.
func deployApplication(rc *eos_io.RuntimeContext, app string) error {
	if err := utils.DeployApp(rc.Ctx, app, false); err != nil {
		return fmt.Errorf("deployment failed for '%s': %w", app, err)
	}
	return nil
}

func init() {
	// Register Jenkins as a subcommand of DeployCmd.
	DeployCmd.AddCommand(NewDeployJenkinsCmd())
}
