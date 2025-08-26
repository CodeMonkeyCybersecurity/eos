// cmd/create/service.go

package create

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/services/service_deployment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createServiceCmd = &cobra.Command{
	Use:   "service [service-name]",
	Short: "Deploy and orchestrate services via SaltStack and Nomad",
	Long: `Deploy and orchestrate services using SaltStack for configuration management and Nomad for scheduling.

This command supports multiple deployment types:
- Nomad jobs for container orchestration
- Docker Compose services
- systemd services for traditional daemons

Examples:
  eos create service grafana --type nomad --image grafana/grafana:latest
  eos create service webapp --type docker --compose-file ./docker-compose.yml
  eos create service myapp --type systemd --exec-start "/usr/bin/myapp"`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("service name must be specified")
		}

		serviceName := args[0]
		deploymentType, _ := cmd.Flags().GetString("type")
		image, _ := cmd.Flags().GetString("image")
		configFile, _ := cmd.Flags().GetString("config-file")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		terraformDir, _ := cmd.Flags().GetString("terraform-dir")
		target, _ := cmd.Flags().GetString("target")

		logger.Info("Deploying service",
			zap.String("service", serviceName),
			zap.String("type", deploymentType),
			zap.String("target", target))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   10 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		// Initialize Nomad configuration
		nomadConfig := &system.NomadConfig{
			Address:    "http://localhost:4646",
			Region:     "global",
			Datacenter: "dc1",
		}

		// Create orchestration manager
		orchestrationManager := system.NewOrchestrationManager(saltManager, terraformDir, vaultPath, nomadConfig)

		// Generate service deployment configuration
		deployment, err := service_deployment.GenerateServiceDeployment(rc, serviceName, deploymentType, image, configFile)
		if err != nil {
			return cerr.Wrap(err, "failed to generate service deployment configuration")
		}

		// Convert to system deployment type
		systemDeployment := service_deployment.ConvertToSystemDeployment(deployment)

		// Deploy service
		result, err := orchestrationManager.DeployService(rc, systemDeployment)
		if err != nil {
			return cerr.Wrap(err, "service deployment failed")
		}

		// Display deployment results
		convertedResult := service_deployment.ConvertFromSystemDeploymentResult(result)
		if err := service_deployment.DisplayDeploymentResult(rc, convertedResult); err != nil {
			logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to display deployment results: %v", err))
		}

		return nil
	}),
}

var createGrafanaCmd = &cobra.Command{
	Use:   "grafana",
	Short: "Deploy Grafana monitoring service via Nomad",
	Long: `Deploy Grafana monitoring service using Nomad orchestration with SaltStack configuration management.

This deploys a production-ready Grafana instance with:
- Persistent data storage
- Vault integration for secrets
- Health checks and service discovery
- Load balancer integration

Examples:
  eos create grafana --version 9.5.2 --database-url postgres://...
  eos create grafana --plugins grafana-worldmap-panel,grafana-clock-panel`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		version, _ := cmd.Flags().GetString("version")
		databaseURL, _ := cmd.Flags().GetString("database-url")
		plugins, _ := cmd.Flags().GetStringSlice("plugins")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")

		logger.Info("Deploying Grafana monitoring service", zap.String("version", version))

		// Initialize managers
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   10 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		nomadConfig := &system.NomadConfig{
			Address:    "http://localhost:4646",
			Region:     "global",
			Datacenter: "dc1",
		}

		orchestrationManager := system.NewOrchestrationManager(saltManager, "", vaultPath, nomadConfig)

		// Configure Grafana deployment
		grafanaConfig := &system.GrafanaConfig{
			Version:       version,
			AdminPassword: "", // Will be generated and stored in Vault
			DatabaseURL:   databaseURL,
			Plugins:       plugins,
			Settings: map[string]string{
				"server.root_url":     "https://grafana.example.com",
				"security.admin_user": "admin",
			},
		}

		// Deploy Grafana
		result, err := orchestrationManager.DeployGrafana(rc, grafanaConfig)
		if err != nil {
			return cerr.Wrap(err, "Grafana deployment failed")
		}

		convertedResult := service_deployment.ConvertFromSystemDeploymentResult(result)
		if err := service_deployment.DisplayDeploymentResult(rc, convertedResult); err != nil {
			logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to display deployment results: %v", err))
		}

		return nil
	}),
}

var createMattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Deploy Mattermost communication platform via Nomad",
	Long: `Deploy Mattermost team communication platform using Nomad orchestration.

This deploys a production-ready Mattermost instance with:
- Database integration (PostgreSQL)
- File storage configuration
- SMTP email settings
- SSL/TLS termination

Examples:
  eos create mattermost --site-url https://chat.company.com
  eos create mattermost --database-url postgres://... --smtp-server mail.company.com`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		version, _ := cmd.Flags().GetString("version")
		siteURL, _ := cmd.Flags().GetString("site-url")
		databaseURL, _ := cmd.Flags().GetString("database-url")
		smtpServer, _ := cmd.Flags().GetString("smtp-server")
		smtpPort, _ := cmd.Flags().GetInt("smtp-port")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")

		logger.Info("Deploying Mattermost communication platform", zap.String("site_url", siteURL))

		// Initialize managers
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   10 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		nomadConfig := &system.NomadConfig{
			Address:    "http://localhost:4646",
			Region:     "global",
			Datacenter: "dc1",
		}

		orchestrationManager := system.NewOrchestrationManager(saltManager, "", vaultPath, nomadConfig)

		// Configure Mattermost deployment
		mattermostConfig := &system.MattermostConfig{
			Version:     version,
			SiteURL:     siteURL,
			DatabaseURL: databaseURL,
			SMTPConfig: system.SMTPConfig{
				Server: smtpServer,
				Port:   smtpPort,
			},
		}

		// Deploy Mattermost
		result, err := orchestrationManager.DeployMattermost(rc, mattermostConfig)
		if err != nil {
			return cerr.Wrap(err, "Mattermost deployment failed")
		}

		convertedResult := service_deployment.ConvertFromSystemDeploymentResult(result)
		if err := service_deployment.DisplayDeploymentResult(rc, convertedResult); err != nil {
			logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to display deployment results: %v", err))
		}

		return nil
	}),
}

func init() {
	// Service deployment command
	createServiceCmd.Flags().String("type", "nomad", "Deployment type: nomad, docker, systemd")
	createServiceCmd.Flags().String("image", "", "Container image for docker/nomad deployments")
	createServiceCmd.Flags().String("config-file", "", "Configuration file path")
	createServiceCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	createServiceCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")
	createServiceCmd.Flags().String("terraform-dir", "", "Terraform directory for infrastructure")
	createServiceCmd.Flags().String("target", "*", "Salt target minions")

	// Grafana deployment command
	createGrafanaCmd.Flags().String("version", "latest", "Grafana version to deploy")
	createGrafanaCmd.Flags().String("database-url", "", "Database connection URL")
	createGrafanaCmd.Flags().StringSlice("plugins", []string{}, "Grafana plugins to install")
	createGrafanaCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	createGrafanaCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")

	// Mattermost deployment command
	createMattermostCmd.Flags().String("version", "latest", "Mattermost version to deploy")
	createMattermostCmd.Flags().String("site-url", "", "Mattermost site URL")
	createMattermostCmd.Flags().String("database-url", "", "Database connection URL")
	createMattermostCmd.Flags().String("smtp-server", "", "SMTP server for email")
	createMattermostCmd.Flags().Int("smtp-port", 587, "SMTP server port")
	createMattermostCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	createMattermostCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")

	CreateCmd.AddCommand(createServiceCmd)
	CreateCmd.AddCommand(createGrafanaCmd)
	CreateCmd.AddCommand(createMattermostCmd)
}
