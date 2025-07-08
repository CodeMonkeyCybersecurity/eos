// cmd/create/service.go

package create

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
		deployment, err := generateServiceDeployment(serviceName, deploymentType, image, configFile)
		if err != nil {
			return cerr.Wrap(err, "failed to generate service deployment configuration")
		}

		// Deploy service
		result, err := orchestrationManager.DeployService(rc, deployment)
		if err != nil {
			return cerr.Wrap(err, "service deployment failed")
		}

		// Display deployment results
		displayDeploymentResult(rc, result)

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

		displayDeploymentResult(rc, result)

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

		displayDeploymentResult(rc, result)

		return nil
	}),
}

func generateServiceDeployment(serviceName, deploymentType, image, configFile string) (*system.ServiceDeployment, error) {
	deployment := &system.ServiceDeployment{
		Name: serviceName,
		Type: deploymentType,
		Resources: system.ResourceRequirements{
			CPU:    500,  // 500 MHz
			Memory: 512,  // 512 MB
			Disk:   1024, // 1 GB
		},
		HealthChecks: []system.HealthCheck{
			{
				Type:     "http",
				Endpoint: "/health",
				Port:     8080,
				Interval: 30 * time.Second,
				Timeout:  5 * time.Second,
				Retries:  3,
			},
		},
		UpdateStrategy: system.UpdateStrategy{
			Type:            "rolling",
			MaxUnavailable:  1,
			MaxSurge:        1,
			ProgressTimeout: 5 * time.Minute,
			RollbackOnError: true,
		},
	}

	switch deploymentType {
	case "nomad":
		deployment.JobSpec = &system.NomadJobSpec{
			ID:          serviceName,
			Name:        serviceName,
			Type:        "service",
			Region:      "global",
			Datacenters: []string{"dc1"},
			Groups: []system.TaskGroup{
				{
					Name:  serviceName,
					Count: 1,
					Tasks: []system.Task{
						{
							Name:   serviceName,
							Driver: "docker",
							Config: map[string]interface{}{
								"image": image,
								"ports": []string{"http"},
							},
							Resources: system.Resources{
								CPU:    500,
								Memory: 512,
								Ports: map[string]int{
									"http": 8080,
								},
							},
						},
					},
				},
			},
		}

	case "docker":
		deployment.DockerConfig = &system.DockerServiceConfig{
			Image: extractImageName(image),
			Tag:   extractImageTag(image),
			Ports: []system.PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 8080,
					Protocol:      "tcp",
				},
			},
			RestartPolicy: "unless-stopped",
		}

	case "systemd":
		deployment.SystemdConfig = &system.SystemdServiceConfig{
			ExecStart: fmt.Sprintf("/usr/bin/%s", serviceName),
			User:      serviceName,
			Group:     serviceName,
			Type:      "simple",
			Restart:   "always",
			WantedBy:  []string{"multi-user.target"},
		}

	default:
		return nil, cerr.New(fmt.Sprintf("unsupported deployment type: %s", deploymentType))
	}

	return deployment, nil
}

func extractImageName(image string) string {
	// Extract image name from full image string (e.g., "nginx:1.20" -> "nginx")
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[:idx]
	}
	return image
}

func extractImageTag(image string) string {
	// Extract tag from full image string (e.g., "nginx:1.20" -> "1.20")
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:]
	}
	return "latest"
}

func displayDeploymentResult(rc *eos_io.RuntimeContext, result *system.DeploymentResult) {
	logger := otelzap.Ctx(rc.Ctx)

	if result.Success {
		logger.Info("Service deployment completed successfully",
			zap.String("service", result.ServiceName),
			zap.String("type", result.Type),
			zap.Duration("duration", result.Duration),
			zap.String("job_id", result.JobID),
			zap.Int("allocations", result.AllocationsCreated))
	} else {
		logger.Error("Service deployment failed",
			zap.String("service", result.ServiceName),
			zap.String("type", result.Type),
			zap.Duration("duration", result.Duration),
			zap.Strings("errors", result.Errors))
	}

	// Display service endpoints
	if len(result.Endpoints) > 0 {
		logger.Info("Service endpoints available")
		for _, endpoint := range result.Endpoints {
			logger.Info("Endpoint",
				zap.String("name", endpoint.Name),
				zap.String("address", endpoint.Address),
				zap.Int("port", endpoint.Port),
				zap.String("protocol", endpoint.Protocol),
				zap.String("health", endpoint.Health))
		}
	}

	// Display health status
	if len(result.HealthStatus) > 0 {
		logger.Info("Health check results")
		for checkType, status := range result.HealthStatus {
			logger.Info("Health check",
				zap.String("type", checkType),
				zap.String("status", status))
		}
	}

	// Log as JSON for machine parsing
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	logger.Debug("Complete deployment result", zap.String("result_json", string(resultJSON)))
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
