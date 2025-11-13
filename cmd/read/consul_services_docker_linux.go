//go:build linux

// cmd/read/consul_services_docker_linux.go
//
// Docker service registration subcommand (Linux only).
// This is separate because it depends on Linux-only consul package functions.

package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Consul services docker subcommand
var consulServicesDockerCmd = &cobra.Command{
	Use:   "services-docker [container-names...]",
	Short: "Generate Consul service definitions for Docker containers",
	Long: `Generate Consul service definition files for Docker containers.

This command creates HCL service definition files in /etc/consul.d/ following HashiCorp's
recommended pattern for Docker + Consul integration:
  - Host-based Consul client agent (not sidecars)
  - Service definition files in /etc/consul.d/
  - Health checks using docker exec pattern
  - Automatic service discovery via container labels

The command can:
  1. Register specific containers by name
  2. Auto-discover all containers from a docker-compose.yml file
  3. Register all running containers on the host

Container metadata is extracted from:
  - Container labels (consul.service.*)
  - Docker Compose labels
  - Container configuration (ports, health checks)
  - Smart defaults based on service type

EXAMPLES:
  # Register specific containers
  eos read consul services-docker hecate-caddy hecate-authentik

  # Auto-discover from docker-compose.yml
  eos read consul services-docker --compose-file /opt/hecate/docker-compose.yml

  # Register all running containers
  eos read consul services-docker --all

  # Dry-run mode (show what would be registered)
  eos read consul services-docker --all --dry-run`,
	RunE: eos.Wrap(runConsulServicesDocker),
}

var (
	composeFile string
	registerAll bool
)

func runConsulServicesDocker(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Registering Docker containers with Consul",
		zap.Bool("register_all", registerAll),
		zap.String("compose_file", composeFile),
		zap.Int("specified_containers", len(args)))

	var containerNames []string

	// ASSESS - Determine which containers to register
	if composeFile != "" {
		// Discover containers from compose file
		logger.Info("Discovering containers from docker-compose.yml",
			zap.String("compose_file", composeFile))

		discovered, err := consul.GetContainersFromComposeFile(rc, composeFile)
		if err != nil {
			return fmt.Errorf("failed to discover containers from compose file: %w", err)
		}

		containerNames = discovered
		logger.Info("Containers discovered from compose file",
			zap.Int("count", len(containerNames)),
			zap.Strings("containers", containerNames))

	} else if registerAll {
		// Register all running containers
		return fmt.Errorf("--all flag not yet implemented (use --compose-file or specify container names)")

	} else if len(args) > 0 {
		// Use specified container names
		containerNames = args

	} else {
		return fmt.Errorf("must specify container names, --compose-file, or --all")
	}

	// INTERVENE - Register each container
	successCount := 0
	failureCount := 0

	for _, containerName := range containerNames {
		logger.Info("Generating service definition",
			zap.String("container", containerName))

		// Generate service definition
		servicePath, err := consul.GenerateDockerServiceDefinition(rc, containerName, nil)
		if err != nil {
			logger.Warn("Failed to generate service definition (non-fatal)",
				zap.String("container", containerName),
				zap.Error(err))
			failureCount++
			continue
		}

		logger.Info("Service definition generated",
			zap.String("container", containerName),
			zap.String("file", servicePath))
		successCount++
	}

	// EVALUATE - Report results
	logger.Info("Service definition generation complete",
		zap.Int("success_count", successCount),
		zap.Int("failure_count", failureCount),
		zap.Int("total", len(containerNames)))

	if failureCount > 0 {
		logger.Warn("Some service definitions failed to generate",
			zap.Int("failed_count", failureCount),
			zap.String("impact", "These services will not be registered with Consul"),
			zap.String("remediation", "Check container names and ensure Consul agent is running"))
	}

	if successCount == 0 {
		return fmt.Errorf("failed to generate any service definitions")
	}

	logger.Info("Consul service definitions written to /etc/consul.d/",
		zap.Int("services_registered", successCount))

	return nil
}

func init() {
	// services-docker subcommand flags
	consulServicesDockerCmd.Flags().StringVar(&composeFile, "compose-file", "", "Path to docker-compose.yml for auto-discovery")
	consulServicesDockerCmd.Flags().BoolVar(&registerAll, "all", false, "Register all running containers")

	// Add subcommand to ConsulCmd
	ConsulCmd.AddCommand(consulServicesDockerCmd)
}
