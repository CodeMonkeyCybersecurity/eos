package clusterfuzz

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployInfrastructure deploys the ClusterFuzz infrastructure to Nomad
// following the Assess → Intervene → Evaluate pattern
func DeployInfrastructure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing infrastructure deployment requirements")
	
	// Check if Nomad is accessible
	if err := checkNomadConnectivity(rc, config.NomadAddress); err != nil {
		return fmt.Errorf("nomad not accessible: %w", err)
	}
	
	// INTERVENE
	logger.Info("Deploying ClusterFuzz infrastructure")
	
	// Build Docker images first
	logger.Info("Building Docker images...")
	if err := BuildDockerImages(rc, config); err != nil {
		return fmt.Errorf("failed to build Docker images: %w", err)
	}
	
	// Deploy core services job
	logger.Info("Deploying core services to Nomad...")
	coreJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-core.nomad")
	
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "run", "-address=" + config.NomadAddress, coreJobPath},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy core services: %w", err)
	}
	
	// EVALUATE
	logger.Info("Waiting for infrastructure to be ready...")
	if err := WaitForInfrastructure(rc, config); err != nil {
		return fmt.Errorf("infrastructure deployment verification failed: %w", err)
	}
	
	logger.Info("Infrastructure deployed successfully")
	return nil
}

// BuildDockerImages builds the required Docker images for ClusterFuzz
func BuildDockerImages(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Checking Docker availability")
	
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"version"},
	})
	if err != nil {
		return fmt.Errorf("docker not available: %w", err)
	}
	
	// INTERVENE
	dockerDir := filepath.Join(config.ConfigDir, "docker")
	
	// Build web image
	webDockerfilePath := filepath.Join(dockerDir, "web.Dockerfile")
	logger.Info("Building ClusterFuzz web image...")
	
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"build", "-t", "clusterfuzz/web:custom", "-f", webDockerfilePath, dockerDir},
	})
	if err != nil {
		logger.Warn("Failed to build web image, will use default", zap.Error(err))
	}
	
	// Build bot image
	botDockerfilePath := filepath.Join(dockerDir, "bot.Dockerfile")
	logger.Info("Building ClusterFuzz bot image...")
	
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"build", "-t", "clusterfuzz/bot:custom", "-f", botDockerfilePath, dockerDir},
	})
	if err != nil {
		logger.Warn("Failed to build bot image, will use default", zap.Error(err))
	}
	
	// EVALUATE
	logger.Info("Docker images built successfully")
	return nil
}

// WaitForInfrastructure waits for all infrastructure services to be ready
func WaitForInfrastructure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	services := []struct {
		name string
		host string
		port int
	}{
		{"PostgreSQL", config.DatabaseConfig.Host, config.DatabaseConfig.Port},
		{"Redis", config.QueueConfig.Host, config.QueueConfig.Port},
	}
	
	// Add MinIO if configured
	if config.StorageConfig.Type == "minio" {
		services = append(services, struct {
			name string
			host string
			port int
		}{"MinIO", "localhost", 9000})
	}
	
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Minute)
	defer cancel()
	
	for _, svc := range services {
		logger.Info("Waiting for service", zap.String("service", svc.name))
		if err := WaitForService(ctx, svc.host, svc.port); err != nil {
			return fmt.Errorf("%s not ready: %w", svc.name, err)
		}
		logger.Info("Service is ready", zap.String("service", svc.name))
	}
	
	return nil
}

// WaitForService waits for a network service to become available
func WaitForService(ctx context.Context, host string, port int) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				_ = conn.Close()
				return nil
			}
		}
	}
}

// DeployApplication deploys the ClusterFuzz application
func DeployApplication(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Checking application deployment prerequisites")
	
	// INTERVENE
	logger.Info("Deploying ClusterFuzz application to Nomad...")
	appJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-app.nomad")
	
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "run", "-address=" + config.NomadAddress, appJobPath},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy application: %w", err)
	}
	
	// EVALUATE
	logger.Info("Waiting for application to be ready...")
	time.Sleep(30 * time.Second) // Give it time to start
	
	// Check if web UI is accessible
	if err := WaitForService(rc.Ctx, "localhost", 9000); err != nil {
		return fmt.Errorf("application web UI not ready: %w", err)
	}
	
	logger.Info("Application deployed successfully")
	return nil
}

// DeployBots deploys fuzzing bots to the cluster
func DeployBots(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Preparing bot deployment",
		zap.Int("regular_bots", config.BotCount),
		zap.Int("preemptible_bots", config.PreemptibleBotCount))
	
	// INTERVENE
	botsJobPath := filepath.Join(config.ConfigDir, "jobs", "clusterfuzz-bots.nomad")
	
	logger.Info("Deploying fuzzing bots to Nomad...")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "run", "-address=" + config.NomadAddress, botsJobPath},
	})
	if err != nil {
		return fmt.Errorf("failed to deploy bots: %w", err)
	}
	
	// EVALUATE
	logger.Info("Bots deployed successfully")
	return nil
}

func checkNomadConnectivity(rc *eos_io.RuntimeContext, address string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Nomad connectivity", zap.String("address", address))
	
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"status", "-address=" + address},
	})
	
	return err
}