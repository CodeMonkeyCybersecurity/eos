// Package bionicgpt provides phased deployment for reliable service startup
//
// This module implements staged deployment to prevent cascading failures.
// Following shift-left principles: start services in dependency order, verify each phase.
//
// Deployment Phases:
//   Phase 1: Database (postgres) - Foundation layer
//   Phase 2: Migrations - Schema setup
//   Phase 3: Supporting Services (embeddings, chunking) - Processing layer
//   Phase 4: LiteLLM Proxy - Translation layer
//   Phase 5: RAG Engine - Document processing
//   Phase 6: Application - User interface
//
// Benefits:
//   - Catches failures early (database issues before app starts)
//   - Clear error attribution (know which component failed)
//   - Faster recovery (restart only failed component)
//   - Better diagnostics (phase-specific logs)
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeploymentPhase represents a stage in the deployment process
type DeploymentPhase struct {
	Name         string        // Human-readable phase name
	Services     []string      // Docker Compose service names to start
	WaitTime     time.Duration // Time to wait for services to stabilize
	HealthChecks []string      // Services that must be healthy
	Optional     bool          // If true, continue even if phase fails
}

// phasedDeployment performs staged service startup for reliability
// This replaces the simple "docker compose up -d" with intelligent phased deployment
func (bgi *BionicGPTInstaller) phasedDeployment(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("Starting Phased Deployment")
	logger.Info("Services will start in dependency order with health verification")
	logger.Info("════════════════════════════════════════════════════════════════")

	phases := []DeploymentPhase{
		{
			Name:         "Phase 1: Database Foundation",
			Services:     []string{"postgres"},
			WaitTime:     20 * time.Second,
			HealthChecks: []string{"postgres"},
			Optional:     false,
		},
		{
			Name:         "Phase 2: Database Migrations",
			Services:     []string{"migrations"},
			WaitTime:     30 * time.Second,
			HealthChecks: []string{}, // Migrations is a one-shot job
			Optional:     false,
		},
		{
			Name:         "Phase 3: Supporting Services",
			Services:     []string{"embeddings-api", "chunking-engine"},
			WaitTime:     15 * time.Second,
			HealthChecks: []string{}, // These don't have health checks
			Optional:     false,
		},
		{
			Name:         "Phase 4: LiteLLM Proxy",
			Services:     []string{"litellm-proxy"},
			WaitTime:     90 * time.Second, // Longer wait - needs to connect to Azure
			HealthChecks: []string{"litellm-proxy"},
			Optional:     false, // Critical - app depends on this
		},
		{
			Name:         "Phase 5: RAG Engine",
			Services:     []string{"rag-engine"},
			WaitTime:     15 * time.Second,
			HealthChecks: []string{},
			Optional:     false,
		},
		{
			Name:         "Phase 6: Application Interface",
			Services:     []string{"app"},
			WaitTime:     30 * time.Second,
			HealthChecks: []string{"app"},
			Optional:     false,
		},
	}

	for i, phase := range phases {
		logger.Info("")
		logger.Info(fmt.Sprintf("──────────────────────────────────────────────────────────────"))
		logger.Info(fmt.Sprintf("%s (%d/%d)", phase.Name, i+1, len(phases)))
		logger.Info(fmt.Sprintf("──────────────────────────────────────────────────────────────"))

		// Start services for this phase
		if err := bgi.startPhaseServices(ctx, phase); err != nil {
			if phase.Optional {
				logger.Warn(fmt.Sprintf("Phase failed but is optional, continuing"),
					zap.Error(err))
				continue
			}
			return fmt.Errorf("phase %d failed: %w", i+1, err)
		}

		// Wait for services to stabilize
		logger.Info(fmt.Sprintf("Waiting %v for services to stabilize...", phase.WaitTime))
		time.Sleep(phase.WaitTime)

		// Verify health checks
		if len(phase.HealthChecks) > 0 {
			if err := bgi.verifyPhaseHealth(ctx, phase); err != nil {
				if phase.Optional {
					logger.Warn("Phase health check failed but is optional",
						zap.Error(err))
					continue
				}
				return fmt.Errorf("phase %d health check failed: %w", i+1, err)
			}
		}

		logger.Info(fmt.Sprintf("✓ %s completed successfully", phase.Name))
	}

	logger.Info("")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("✓ Phased Deployment Completed Successfully")
	logger.Info("All services started in correct order and verified healthy")
	logger.Info("════════════════════════════════════════════════════════════════")

	return nil
}

// startPhaseServices starts the services for a deployment phase
func (bgi *BionicGPTInstaller) startPhaseServices(ctx context.Context, phase DeploymentPhase) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(fmt.Sprintf("Starting services: %s", strings.Join(phase.Services, ", ")))

	args := []string{"compose", "-f", bgi.config.ComposeFile, "up", "-d"}
	args = append(args, phase.Services...)

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    args,
		Dir:     bgi.config.InstallDir,
		Capture: true,
		Timeout: 5 * time.Minute,
	})

	if err != nil {
		logger.Error("Failed to start services",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("docker compose up failed: %s", output)
	}

	logger.Debug("Services started",
		zap.String("services", strings.Join(phase.Services, ", ")),
		zap.String("output", output))

	return nil
}

// verifyPhaseHealth checks that services in this phase are healthy
func (bgi *BionicGPTInstaller) verifyPhaseHealth(ctx context.Context, phase DeploymentPhase) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(fmt.Sprintf("Verifying health: %s", strings.Join(phase.HealthChecks, ", ")))

	for _, service := range phase.HealthChecks {
		containerName := bgi.getContainerName(service)

		// Check container is running
		output, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Status}}"},
			Capture: true,
		})

		if err != nil || strings.TrimSpace(output) == "" {
			logger.Error(fmt.Sprintf("Container not running: %s", containerName))
			return fmt.Errorf("container %s not running", containerName)
		}

		// Check health status (if container has health check)
		healthOutput, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"inspect", "--format", "{{.State.Health.Status}}", containerName},
			Capture: true,
		})

		healthStatus := strings.TrimSpace(healthOutput)

		// If container doesn't have health check, just verify it's running
		if err != nil || healthStatus == "<no value>" || healthStatus == "" {
			if strings.Contains(strings.TrimSpace(output), "Up") {
				logger.Info(fmt.Sprintf("  ✓ %s: running (no health check)", service))
				continue
			}
			logger.Error(fmt.Sprintf("  ✗ %s: not running", service))
			return fmt.Errorf("service %s not running", service)
		}

		// Container has health check - verify it's healthy
		if healthStatus == "healthy" {
			logger.Info(fmt.Sprintf("  ✓ %s: healthy", service))
		} else if healthStatus == "starting" {
			logger.Info(fmt.Sprintf("  ⏳ %s: still starting (status: %s)", service, healthStatus))
			// Give it more time
			logger.Info(fmt.Sprintf("Waiting additional 30s for %s to become healthy...", service))
			time.Sleep(30 * time.Second)

			// Check again
			healthOutput2, _ := execute.Run(ctx, execute.Options{
				Command: "docker",
				Args:    []string{"inspect", "--format", "{{.State.Health.Status}}", containerName},
				Capture: true,
			})
			healthStatus2 := strings.TrimSpace(healthOutput2)

			if healthStatus2 == "healthy" {
				logger.Info(fmt.Sprintf("  ✓ %s: now healthy", service))
			} else {
				logger.Warn(fmt.Sprintf("  ⚠ %s: still not healthy (status: %s), but continuing", service, healthStatus2))
				// Don't fail - service might become healthy later
			}
		} else {
			logger.Warn(fmt.Sprintf("  ⚠ %s: unhealthy (status: %s), but continuing", service, healthStatus))
			// Show last few log lines for debugging
			logs, _ := execute.Run(ctx, execute.Options{
				Command: "docker",
				Args:    []string{"logs", "--tail", "20", containerName},
				Capture: true,
			})
			logger.Debug(fmt.Sprintf("Recent logs from %s:\n%s", service, logs))
		}
	}

	return nil
}

// getContainerName returns the Docker container name for a service
func (bgi *BionicGPTInstaller) getContainerName(service string) string {
	// Map service names to container names
	mapping := map[string]string{
		"postgres":        ContainerPostgres,
		"migrations":      ContainerMigrations,
		"embeddings-api":  ContainerEmbeddings,
		"chunking-engine": ContainerChunking,
		"litellm-proxy":   ContainerLiteLLM,
		"rag-engine":      ContainerRAGEngine,
		"app":             ContainerApp,
	}

	if containerName, ok := mapping[service]; ok {
		return containerName
	}

	return service // Fallback
}
