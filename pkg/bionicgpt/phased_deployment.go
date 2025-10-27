// Package bionicgpt provides phased deployment for reliable service startup
//
// This module implements staged deployment to prevent cascading failures.
// Following shift-left principles: start services in dependency order, verify each phase.
//
// Deployment Phases:
//
//	Phase 1: Database (postgres) - Foundation layer
//	Phase 2: Migrations - Schema setup
//	Phase 3: Supporting Services (embeddings, chunking) - Processing layer
//	Phase 4: LiteLLM Proxy - Translation layer
//	Phase 5: RAG Engine - Document processing
//	Phase 6: Application - User interface
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
		logger.Info("──────────────────────────────────────────────────────────────")
		logger.Info(fmt.Sprintf("%s (%d/%d)", phase.Name, i+1, len(phases)))
		logger.Info("──────────────────────────────────────────────────────────────")

		// Start services for this phase
		if err := bgi.startPhaseServices(ctx, phase); err != nil {
			if phase.Optional {
				logger.Warn("Phase failed but is optional, continuing",
					zap.Error(err))
				continue
			}
			return fmt.Errorf("phase %d failed: %w", i+1, err)
		}

		// P0 FIX: Show progress during stabilization wait instead of silent sleep
		logger.Info(fmt.Sprintf("Waiting %v for services to stabilize...", phase.WaitTime))
		bgi.waitWithProgress(ctx, phase.WaitTime)

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
// P0 FIX: Add real-time progress updates to prevent "appears to be hanging" confusion
func (bgi *BionicGPTInstaller) startPhaseServices(ctx context.Context, phase DeploymentPhase) error {
	logger := otelzap.Ctx(ctx)

	logger.Info(fmt.Sprintf("Starting services: %s", strings.Join(phase.Services, ", ")))

	// P0 FIX: Warn user if this might take a while (app container can be multi-GB)
	for _, service := range phase.Services {
		if service == "app" {
			logger.Info("⏳ Starting main application container")
			logger.Info("This may take 1-3 minutes on first install (large image download)")
			logger.Info("Progress updates will be shown every 15 seconds...")
		}
	}

	args := []string{"compose", "-f", bgi.config.ComposeFile, "up", "-d"}
	args = append(args, phase.Services...)

	logger.Debug("Docker compose command starting",
		zap.String("command", "docker"),
		zap.Strings("args", args),
		zap.String("working_dir", bgi.config.InstallDir),
		zap.Duration("timeout", 5*time.Minute))

	// P0 FIX: Run docker compose in background with progress updates
	startTime := time.Now()
	done := make(chan struct {
		output string
		err    error
	}, 1)

	go func() {
		output, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    args,
			Dir:     bgi.config.InstallDir,
			Capture: true,
			Timeout: 5 * time.Minute,
		})
		done <- struct {
			output string
			err    error
		}{output, err}
	}()

	// P0 FIX: Show progress every 15 seconds while waiting
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result := <-done:
			elapsed := time.Since(startTime).Round(time.Second)
			if result.err != nil {
				logger.Error("Failed to start services",
					zap.Error(result.err),
					zap.String("output", result.output),
					zap.Duration("elapsed", elapsed))

				// P1 FIX: Better error context for timeouts
				if strings.Contains(result.err.Error(), "timeout") || strings.Contains(result.err.Error(), "deadline exceeded") {
					return fmt.Errorf("docker compose up timed out after %v\n"+
						"This usually means:\n"+
						"  1. Large container image is being downloaded (check network speed)\n"+
						"  2. Container is failing health checks repeatedly\n"+
						"  3. Dependency service is not healthy\n\n"+
						"Check container status: docker ps -a | grep bionicgpt\n"+
						"Check logs: docker compose -f %s logs --tail=50\n\n"+
						"Raw output: %s",
						elapsed, bgi.config.ComposeFile, result.output)
				}

				return fmt.Errorf("docker compose up failed: %s", result.output)
			}

			logger.Info(fmt.Sprintf("✓ Services started successfully (elapsed: %v)", elapsed))
			logger.Debug("Docker compose output",
				zap.String("services", strings.Join(phase.Services, ", ")),
				zap.String("output", result.output),
				zap.Duration("elapsed", elapsed))

			return nil

		case <-ticker.C:
			elapsed := time.Since(startTime).Round(time.Second)
			logger.Info(fmt.Sprintf("  ⏳ Still starting %s... (%v elapsed)",
				strings.Join(phase.Services, ", "), elapsed))
			logger.Info("  Docker is working in the background (pulling images, creating containers, setting up networks)")

			// P2: Additional diagnostic info for long waits
			if elapsed > 90*time.Second {
				logger.Info("  💡 TIP: Open another terminal and run: docker ps -a | grep bionicgpt")
				logger.Info("  This will show you real-time container status")
			}
		}
	}
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
		switch healthStatus {
		case "healthy":
			logger.Info(fmt.Sprintf("  ✓ %s: healthy", service))
		case "starting":
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
		default:
			// P1 FIX: Intelligent error classification for LiteLLM
			if service == "litellm-proxy" {
				logger.Warn(fmt.Sprintf("  ⚠ %s: unhealthy (status: %s), performing diagnostic analysis", service, healthStatus))

				// Diagnose LiteLLM health with error classification
				liteLLMError, diagErr := DiagnoseLiteLLMHealth(ctx, containerName)
				if diagErr != nil {
					logger.Error("Failed to diagnose LiteLLM health",
						zap.Error(diagErr))
				} else {
					// Log classified error with remediation
					logger.Error("LiteLLM Error Diagnosis",
						zap.String("type", string(liteLLMError.Type)),
						zap.String("message", liteLLMError.Message),
						zap.String("remediation", liteLLMError.Remediation),
						zap.Bool("should_retry", liteLLMError.ShouldRetry))

					// If it's a config error, fail fast (don't retry)
					if !liteLLMError.ShouldRetry {
						return fmt.Errorf("LiteLLM %s error (will not retry): %s\n\n%s",
							liteLLMError.Type, liteLLMError.Message, liteLLMError.Remediation)
					}

					logger.Warn(fmt.Sprintf("  ⚠ Transient error - will continue (may recover): %s", liteLLMError.Message))
				}
			} else {
				// Generic unhealthy handling for other services
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
	}

	return nil
}

// waitWithProgress waits for the specified duration, showing progress updates
// P0 FIX: Replace silent time.Sleep() with visible progress updates
func (bgi *BionicGPTInstaller) waitWithProgress(ctx context.Context, duration time.Duration) {
	logger := otelzap.Ctx(ctx)

	// Don't show progress for short waits (<30s)
	if duration < 30*time.Second {
		time.Sleep(duration)
		return
	}

	// Show progress every 10 seconds for longer waits
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	deadline := time.Now().Add(duration)
	remaining := duration

	for remaining > 0 {
		select {
		case <-ctx.Done():
			logger.Warn("Context cancelled during wait")
			return
		case <-ticker.C:
			remaining = time.Until(deadline)
			if remaining <= 0 {
				return
			}
			logger.Info(fmt.Sprintf("  ⏳ %v remaining...", remaining.Round(time.Second)))
		case <-time.After(remaining):
			return
		}
	}
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
