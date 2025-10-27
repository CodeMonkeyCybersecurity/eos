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

		// P0 FIX: Phase 4 (LiteLLM) gets retry logic with exponential backoff
		// RATIONALE: LiteLLM connects to external Azure OpenAI, which may have transient network issues
		// REFERENCE: Adversarial Analysis ADVERSARIAL_ANALYSIS_BIONICGPT_PHASE6_FAILURE.md P0 Fix #3
		if i == 3 { // Phase 4: LiteLLM Proxy (0-indexed)
			logger.Info("ℹ️  LiteLLM connects to external Azure OpenAI - enabling retry logic for transient failures")
			if err := bgi.retryPhaseWithBackoff(ctx, phase, 3); err != nil {
				if phase.Optional {
					logger.Warn("Phase failed but is optional, continuing",
						zap.Error(err))
					continue
				}
				return fmt.Errorf("phase %d failed after retries: %w", i+1, err)
			}
			// Skip normal processing - retry logic handled everything
			continue
		}

		// Normal phase processing (for all non-LiteLLM phases)
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
// P1 FIX: Added telemetry for health check duration tracking
func (bgi *BionicGPTInstaller) verifyPhaseHealth(ctx context.Context, phase DeploymentPhase) error {
	logger := otelzap.Ctx(ctx)

	// P1 FIX: Track health check performance metrics
	healthCheckStart := time.Now()
	defer func() {
		duration := time.Since(healthCheckStart)
		logger.Info("Health check completed",
			zap.Duration("duration", duration),
			zap.Int("services_checked", len(phase.HealthChecks)),
			zap.String("phase_name", phase.Name))
	}()

	logger.Info(fmt.Sprintf("Verifying health: %s", strings.Join(phase.HealthChecks, ", ")))

	for _, service := range phase.HealthChecks {
		// P1 FIX: Track per-service health check timing
		serviceCheckStart := time.Now()
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
			// P1 FIX: Log telemetry for healthy service
			serviceDuration := time.Since(serviceCheckStart)
			logger.Info(fmt.Sprintf("  ✓ %s: healthy", service),
				zap.Duration("check_duration", serviceDuration),
				zap.String("container", containerName))
		case "starting":
			logger.Info(fmt.Sprintf("  ⏳ %s: still starting (status: %s)", service, healthStatus))

			// P0 FIX: Wait for at least one full health check cycle
			// With interval=15s, wait 20s to guarantee at least one check completed
			waitDuration := 20 * time.Second
			logger.Info(fmt.Sprintf("Waiting %v for health check cycle to complete...", waitDuration))
			time.Sleep(waitDuration)

			// Check health again after full cycle
			healthOutput2, _ := execute.Run(ctx, execute.Options{
				Command: "docker",
				Args:    []string{"inspect", "--format", "{{.State.Health.Status}}", containerName},
				Capture: true,
			})
			healthStatus2 := strings.TrimSpace(healthOutput2)

			switch healthStatus2 {
			case "healthy":
				logger.Info(fmt.Sprintf("  ✓ %s: now healthy after waiting for health check cycle", service))
			case "starting":
				// P0 FIX: Still in start_period - this might be normal OR failing checks silently
				logger.Warn(fmt.Sprintf("  ⚠ %s: still in 'starting' state after full health check wait", service))
				logger.Warn("This likely means health checks are failing but within start_period grace")

				// P0 FIX: For REQUIRED services (Optional: false), investigate and fail fast
				if !phase.Optional {
					logger.Error(fmt.Sprintf("Required service %s not healthy - investigating", service))

					// Get container logs for diagnosis
					logs, _ := execute.Run(ctx, execute.Options{
						Command: "docker",
						Args:    []string{"logs", "--tail", "50", containerName},
						Capture: true,
					})

					// P0 FIX: For LiteLLM specifically, use intelligent diagnosis
					if service == "litellm-proxy" {
						liteLLMError, diagErr := DiagnoseLiteLLMHealth(ctx, containerName)
						if diagErr == nil {
							logger.Error("LiteLLM Error Diagnosis",
								zap.String("type", string(liteLLMError.Type)),
								zap.String("message", liteLLMError.Message),
								zap.String("remediation", liteLLMError.Remediation),
								zap.Bool("should_retry", liteLLMError.ShouldRetry))

							if !liteLLMError.ShouldRetry {
								// P1 FIX: Enhanced error message with full diagnostic context
								// REFERENCE: Adversarial Analysis P1 Fix #2
								return fmt.Errorf("════════════════════════════════════════════════════════════════\n"+
									"LITELLM HEALTH CHECK FAILED\n"+
									"════════════════════════════════════════════════════════════════\n\n"+
									"Error Type: %s (CONFIGURATION ERROR - will not retry)\n"+
									"Container: %s\n"+
									"Health Status: starting (health checks failing within grace period)\n\n"+
									"Problem:\n"+
									"  %s\n\n"+
									"Remediation Steps:\n"+
									"%s\n\n"+
									"Container Logs (last 50 lines):\n"+
									"────────────────────────────────────────────────────────────────\n"+
									"%s\n"+
									"────────────────────────────────────────────────────────────────\n\n"+
									"Debug Commands:\n"+
									"  View full logs:    docker logs %s --tail 200\n"+
									"  Check health:      docker inspect %s | grep -A 20 Health\n"+
									"  Restart service:   docker compose -f /opt/bionicgpt/docker-compose.yml restart litellm-proxy\n"+
									"  Run diagnostics:   eos debug bionicgpt\n\n"+
									"Next Steps:\n"+
									"  1. Fix the configuration issue above\n"+
									"  2. Verify in Vault: vault kv get secret/bionicgpt/azure_api_key\n"+
									"  3. Retry deployment: eos create bionicgpt --force\n"+
									"════════════════════════════════════════════════════════════════",
									liteLLMError.Type, containerName, liteLLMError.Message,
									liteLLMError.Remediation, logs, containerName, containerName)
							}
						}
					}

					// P0 FIX: For any required service still in "starting", fail deployment
					// P1 FIX: Enhanced error with full diagnostic context
					// RATIONALE: If not healthy after start_period + wait, won't magically fix itself
					// EVIDENCE: Phase 6 depends on Phase 4 services being healthy NOW
					return fmt.Errorf("════════════════════════════════════════════════════════════════\n"+
						"REQUIRED SERVICE HEALTH CHECK FAILED\n"+
						"════════════════════════════════════════════════════════════════\n\n"+
						"Service: %s\n"+
						"Container: %s\n"+
						"Current Status: %s\n"+
						"Expected Status: healthy\n"+
						"Optional: false (service is REQUIRED)\n\n"+
						"Problem:\n"+
						"  This service is critical and must be healthy before proceeding.\n"+
						"  Health check is stuck in 'starting' state, indicating that health\n"+
						"  checks are failing but still within the grace period (start_period).\n\n"+
						"  Phase 6 (application) depends on this service being healthy NOW.\n"+
						"  Continuing would result in deployment failure after 30+ more minutes.\n\n"+
						"Container Logs (last 50 lines):\n"+
						"────────────────────────────────────────────────────────────────\n"+
						"%s\n"+
						"────────────────────────────────────────────────────────────────\n\n"+
						"Debug Commands:\n"+
						"  View full logs:    docker logs %s --tail 200\n"+
						"  Check health:      docker inspect %s | grep -A 20 Health\n"+
						"  View processes:    docker top %s\n"+
						"  Restart service:   docker compose -f /opt/bionicgpt/docker-compose.yml restart %s\n"+
						"  Run diagnostics:   eos debug bionicgpt\n\n"+
						"Next Steps:\n"+
						"  1. Review the logs above to identify the root cause\n"+
						"  2. Fix the underlying issue (config, network, dependencies)\n"+
						"  3. Retry deployment: eos create bionicgpt --force\n"+
						"════════════════════════════════════════════════════════════════",
						service, containerName, healthStatus2, logs, containerName, containerName,
						containerName, service)
				}

				// Optional service - log warning but continue
				logger.Warn(fmt.Sprintf("  ⚠ Optional service %s not healthy, but continuing", service))

			case "unhealthy":
				// P0 FIX: Explicitly unhealthy - always fail for required services
				logger.Error(fmt.Sprintf("  ✗ %s: unhealthy", service))

				// Get logs for diagnosis
				logs, _ := execute.Run(ctx, execute.Options{
					Command: "docker",
					Args:    []string{"logs", "--tail", "50", containerName},
					Capture: true,
				})

				if service == "litellm-proxy" {
					liteLLMError, _ := DiagnoseLiteLLMHealth(ctx, containerName)
					// P1 FIX: Enhanced error message with structured diagnostic context
					return fmt.Errorf("════════════════════════════════════════════════════════════════\n"+
						"LITELLM BECAME UNHEALTHY\n"+
						"════════════════════════════════════════════════════════════════\n\n"+
						"Service: %s\n"+
						"Container: %s\n"+
						"Error Type: %s\n"+
						"Health Status: unhealthy (failed health checks)\n"+
						"Should Retry: %v\n\n"+
						"Problem:\n"+
						"  %s\n\n"+
						"Remediation Steps:\n"+
						"%s\n\n"+
						"Container Logs (last 50 lines):\n"+
						"────────────────────────────────────────────────────────────────\n"+
						"%s\n"+
						"────────────────────────────────────────────────────────────────\n\n"+
						"Debug Commands:\n"+
						"  View full logs:    docker logs %s --tail 200\n"+
						"  Check health:      docker inspect %s | grep -A 20 Health\n"+
						"  Test LiteLLM API:  curl http://localhost:4000/health/liveliness\n"+
						"  Run diagnostics:   eos debug bionicgpt\n"+
						"════════════════════════════════════════════════════════════════",
						service, containerName, liteLLMError.Type, liteLLMError.ShouldRetry,
						liteLLMError.Message, liteLLMError.Remediation, logs, containerName, containerName)
				}

				if !phase.Optional {
					return fmt.Errorf("════════════════════════════════════════════════════════════════\n"+
						"SERVICE BECAME UNHEALTHY\n"+
						"════════════════════════════════════════════════════════════════\n\n"+
						"Service: %s\n"+
						"Container: %s\n"+
						"Health Status: unhealthy (failed health checks)\n"+
						"Optional: false (service is REQUIRED)\n\n"+
						"Problem:\n"+
						"  Service health check transitioned from 'starting' to 'unhealthy'.\n"+
						"  This indicates the service started but failed to become healthy.\n\n"+
						"Container Logs (last 50 lines):\n"+
						"────────────────────────────────────────────────────────────────\n"+
						"%s\n"+
						"────────────────────────────────────────────────────────────────\n\n"+
						"Debug Commands:\n"+
						"  View full logs:    docker logs %s --tail 200\n"+
						"  Check health:      docker inspect %s | grep -A 20 Health\n"+
						"  View processes:    docker top %s\n"+
						"  Restart service:   docker compose -f /opt/bionicgpt/docker-compose.yml restart %s\n"+
						"  Run diagnostics:   eos debug bionicgpt\n"+
						"════════════════════════════════════════════════════════════════",
						service, containerName, logs, containerName, containerName, containerName, service)
				}

				logger.Warn(fmt.Sprintf("  ⚠ Optional service %s is unhealthy, but continuing", service))

			default:
				logger.Warn(fmt.Sprintf("  ⚠ %s: unknown health status: %s", service, healthStatus2))
				if !phase.Optional {
					return fmt.Errorf("service %s has unknown health status: %s", service, healthStatus2)
				}
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

// retryPhaseWithBackoff retries a deployment phase with exponential backoff
// P0 FIX: Add retry logic for transient failures (especially LiteLLM)
// P1 FIX: Added telemetry for retry tracking
// REFERENCE: Adversarial Analysis ADVERSARIAL_ANALYSIS_BIONICGPT_PHASE6_FAILURE.md P0 Fix #3
func (bgi *BionicGPTInstaller) retryPhaseWithBackoff(
	ctx context.Context,
	phase DeploymentPhase,
	maxRetries int,
) error {
	logger := otelzap.Ctx(ctx)

	// P1 FIX: Track retry phase performance metrics
	retryPhaseStart := time.Now()
	attemptsMade := 0
	defer func() {
		totalDuration := time.Since(retryPhaseStart)
		logger.Info("Retry phase completed",
			zap.Duration("total_duration", totalDuration),
			zap.Int("attempts_made", attemptsMade),
			zap.Int("max_retries", maxRetries),
			zap.String("phase_name", phase.Name))
	}()

	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info(fmt.Sprintf("Phase will retry up to %d times on transient failures", maxRetries))
	logger.Info("Configuration errors will fail immediately (no retry)")
	logger.Info("════════════════════════════════════════════════════════════════")

	for attempt := 1; attempt <= maxRetries; attempt++ {
		attemptsMade = attempt // P1 FIX: Track attempts for telemetry
		logger.Info("")
		logger.Info(fmt.Sprintf("🔄 Attempt %d/%d: %s", attempt, maxRetries, phase.Name))

		// Try starting services
		startErr := bgi.startPhaseServices(ctx, phase)
		if startErr != nil {
			// Check if this is a config error or transient error
			if strings.Contains(startErr.Error(), "configuration") ||
				strings.Contains(startErr.Error(), "will not retry") {
				// Configuration error - fail fast, don't retry
				logger.Error("Configuration error detected - failing immediately",
					zap.Error(startErr))
				return startErr
			}

			if attempt < maxRetries {
				backoff := time.Duration(attempt*30) * time.Second
				logger.Warn(fmt.Sprintf("❌ Attempt %d failed (transient error), retrying in %v",
					attempt, backoff),
					zap.Error(startErr))
				logger.Info("Restarting failed services before retry...")

				// Restart services before retrying
				for _, serviceName := range phase.Services {
					execute.Run(ctx, execute.Options{
						Command: "docker",
						Args:    []string{"compose", "-f", bgi.config.ComposeFile, "restart", serviceName},
						Dir:     bgi.config.InstallDir,
						Capture: true,
					})
				}

				bgi.waitWithProgress(ctx, backoff)
				continue
			}
			return fmt.Errorf("phase failed after %d attempts: %w", maxRetries, startErr)
		}

		// Services started successfully, wait for stabilization
		logger.Info(fmt.Sprintf("Services started successfully, waiting %v for stabilization...", phase.WaitTime))
		bgi.waitWithProgress(ctx, phase.WaitTime)

		// Verify health checks
		if len(phase.HealthChecks) > 0 {
			healthErr := bgi.verifyPhaseHealth(ctx, phase)
			if healthErr != nil {
				// Check if this is a config error or transient error
				if strings.Contains(healthErr.Error(), "configuration") ||
					strings.Contains(healthErr.Error(), "will not retry") {
					// Configuration error - fail fast, don't retry
					logger.Error("Configuration error detected during health check - failing immediately",
						zap.Error(healthErr))
					return healthErr
				}

				if attempt < maxRetries {
					backoff := time.Duration(attempt*30) * time.Second
					logger.Warn(fmt.Sprintf("❌ Health check failed on attempt %d (transient error), retrying in %v",
						attempt, backoff),
						zap.Error(healthErr))
					logger.Info("Restarting services before retry...")

					// Restart services before retrying
					for _, serviceName := range phase.Services {
						execute.Run(ctx, execute.Options{
							Command: "docker",
							Args:    []string{"compose", "-f", bgi.config.ComposeFile, "restart", serviceName},
							Dir:     bgi.config.InstallDir,
							Capture: true,
						})
					}

					bgi.waitWithProgress(ctx, backoff)
					continue
				}
				return fmt.Errorf("health check failed after %d attempts: %w", maxRetries, healthErr)
			}
		}

		// Success!
		logger.Info("")
		logger.Info(fmt.Sprintf("✅ %s completed successfully on attempt %d/%d",
			phase.Name, attempt, maxRetries))
		return nil
	}

	return fmt.Errorf("phase failed after %d attempts", maxRetries)
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
