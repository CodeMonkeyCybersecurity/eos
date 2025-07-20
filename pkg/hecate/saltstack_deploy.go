// pkg/hecate/saltstack_deploy.go

package hecate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/sizing"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployWithSaltStack deploys Hecate using SaltStack orchestration
func DeployWithSaltStack(rc *eos_io.RuntimeContext) error {
	return DeployWithSaltStackAndServices(rc, nil)
}

// DeployWithSaltStackAndServices deploys Hecate with optional additional services
func DeployWithSaltStackAndServices(rc *eos_io.RuntimeContext, requestedServices []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate deployment with SaltStack",
		zap.Strings("additional_services", requestedServices))

	// ASSESS - Check if system is bootstrapped first
	logger.Info("Checking system bootstrap status")
	if !bootstrap.IsSystemBootstrapped() {
		logger.Info("System not bootstrapped, prompting user")
		shouldBootstrap, err := bootstrap.PromptForBootstrap(rc)
		if err != nil {
			return fmt.Errorf("bootstrap prompt failed: %w", err)
		}
		
		if shouldBootstrap {
			// Run bootstrap command
			logger.Info("Running system bootstrap")
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "eos",
				Args:    []string{"bootstrap"},
			})
			if err != nil {
				return fmt.Errorf("bootstrap failed: %w", err)
			}
			
			// Mark system as bootstrapped
			if err := bootstrap.MarkSystemAsBootstrapped(rc); err != nil {
				logger.Warn("Failed to mark system as bootstrapped", zap.Error(err))
			}
		} else {
			return eos_err.NewUserError("hecate deployment requires a bootstrapped system")
		}
	}

	// ASSESS - Perform hardware sizing preflight check
	logger.Info("Performing hardware sizing validation")
	
	// Use systematic approach to validate hardware requirements  
	// Calculate requirements for small production Hecate deployment
	breakdown, err := sizing.CalculateHecateRequirements(rc, "small_production")
	if err != nil {
		logger.Warn("Could not calculate systematic requirements, using manual validation", zap.Error(err))
		// Fall back to a simple manual check if calculation fails
		return checkManualHecateRequirements(rc)
	}
	
	// Calculate requirements with debug logging for verbose details
	logger.Debug("Calculated Hecate requirements",
		zap.Float64("cpu_cores", breakdown.FinalRequirements.CPU),
		zap.Float64("memory_gb", breakdown.FinalRequirements.Memory),
		zap.Float64("storage_gb", breakdown.FinalRequirements.Storage))
	
	// Generate a report for the user
	report, err := sizing.GenerateHecateRecommendationReport(rc, "small_production")
	if err == nil {
		logger.Debug("Hecate sizing report generated",
			zap.String("report_length", fmt.Sprintf("%d chars", len(report))))
		// Log key points from the report (but don't flood the log)
		lines := strings.Split(report, "\n")
		for i, line := range lines {
			if i < 10 && strings.TrimSpace(line) != "" { // Show first 10 non-empty lines
				logger.Info("terminal prompt: " + line)
			}
		}
	}
	
	// Perform basic validation - just ensure we have minimum viable resources
	if err := checkManualHecateRequirements(rc); err != nil {
		return fmt.Errorf("hardware requirements check failed: %w", err)
	}

	// ASSESS - Run comprehensive preflight checks
	preflightResult, err := PreflightChecks(rc)
	if err != nil {
		return fmt.Errorf("preflight checks failed: %w", err)
	}

	// Handle any missing dependencies interactively
	if !preflightResult.CanProceed {
		if err := InteractivelyHandleDependencies(rc, preflightResult); err != nil {
			return err
		}
		
		// Re-run preflight checks after installations
		preflightResult, err = PreflightChecks(rc)
		if err != nil {
			return fmt.Errorf("preflight checks failed after dependency installation: %w", err)
		}
		
		if !preflightResult.CanProceed {
			return eos_err.NewUserError("Cannot proceed with deployment - critical issues remain unresolved")
		}
	}

	// Initialize state manager for tracking deployment progress
	stateManager := NewStateManager(rc)

	// Set up rollback handler
	var completedPhases []string
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Deployment panic, initiating rollback",
				zap.Any("error", r),
				zap.Strings("completed_phases", completedPhases))
			rollbackDeployment(rc, completedPhases)
		}
	}()

	// INTERVENE - Apply Salt states in phases
	logger.Info("Applying SaltStack states for Hecate deployment")

	// Define deployment phases in order
	phases := []struct {
		name        string
		state       string
		description string
		critical    bool
		healthCheck func(*eos_io.RuntimeContext) error
	}{
		{
			name:        "hashicorp_stack",
			state:       "hecate.prereqs",
			description: "Ensuring HashiCorp stack (Consul, Vault, Nomad) is ready",
			critical:    true,
			healthCheck: checkHashiCorpStack,
		},
		{
			name:        "hybrid_secrets",
			state:       "hecate.hybrid_secrets",
			description: "Creating secrets for Hecate components (Vault or Salt pillar)",
			critical:    true,
			healthCheck: checkVaultSecrets,
		},
		{
			name:        "postgres",
			state:       "hecate.authentik.database",
			description: "Deploying PostgreSQL for Authentik",
			critical:    true,
			healthCheck: checkPostgres,
		},
		{
			name:        "redis",
			state:       "hecate.authentik.redis",
			description: "Deploying Redis for Authentik sessions",
			critical:    true,
			healthCheck: checkRedis,
		},
		{
			name:        "authentik",
			state:       "hecate.authentik.install",
			description: "Deploying Authentik identity provider",
			critical:    true,
			healthCheck: checkAuthentik,
		},
		{
			name:        "caddy",
			state:       "hecate.caddy",
			description: "Deploying Caddy reverse proxy",
			critical:    true,
			healthCheck: checkCaddy,
		},
		{
			name:        "integration",
			state:       "hecate.integration",
			description: "Configuring Caddy-Authentik integration",
			critical:    true,
			healthCheck: checkIntegration,
		},
	}

	// Execute each phase with error handling and health checks
	for _, phase := range phases {
		logger.Info("Executing deployment phase",
			zap.String("phase", phase.name),
			zap.String("description", phase.description))

		// Update state manager
		if err := stateManager.UpdatePhase(phase.name, "in_progress"); err != nil {
			logger.Warn("Failed to update state", zap.Error(err))
		}

		// Apply Salt state with enhanced retry logic and better error handling
		retries := 3
		var lastErr error
		baseBackoff := 10 * time.Second

		for attempt := 1; attempt <= retries; attempt++ {
			logger.Info("Applying Salt state",
				zap.String("phase", phase.name),
				zap.String("state", phase.state),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", retries))

			// Enhanced Salt arguments for better output and debugging
			args := []string{
				"state.apply",
				phase.state,
				"--output=json",
				"--log-level=info",
				"--state-output=changes",
				"--timeout=300", // 5 minute timeout per state
			}

			// Run Salt state with timeout protection
			output, err := execute.Run(rc.Ctx, execute.Options{
				Command: "salt-call",
				Args:    args,
				Capture: true,
			})

			if err == nil {
				logger.Info("Salt state execution succeeded",
					zap.String("phase", phase.name),
					zap.String("state", phase.state))

				// Log detailed output for debugging
				logger.Debug("Salt state execution result",
					zap.String("phase", phase.name),
					zap.String("output", output))

				// Run health check for this phase with retry logic
				if phase.healthCheck != nil {
					logger.Info("Running health check for phase",
						zap.String("phase", phase.name))

					healthCheckRetries := 3
					var healthErr error

					for healthAttempt := 1; healthAttempt <= healthCheckRetries; healthAttempt++ {
						healthErr = phase.healthCheck(rc)
						if healthErr == nil {
							logger.Debug("Health check passed",
								zap.String("phase", phase.name),
								zap.Int("health_attempt", healthAttempt))
							break
						}

						if healthAttempt < healthCheckRetries {
							logger.Warn("Health check failed, retrying",
								zap.String("phase", phase.name),
								zap.Error(healthErr),
								zap.Int("health_attempt", healthAttempt))
							time.Sleep(time.Duration(healthAttempt*5) * time.Second)
						}
					}

					if healthErr != nil {
						lastErr = fmt.Errorf("health check failed for %s after %d attempts: %w", phase.name, healthCheckRetries, healthErr)
						if attempt < retries {
							logger.Warn("Health check failed after all retries, retrying entire phase",
								zap.String("phase", phase.name),
								zap.Error(healthErr),
								zap.Int("attempt", attempt))
							time.Sleep(baseBackoff * time.Duration(attempt))
							continue
						}
					}
				}

				// Phase completed successfully
				completedPhases = append(completedPhases, phase.name)
				if err := stateManager.UpdatePhase(phase.name, "completed"); err != nil {
					logger.Warn("Failed to update state", zap.Error(err))
				}

				logger.Info("Phase completed successfully",
					zap.String("phase", phase.name))
				break
			}

			// Salt state execution failed
			lastErr = fmt.Errorf("salt state %s failed: %w", phase.state, err)
			logger.Error("Salt state execution failed",
				zap.String("phase", phase.name),
				zap.String("state", phase.state),
				zap.Error(err),
				zap.String("output", output),
				zap.Int("attempt", attempt))

			if attempt < retries {
				backoffDuration := baseBackoff * time.Duration(attempt)
				logger.Warn("Retrying phase after backoff",
					zap.String("phase", phase.name),
					zap.Duration("backoff", backoffDuration),
					zap.Int("attempt", attempt))
				time.Sleep(backoffDuration)

				// Try to recover by checking service states
				if err := recoverPhase(rc, phase.name); err != nil {
					logger.Warn("Phase recovery failed",
						zap.String("phase", phase.name),
						zap.Error(err))
				}
			}
		}

		// Check if phase failed after all retries
		if lastErr != nil {
			if err := stateManager.UpdatePhase(phase.name, "failed"); err != nil {
				logger.Warn("Failed to update state", zap.Error(err))
			}

			if phase.critical {
				// Critical phase failed, initiate rollback
				logger.Error("Critical phase failed, initiating rollback",
					zap.String("phase", phase.name),
					zap.Error(lastErr))

				if err := rollbackDeployment(rc, completedPhases); err != nil {
					logger.Error("Rollback failed", zap.Error(err))
				}

				return fmt.Errorf("deployment failed at phase %s: %w", phase.name, lastErr)
			} else {
				// Non-critical phase failed, continue
				logger.Warn("Non-critical phase failed, continuing",
					zap.String("phase", phase.name),
					zap.Error(lastErr))
			}
		}
	}

	// Deploy additional services if requested
	if len(requestedServices) > 0 {
		logger.Info("Deploying additional services",
			zap.Strings("services", requestedServices))
		
		// Resolve service dependencies
		allServices := resolveServiceDependencies(requestedServices)
		logger.Info("Resolved service dependencies",
			zap.Strings("all_services", allServices))
		
		// Deploy each service
		for _, serviceName := range allServices {
			service, exists := GetService(serviceName)
			if !exists {
				logger.Warn("Unknown service requested, skipping",
					zap.String("service", serviceName))
				continue
			}
			
			logger.Info("Deploying service",
				zap.String("service", serviceName),
				zap.String("display_name", service.DisplayName))
			
			// Deploy service using Nomad if job path is specified
			if service.NomadJobPath != "" {
				if err := deployServiceWithNomad(rc, service); err != nil {
					logger.Error("Failed to deploy service",
						zap.String("service", serviceName),
						zap.Error(err))
					// Continue with other services even if one fails
					continue
				}
			}
			
			// Create Hecate route for the service
			if service.Subdomain != "" {
				if err := createServiceRoute(rc, service); err != nil {
					logger.Error("Failed to create route for service",
						zap.String("service", serviceName),
						zap.Error(err))
				}
			}
			
			completedPhases = append(completedPhases, "service_"+serviceName)
		}
	}

	// EVALUATE - Verify complete deployment
	if err := verifyDeployment(rc); err != nil {
		return fmt.Errorf("deployment verification failed: %w", err)
	}

	// Update final state
	if err := stateManager.SetDeploymentComplete(); err != nil {
		logger.Warn("Failed to update deployment state", zap.Error(err))
	}

	// EVALUATE - Skip the cluster-oriented postflight validation for single-node Hecate
	logger.Info("Deployment validation completed")

	logger.Info("Hecate deployment completed successfully")
	return nil
}

// assessPrerequisites checks that all required services are available and attempts to install missing ones
// DEPRECATED: This function is replaced by PreflightChecks() which provides more comprehensive validation
// This is kept for backward compatibility but should not be used directly
func assessPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing prerequisites for Hecate deployment")

	// Check for required services with detailed diagnostics
	requiredServices := []struct {
		name        string
		installCmd  string
		description string
	}{
		{name: "nomad", installCmd: "nomad", description: "HashiCorp Nomad orchestrator"},
		{name: "consul", installCmd: "consul", description: "HashiCorp Consul service mesh"},
		{name: "vault", installCmd: "vault", description: "HashiCorp Vault secrets management"},
		{name: "salt-minion", installCmd: "saltstack", description: "SaltStack configuration management"},
	}

	for _, service := range requiredServices {
		logger.Debug("Checking service", zap.String("service", service.name))

		// First check if service is installed
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"list-unit-files", service.name + ".service"},
			Capture: true,
		})
		if err != nil || !strings.Contains(output, service.name+".service") {
			// Service not installed - attempt to install it
			logger.Warn("Required service not installed, attempting automatic installation",
				zap.String("service", service.name),
				zap.String("description", service.description))

			// Install the missing service
			logger.Info("terminal prompt: ⚠️  Missing dependency detected: " + service.description)
			logger.Info("terminal prompt: Installing " + service.name + " automatically...")

			if err := installMissingService(rc, service.installCmd); err != nil {
				logger.Error("Failed to install service automatically",
					zap.String("service", service.name),
					zap.Error(err))
				return eos_err.NewUserError("Failed to install %s automatically: %v\n\nPlease install manually:\n  eos create %s",
					service.name, err, service.installCmd)
			}

			// Wait a moment for service to stabilize
			time.Sleep(5 * time.Second)
		}

		// Check if service is active
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service.name},
			Capture: true,
		})
		if err != nil || strings.TrimSpace(output) != "active" {
			// Try to start the service
			logger.Warn("Service not active, attempting to start",
				zap.String("service", service.name),
				zap.String("status", strings.TrimSpace(output)))

			_, startErr := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"start", service.name},
				Capture: true,
			})

			if startErr != nil {
				// Get detailed status for better error reporting
				statusOutput, _ := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"status", service.name, "--no-pager", "-l"},
					Capture: true,
				})

				logger.Error("Failed to start service",
					zap.String("service", service.name),
					zap.Error(startErr))

				return eos_err.NewUserError("Required service %s could not be started.\nCurrent status: %s\n\nService details:\n%s\n\nPlease resolve the issue and try again",
					service.name, strings.TrimSpace(output), statusOutput)
			}

			// Wait for service to fully start
			time.Sleep(3 * time.Second)

			// Verify it's now active
			output, err = execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"is-active", service.name},
				Capture: true,
			})
			if err != nil || strings.TrimSpace(output) != "active" {
				return eos_err.NewUserError("Service %s failed to start properly", service.name)
			}
		}

		logger.Info("Service check passed", zap.String("service", service.name))
	}

	// Check for SaltStack states
	stateFile := "/srv/salt/hecate/init.sls"
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "test",
		Args:    []string{"-f", stateFile},
		Capture: true,
	})
	if err != nil {
		logger.Info("SaltStack states not found, synchronizing from repository")

		// Sync Salt states from the Eos repository
		syncOutput, syncErr := execute.Run(rc.Ctx, execute.Options{
			Command: "salt-call",
			Args:    []string{"saltutil.sync_all"},
			Capture: true,
		})
		if syncErr != nil {
			return fmt.Errorf("failed to sync Salt states: %w", syncErr)
		}
		logger.Debug("Salt sync result", zap.String("output", syncOutput))
	}

	// Check Vault is unsealed (using correct port 8179)
	vaultOutput, err := executeVaultCommand(rc, []string{"status", "-format=json"}, true)
	if err != nil {
		// Check if it's just sealed (exit code 2) vs actually down
		if strings.Contains(err.Error(), "exit status 2") {
			logger.Warn("Vault is sealed, attempting to handle this condition")
			// In dev mode, we can continue as vault will auto-unseal
			// In production, this would need manual intervention
			logger.Info("terminal prompt: ⚠️  Vault is sealed. For production deployments, please unseal Vault manually.")
			logger.Info("terminal prompt: For dev mode, Vault should auto-unseal.")
		} else {
			return eos_err.NewUserError("vault is not accessible - ensure it is running")
		}
	} else {
		logger.Debug("Vault status", zap.String("output", vaultOutput))
	}

	// Check for existing Hecate deployment
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "hecate-caddy"},
		Capture: true,
	})
	if err == nil {
		logger.Warn("Existing Hecate deployment detected")
		logger.Info("terminal prompt: An existing Hecate deployment was found. Would you like to redeploy? [y/N]")

		response, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}

		if response != "y" && response != "Y" {
			return eos_err.NewUserError("deployment cancelled by user")
		}

		// Stop existing jobs
		logger.Info("Stopping existing Hecate jobs")
		jobs := []string{"hecate-caddy", "hecate-authentik-server", "hecate-authentik-worker", "hecate-redis", "hecate-postgres"}
		for _, job := range jobs {
			execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", job},
				Capture: true,
			})
		}

		// Wait for cleanup
		time.Sleep(10 * time.Second)
	}

	logger.Info("All prerequisites satisfied")
	return nil
}

// verifyDeployment checks that all Hecate components are running correctly
func verifyDeployment(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Hecate deployment")

	// Define expected jobs and their health endpoints
	type jobCheck struct {
		name     string
		endpoint string
		required bool
	}

	jobs := []jobCheck{
		{name: "hecate-postgres", endpoint: "", required: true},
		{name: "hecate-redis", endpoint: "", required: true},
		{name: "hecate-authentik-server", endpoint: fmt.Sprintf("http://localhost:%d/-/health/ready/", shared.PortAuthentik), required: true},
		{name: "hecate-authentik-worker", endpoint: "", required: true},
		{name: "hecate-caddy", endpoint: fmt.Sprintf("http://localhost:%d/health", shared.PortCaddyAdmin), required: true},
	}

	// Check each job status
	for _, job := range jobs {
		logger.Debug("Checking job status", zap.String("job", job.name))

		// Check Nomad job status
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-json", job.name},
			Capture: true,
		})
		if err != nil {
			if job.required {
				return fmt.Errorf("required job %s is not running", job.name)
			}
			logger.Warn("Optional job not running", zap.String("job", job.name))
			continue
		}

		// Check health endpoint if defined
		if job.endpoint != "" {
			logger.Debug("Checking health endpoint",
				zap.String("job", job.name),
				zap.String("endpoint", job.endpoint))

			// Retry health check with backoff
			maxRetries := 30
			for i := 0; i < maxRetries; i++ {
				_, err := execute.Run(rc.Ctx, execute.Options{
					Command: "curl",
					Args:    []string{"-sf", job.endpoint},
					Capture: true,
				})
				if err == nil {
					logger.Debug("Health check passed", zap.String("job", job.name))
					break
				}

				if i == maxRetries-1 {
					return fmt.Errorf("health check failed for %s after %d attempts", job.name, maxRetries)
				}

				logger.Debug("Health check failed, retrying",
					zap.String("job", job.name),
					zap.Int("attempt", i+1))
				time.Sleep(5 * time.Second)
			}
		}
	}

	// Verify Consul service registration
	logger.Info("Verifying Consul service registrations")
	services := []string{"hecate-postgres", "hecate-redis", "hecate-authentik-server", "hecate-caddy"}

	for _, service := range services {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "consul",
			Args:    []string{"catalog", "services", "-service=" + service},
			Capture: true,
		})
		if err != nil || !strings.Contains(output, service) {
			logger.Warn("Service not registered in Consul", zap.String("service", service))
		} else {
			logger.Debug("Service registered in Consul", zap.String("service", service))
		}
	}

	// Check Vault secrets were created
	logger.Info("Verifying Vault secrets")
	secrets := []string{
		"secret/hecate/postgres/root_password",
		"secret/hecate/postgres/password",
		"secret/hecate/redis/password",
		"secret/hecate/authentik/secret_key",
		"secret/hecate/authentik/admin",
	}

	for _, secret := range secrets {
		_, err := executeVaultCommand(rc, []string{"kv", "get", "-field=value", secret}, true)
		if err != nil {
			logger.Warn("Secret not found in Vault", zap.String("secret", secret))
		} else {
			logger.Debug("Secret verified in Vault", zap.String("secret", secret))
		}
	}

	// Display deployment summary
	logger.Info("Hecate deployment verification completed")
	logger.Info("terminal prompt: ✅ Hecate Deployment Successful!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Access URLs:")
	logger.Info(fmt.Sprintf("terminal prompt:   - Caddy Admin: http://localhost:%d", shared.PortCaddyAdmin))
	logger.Info(fmt.Sprintf("terminal prompt:   - Authentik: http://localhost:%d", shared.PortAuthentik))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Admin Credentials:")

	// Retrieve and display admin credentials
	_, err := executeVaultCommand(rc, []string{"kv", "get", "-format=json", "secret/hecate/authentik/admin"}, true)
	if err == nil {
		logger.Info("terminal prompt:   - Username: akadmin")
		logger.Info("terminal prompt:   - Password: (stored in Vault at secret/hecate/authentik/admin)")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: To retrieve the admin password:")
		logger.Info("terminal prompt:   vault kv get -field=password secret/hecate/authentik/admin")
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Configure DNS for your domain")
	logger.Info("terminal prompt:   2. Add routes using: eos create hecate route")
	logger.Info("terminal prompt:   3. Configure authentication policies in Authentik")
	logger.Info("terminal prompt:   4. Monitor logs: nomad logs -f hecate-caddy")

	return nil
}

// ConfigureRoute adds a new route to Hecate
func ConfigureRoute(rc *eos_io.RuntimeContext, route *Route) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Hecate route",
		zap.String("domain", route.Domain),
		zap.String("route_id", route.ID))

	// Basic validation
	if route.Domain == "" {
		return eos_err.NewUserError("route domain cannot be empty")
	}
	if route.Upstream == nil || route.Upstream.URL == "" {
		return eos_err.NewUserError("route upstream URL cannot be empty")
	}

	// Generate Caddy configuration for the route
	caddyConfig := generateCaddyRoute(route)

	// Write route configuration
	routeFile := filepath.Join("/opt/hecate/caddy/routes", fmt.Sprintf("%s.caddy", route.ID))
	if err := os.WriteFile(routeFile, []byte(caddyConfig), 0644); err != nil {
		return fmt.Errorf("failed to write route configuration: %w", err)
	}

	// Reload Caddy configuration
	logger.Info("Reloading Caddy configuration")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-X", "POST", fmt.Sprintf("http://localhost:%d/reload", shared.PortCaddyAdmin)},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to reload Caddy: %w", err)
	}

	logger.Info("Route configured successfully",
		zap.String("route_id", route.ID),
		zap.String("response", output))

	return nil
}

// executeVaultCommand executes a vault command with the correct VAULT_ADDR set
func executeVaultCommand(rc *eos_io.RuntimeContext, args []string, capture bool) (string, error) {
	// Save current VAULT_ADDR
	oldVaultAddr := os.Getenv("VAULT_ADDR")

	// Set correct VAULT_ADDR for port 8179
	os.Setenv("VAULT_ADDR", "https://127.0.0.1:8179")

	// Execute the command
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    args,
		Capture: capture,
	})

	// Restore original VAULT_ADDR
	if oldVaultAddr != "" {
		os.Setenv("VAULT_ADDR", oldVaultAddr)
	} else {
		os.Unsetenv("VAULT_ADDR")
	}

	return output, err
}

// installMissingService attempts to install a missing dependency using eos create commands
func installMissingService(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing missing service",
		zap.String("service", serviceName))

	// Build the command to install the service
	// We'll call the eos binary directly to leverage existing installation logic
	eosPath, err := os.Executable()
	if err != nil {
		// Fallback to standard path
		eosPath = "/usr/local/bin/eos"
	}

	// Execute the installation command
	args := []string{"create", serviceName}

	// Special handling for certain services that need additional flags
	switch serviceName {
	case "vault":
		// Vault needs to be installed in dev mode for quick setup
		args = append(args, "--dev-mode")
	case "consul":
		// Consul can use default settings
		args = append(args, "--dev-mode")
	case "nomad":
		// Nomad needs both server and client roles for single-node setup
		args = append(args, "--node-role", "both")
	case "saltstack":
		// SaltStack needs masterless mode for single-node setup
		args = append(args, "--masterless")
	}

	logger.Info("Executing installation command",
		zap.String("command", eosPath),
		zap.Strings("args", args))

	// Run the installation with a longer timeout
	installCtx, cancel := context.WithTimeout(rc.Ctx, 10*time.Minute)
	defer cancel()

	output, err := execute.Run(installCtx, execute.Options{
		Command: eosPath,
		Args:    args,
		Capture: true,
	})

	if err != nil {
		logger.Error("Installation failed",
			zap.String("service", serviceName),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("failed to install %s: %w", serviceName, err)
	}

	logger.Info("Service installed successfully",
		zap.String("service", serviceName))

	// Give the service a moment to fully initialize
	time.Sleep(5 * time.Second)

	// For Vault, we need to handle unsealing in dev mode and set correct VAULT_ADDR
	if serviceName == "vault" {
		logger.Info("Handling Vault post-installation setup")

		// Set the correct VAULT_ADDR with port 8179
		os.Setenv("VAULT_ADDR", "https://127.0.0.1:8179")

		// In dev mode, Vault should auto-unseal, but let's verify
		_, err := executeVaultCommand(rc, []string{"status"}, true)
		if err != nil {
			logger.Warn("Vault status check failed after installation", zap.Error(err))
		}
	}

	return nil
}

// generateCaddyRoute creates a Caddy configuration snippet for a route
func generateCaddyRoute(route *Route) string {
	var config strings.Builder

	config.WriteString(fmt.Sprintf("# Route: %s\n", route.ID))
	config.WriteString(fmt.Sprintf("# Created: %s\n", time.Now().Format(time.RFC3339)))
	config.WriteString(fmt.Sprintf("\n%s {\n", route.Domain))

	// Add common headers
	config.WriteString("  import common_headers\n")

	// Add authentication if required
	if route.AuthPolicy != nil && route.AuthPolicy.Provider == "authentik" {
		config.WriteString("  import authentik_auth\n")
	}

	// Configure reverse proxy
	if route.Upstream != nil {
		config.WriteString(fmt.Sprintf("\n  reverse_proxy %s {\n", route.Upstream.URL))

		// Add health checks
		if route.HealthCheck != nil {
			config.WriteString(fmt.Sprintf("    health_uri %s\n", route.HealthCheck.Path))
			config.WriteString(fmt.Sprintf("    health_interval %s\n", route.HealthCheck.Interval))
			config.WriteString(fmt.Sprintf("    health_timeout %s\n", route.HealthCheck.Timeout))
		}

		// Add load balancing policy if specified
		if route.Upstream.LoadBalancePolicy != "" {
			config.WriteString(fmt.Sprintf("    lb_policy %s\n", route.Upstream.LoadBalancePolicy))
			config.WriteString("    lb_try_duration 30s\n")
		}

		config.WriteString("  }\n")
	}

	// Add rate limiting
	if route.RateLimit != nil {
		config.WriteString(fmt.Sprintf("\n  rate_limit {\n"))
		config.WriteString(fmt.Sprintf("    zone static %drps %s\n", route.RateLimit.RequestsPerSecond, route.RateLimit.WindowSize))
		config.WriteString("  }\n")
	}

	config.WriteString("}\n")

	return config.String()
}

// Health check functions for each deployment phase

func checkHashiCorpStack(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking HashiCorp stack health")

	// Check Consul
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"members"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("consul not healthy: %w", err)
	}
	logger.Debug("Consul health check passed", zap.String("output", output))

	// Check Vault (using correct port 8179)
	output, err = executeVaultCommand(rc, []string{"status", "-format=json"}, true)
	if err != nil {
		return fmt.Errorf("vault not healthy: %w", err)
	}
	logger.Debug("Vault health check passed", zap.String("output", output))

	// Check Nomad
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"node", "status", "-json"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("nomad not healthy: %w", err)
	}
	logger.Debug("Nomad health check passed", zap.String("output", output))

	return nil
}

func checkVaultSecrets(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking secrets using hybrid secret manager")

	// Use the hybrid secret manager to check secrets regardless of backend
	secretManager, err := NewSecretManager(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	logger.Info("Using secret backend", zap.String("backend", string(secretManager.GetBackend())))

	// Validate all required secrets are available
	if err := secretManager.ValidateSecrets(); err != nil {
		return fmt.Errorf("secret validation failed: %w", err)
	}

	logger.Debug("All secrets validated successfully")
	return nil
}

func checkPostgres(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking PostgreSQL deployment")

	// Check Nomad job status
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "-json", "hecate-postgres"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("postgres job not running: %w", err)
	}

	// Wait for allocation to be healthy
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		allocOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "allocs", "-json", "hecate-postgres"},
			Capture: true,
		})
		if err == nil && strings.Contains(allocOutput, `"ClientStatus":"running"`) {
			logger.Debug("PostgreSQL allocation running")
			return nil
		}

		logger.Debug("Waiting for PostgreSQL allocation",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxRetries))
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("postgres allocation not healthy after %d attempts", maxRetries)
}

func checkRedis(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Redis deployment")

	// Check Nomad job status
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "-json", "hecate-redis"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("redis job not running: %w", err)
	}

	// Wait for allocation to be healthy
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		allocOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "allocs", "-json", "hecate-redis"},
			Capture: true,
		})
		if err == nil && strings.Contains(allocOutput, `"ClientStatus":"running"`) {
			logger.Debug("Redis allocation running")
			return nil
		}

		logger.Debug("Waiting for Redis allocation",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxRetries))
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("redis allocation not healthy after %d attempts", maxRetries)
}

func checkAuthentik(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Authentik deployment")

	// Check both server and worker jobs
	jobs := []string{"hecate-authentik-server", "hecate-authentik-worker"}

	for _, job := range jobs {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-json", job},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("%s job not running: %w", job, err)
		}
		logger.Debug("Job status verified", zap.String("job", job))
	}

	// Check Authentik health endpoint
	maxRetries := 60 // Authentik can take a while to start
	for i := 0; i < maxRetries; i++ {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-sf", "http://localhost:9000/-/health/ready/"},
			Capture: true,
		})
		if err == nil {
			logger.Debug("Authentik health check passed")
			return nil
		}

		logger.Debug("Waiting for Authentik to be ready",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxRetries))
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("authentik not healthy after %d attempts", maxRetries)
}

func checkCaddy(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Caddy deployment")

	// Check Nomad job status
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "-json", "hecate-caddy"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("caddy job not running: %w", err)
	}

	// Check Caddy admin API
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-sf", fmt.Sprintf("http://localhost:%d/health", shared.PortCaddyAdmin)},
			Capture: true,
		})
		if err == nil {
			logger.Debug("Caddy health check passed")
			return nil
		}

		logger.Debug("Waiting for Caddy to be ready",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxRetries))
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("caddy not healthy after %d attempts", maxRetries)
}

func checkIntegration(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Caddy-Authentik integration")

	// Check if Caddy can reach Authentik
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-sf", "-H", "Host: authentik.local", "http://localhost/"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("caddy cannot reach authentik: %w", err)
	}

	// Check if authentication flow is configured
	configOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-sf", fmt.Sprintf("http://localhost:%d/config/", shared.PortCaddyAdmin)},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("cannot retrieve caddy config: %w", err)
	}

	if !strings.Contains(configOutput, "authentik") {
		return fmt.Errorf("authentik integration not found in caddy config")
	}

	logger.Debug("Integration check passed")
	return nil
}

// rollbackDeployment attempts to rollback completed phases
func rollbackDeployment(rc *eos_io.RuntimeContext, completedPhases []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting deployment rollback",
		zap.Strings("completed_phases", completedPhases))

	// Rollback in reverse order
	for i := len(completedPhases) - 1; i >= 0; i-- {
		phase := completedPhases[i]
		logger.Info("Rolling back phase", zap.String("phase", phase))

		switch phase {
		case "caddy":
			execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", "hecate-caddy"},
				Capture: true,
			})
		case "authentik":
			execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", "hecate-authentik-server"},
				Capture: true,
			})
			execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", "hecate-authentik-worker"},
				Capture: true,
			})
		case "redis":
			execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", "hecate-redis"},
				Capture: true,
			})
		case "postgres":
			execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "stop", "-purge", "hecate-postgres"},
				Capture: true,
			})
		case "vault_secrets":
			// Clean up secrets
			secrets := []string{
				"secret/hecate/postgres/root_password",
				"secret/hecate/postgres/password",
				"secret/hecate/redis/password",
				"secret/hecate/authentik/secret_key",
				"secret/hecate/authentik/admin",
			}
			for _, secret := range secrets {
				executeVaultCommand(rc, []string{"kv", "delete", secret}, true)
			}
		}
	}

	logger.Info("Rollback completed")
	return nil
}

// recoverPhase attempts to recover from a failed phase by checking and restarting services
func recoverPhase(rc *eos_io.RuntimeContext, phaseName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Attempting phase recovery", zap.String("phase", phaseName))

	switch phaseName {
	case "hashicorp_stack":
		// Check and restart HashiCorp services
		services := []string{"consul", "vault", "nomad"}
		for _, service := range services {
			if err := restartServiceIfNeeded(rc, service); err != nil {
				logger.Warn("Failed to restart service during recovery",
					zap.String("service", service),
					zap.Error(err))
			}
		}

	case "vault_secrets":
		// Check Vault seal status and try to unseal if needed
		output, err := executeVaultCommand(rc, []string{"status", "-format=json"}, true)
		if err != nil {
			return fmt.Errorf("vault status check failed: %w", err)
		}

		if strings.Contains(output, `"sealed":true`) {
			logger.Info("Vault is sealed, attempting unseal during recovery")
			// Note: In production, you'd need unseal keys stored securely
			logger.Warn("Vault is sealed - manual intervention may be required")
		}

	case "postgres", "redis", "authentik", "caddy":
		// For container-based services, check if Nomad jobs are healthy
		jobName := "hecate-" + phaseName
		if phaseName == "authentik" {
			// Authentik has multiple jobs
			jobs := []string{"hecate-authentik-server", "hecate-authentik-worker"}
			for _, job := range jobs {
				if err := checkNomadJobRecovery(rc, job); err != nil {
					logger.Warn("Nomad job recovery check failed",
						zap.String("job", job),
						zap.Error(err))
				}
			}
		} else {
			if err := checkNomadJobRecovery(rc, jobName); err != nil {
				logger.Warn("Nomad job recovery check failed",
					zap.String("job", jobName),
					zap.Error(err))
			}
		}
	}

	logger.Info("Phase recovery attempt completed", zap.String("phase", phaseName))
	return nil
}

// restartServiceIfNeeded checks service status and restarts if not active
func restartServiceIfNeeded(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
	})

	if err != nil || strings.TrimSpace(output) != "active" {
		logger.Info("Service not active, attempting restart",
			zap.String("service", serviceName),
			zap.String("current_status", strings.TrimSpace(output)))

		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", serviceName},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("failed to restart %s: %w", serviceName, err)
		}

		// Wait a moment for service to start
		time.Sleep(5 * time.Second)

		// Verify restart was successful
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", serviceName},
			Capture: true,
		})
		if err != nil || strings.TrimSpace(output) != "active" {
			return fmt.Errorf("service %s failed to start after restart", serviceName)
		}

		logger.Info("Service restarted successfully", zap.String("service", serviceName))
	}

	return nil
}

// checkNomadJobRecovery checks Nomad job status and attempts basic recovery
func checkNomadJobRecovery(rc *eos_io.RuntimeContext, jobName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check job status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "-json", jobName},
		Capture: true,
	})

	if err != nil {
		logger.Debug("Nomad job not found or failed to check",
			zap.String("job", jobName),
			zap.Error(err))
		return err
	}

	// Check if any allocations are failing
	if strings.Contains(output, `"ClientStatus":"failed"`) {
		logger.Info("Detected failed Nomad allocations, attempting job restart",
			zap.String("job", jobName))

		// Stop and restart the job
		execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "stop", jobName},
			Capture: true,
		})

		// Wait a moment
		time.Sleep(3 * time.Second)

		// Start the job again
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "run", "/opt/hecate/nomad/" + jobName + ".hcl"},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("failed to restart Nomad job %s: %w", jobName, err)
		}

		logger.Info("Nomad job restarted", zap.String("job", jobName))
	}

	return nil
}

// resolveServiceDependencies resolves all dependencies for the requested services
func resolveServiceDependencies(requestedServices []string) []string {
	// Use a map to track all services to deploy (avoiding duplicates)
	servicesToDeploy := make(map[string]bool)
	
	// Process each requested service
	for _, service := range requestedServices {
		// Add the service itself
		servicesToDeploy[service] = true
		
		// Add all its dependencies
		deps := GetServiceDependencies(service)
		for _, dep := range deps {
			servicesToDeploy[dep] = true
		}
	}
	
	// Convert map to sorted slice
	var result []string
	for service := range servicesToDeploy {
		result = append(result, service)
	}
	
	// Sort by dependency order (dependencies first)
	// Simple approach: put databases first, then other services
	var databases, others []string
	for _, service := range result {
		if svc, exists := GetService(service); exists {
			if svc.Category == terraform.CategoryDatabase {
				databases = append(databases, service)
			} else {
				others = append(others, service)
			}
		}
	}
	
	// Combine: databases first, then others
	result = append(databases, others...)
	return result
}

// deployServiceWithNomad deploys a service using Nomad
func deployServiceWithNomad(rc *eos_io.RuntimeContext, service terraform.ServiceDefinition) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying service with Nomad",
		zap.String("service", service.Name),
		zap.String("job_path", service.NomadJobPath))
	
	// Check if Nomad job file exists
	jobPath := filepath.Join("/opt/eos", service.NomadJobPath)
	if _, err := os.Stat(jobPath); os.IsNotExist(err) {
		return fmt.Errorf("Nomad job file not found: %s", jobPath)
	}
	
	// Run Nomad job
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "run", jobPath},
		Capture: true,
		Timeout: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to deploy Nomad job: %w\nOutput: %s", err, output)
	}
	
	// Wait for the job to be healthy
	logger.Info("Waiting for service to be healthy",
		zap.String("service", service.Name))
	
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", service.Name},
			Capture: true,
		})
		
		if err == nil && strings.Contains(output, "running") {
			logger.Info("Service deployment successful",
				zap.String("service", service.Name))
			return nil
		}
		
		logger.Debug("Waiting for service to start",
			zap.String("service", service.Name),
			zap.Int("attempt", i+1))
		time.Sleep(10 * time.Second)
	}
	
	return fmt.Errorf("service failed to become healthy after %d attempts", maxRetries)
}

// createServiceRoute creates a Hecate route for a service
func createServiceRoute(rc *eos_io.RuntimeContext, service terraform.ServiceDefinition) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Hecate route for service",
		zap.String("service", service.Name),
		zap.String("subdomain", service.Subdomain))
	
	// Get the base domain from configuration or environment
	baseDomain := os.Getenv("HECATE_BASE_DOMAIN")
	if baseDomain == "" {
		baseDomain = "eos.local"
	}
	
	// Construct the full domain
	fullDomain := fmt.Sprintf("%s.%s", service.Subdomain, baseDomain)
	
	// Determine the upstream address
	upstream := fmt.Sprintf("%s.service.consul:%d", service.Name, service.Ports[0].Port)
	
	// Create the upstream configuration
	upstreamConfig := &Upstream{
		URL:             fmt.Sprintf("http://%s", upstream),
		HealthCheckPath: service.HealthEndpoint,
		Timeout:         30 * time.Second,
	}
	
	// Create the route configuration
	route := &Route{
		Domain:   fullDomain,
		Upstream: upstreamConfig,
		Headers:  make(map[string]string),
		Metadata: map[string]string{
			"service": service.Name,
			"managed": "true",
		},
	}
	
	// Add auth policy if specified
	if service.AuthPolicy != "" {
		route.AuthPolicy = &AuthPolicy{
			Name:     service.AuthPolicy,
			Provider: "authentik",
		}
	}
	
	// Create default Hecate config (this should be loaded from configuration)
	hecateConfig := &HecateConfig{
		DefaultDomain:        baseDomain,
		CaddyAPIEndpoint:     "http://localhost:2019",
		AuthentikAPIEndpoint: "http://authentik.service.consul:9000",
		StateBackend:         "consul",
		Environment:          "production",
	}
	
	// Use Hecate's route creation API
	if err := CreateRoute(rc, hecateConfig, route); err != nil {
		return fmt.Errorf("failed to create route for service %s: %w", service.Name, err)
	}
	
	logger.Info("Route created successfully",
		zap.String("service", service.Name),
		zap.String("domain", fullDomain),
		zap.String("upstream", upstream))
	
	return nil
}

// mapServiceToSizingType maps service names to sizing types
func mapServiceToSizingType(serviceName string) sizing.ServiceType {
	// Map common service names to sizing types
	serviceMap := map[string]sizing.ServiceType{
		"postgres":     sizing.ServiceTypeDatabase,
		"postgresql":   sizing.ServiceTypeDatabase,
		"mysql":        sizing.ServiceTypeDatabase,
		"mariadb":      sizing.ServiceTypeDatabase,
		"mongodb":      sizing.ServiceTypeDatabase,
		"redis":        sizing.ServiceTypeCache,
		"memcached":    sizing.ServiceTypeCache,
		"nginx":        sizing.ServiceTypeWebServer,
		"apache":       sizing.ServiceTypeWebServer,
		"caddy":        sizing.ServiceTypeProxy,
		"haproxy":      sizing.ServiceTypeProxy,
		"traefik":      sizing.ServiceTypeProxy,
		"rabbitmq":     sizing.ServiceTypeQueue,
		"kafka":        sizing.ServiceTypeQueue,
		"prometheus":   sizing.ServiceTypeMonitoring,
		"grafana":      sizing.ServiceTypeMonitoring,
		"elasticsearch": sizing.ServiceTypeLogging,
		"logstash":     sizing.ServiceTypeLogging,
		"kibana":       sizing.ServiceTypeLogging,
		"vault":        sizing.ServiceTypeVault,
		"consul":       sizing.ServiceTypeOrchestrator,
		"nomad":        sizing.ServiceTypeOrchestrator,
		"kubernetes":   sizing.ServiceTypeOrchestrator,
		"k3s":          sizing.ServiceTypeOrchestrator,
		"docker":       sizing.ServiceTypeContainer,
		"containerd":   sizing.ServiceTypeContainer,
		"minio":        sizing.ServiceTypeStorage,
		"ceph":         sizing.ServiceTypeStorage,
		"glusterfs":    sizing.ServiceTypeStorage,
	}

	// Check direct mapping
	if svcType, exists := serviceMap[strings.ToLower(serviceName)]; exists {
		return svcType
	}

	// Check if service name contains known keywords
	lowerName := strings.ToLower(serviceName)
	for keyword, svcType := range serviceMap {
		if strings.Contains(lowerName, keyword) {
			return svcType
		}
	}

	// Default to empty string if no match
	return ""
}

// checkManualHecateRequirements performs a basic manual check when auto-detection fails
func checkManualHecateRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Performing manual hardware requirements check")
	
	// Basic sanity check - ensure we have at least 1GB RAM and 1 CPU core
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "free",
		Args:    []string{"-m"},
		Capture: true,
	})
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Mem:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					var memoryMB int
					fmt.Sscanf(fields[1], "%d", &memoryMB)
					if memoryMB < 1024 { // Less than 1GB
						logger.Info("terminal prompt: ⚠️  WARNING: System has less than 1GB RAM")
						logger.Info("terminal prompt: Hecate deployment may fail. Continue anyway? [y/N]: ")
						
						response, err := eos_io.ReadInput(rc)
						if err != nil {
							return fmt.Errorf("failed to read user response: %w", err)
						}
						
						if !strings.EqualFold(strings.TrimSpace(response), "y") {
							return eos_err.NewUserError("deployment cancelled due to insufficient resources")
						}
					}
				}
				break
			}
		}
	}
	
	return nil
}



