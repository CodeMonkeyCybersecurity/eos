// pkg/hecate/saltstack_deploy.go

package hecate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployWithSaltStack deploys Hecate using SaltStack orchestration
func DeployWithSaltStack(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate deployment with SaltStack")

	// ASSESS - Check prerequisites
	if err := assessPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
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
			name:        "vault_secrets",
			state:       "hecate.vault_secrets",
			description: "Creating Vault secrets for Hecate components",
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
				
				// Log detailed output for debugging (but only in debug mode)
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
							logger.Info("Health check passed",
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
					zap.String("phase", phase.name),
					zap.Duration("total_time", time.Since(time.Now())))
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

	// EVALUATE - Verify complete deployment
	if err := verifyDeployment(rc); err != nil {
		return fmt.Errorf("deployment verification failed: %w", err)
	}

	// Update final state
	if err := stateManager.SetDeploymentComplete(); err != nil {
		logger.Warn("Failed to update deployment state", zap.Error(err))
	}

	logger.Info("Hecate deployment completed successfully")
	return nil
}

// assessPrerequisites checks that all required services are available
func assessPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing prerequisites for Hecate deployment")

	// Check for required services with detailed diagnostics
	requiredServices := []string{"nomad", "consul", "vault", "salt-minion"}
	
	for _, service := range requiredServices {
		logger.Debug("Checking service", zap.String("service", service))
		
		// First check if service is installed
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"list-unit-files", service + ".service"},
			Capture: true,
		})
		if err != nil || !strings.Contains(output, service + ".service") {
			return eos_err.NewUserError("Required service %s is not installed. Please install the HashiCorp stack first:\n  eos create vault\n  eos create consul\n  eos create nomad\n  eos create saltstack", service)
		}
		
		// Check if service is active
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service},
			Capture: true,
		})
		if err != nil || strings.TrimSpace(output) != "active" {
			// Get detailed status for better error reporting
			statusOutput, _ := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"status", service, "--no-pager", "-l"},
				Capture: true,
			})
			
			return eos_err.NewUserError("Required service %s is not running.\nCurrent status: %s\n\nService details:\n%s\n\nTo start the service: sudo systemctl start %s", 
				service, strings.TrimSpace(output), statusOutput, service)
		}
		
		logger.Info("Service check passed", zap.String("service", service))
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

	// Check Vault is unsealed
	vaultOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status", "-format=json"},
		Capture: true,
	})
	if err != nil {
		return eos_err.NewUserError("vault is not accessible - ensure it is running and unsealed")
	}
	logger.Debug("Vault status", zap.String("output", vaultOutput))

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
		{name: "hecate-authentik-server", endpoint: "http://localhost:9000/-/health/ready/", required: true},
		{name: "hecate-authentik-worker", endpoint: "", required: true},
		{name: "hecate-caddy", endpoint: "http://localhost:2019/health", required: true},
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
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "vault",
			Args:    []string{"kv", "get", "-field=value", secret},
			Capture: true,
		})
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
	logger.Info("terminal prompt:   - Caddy Admin: http://localhost:2019")
	logger.Info("terminal prompt:   - Authentik: http://localhost:9000")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Admin Credentials:")
	
	// Retrieve and display admin credentials
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "get", "-format=json", "secret/hecate/authentik/admin"},
		Capture: true,
	})
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
		Args:    []string{"-X", "POST", "http://localhost:2019/reload"},
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
	
	// Check Vault
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"status", "-format=json"},
		Capture: true,
	})
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
	logger.Debug("Checking Vault secrets")
	
	requiredSecrets := []string{
		"secret/hecate/postgres/root_password",
		"secret/hecate/postgres/password",
		"secret/hecate/redis/password",
		"secret/hecate/authentik/secret_key",
		"secret/hecate/authentik/admin",
	}
	
	for _, secret := range requiredSecrets {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "vault",
			Args:    []string{"kv", "get", "-field=value", secret},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("secret %s not found: %w", secret, err)
		}
		logger.Debug("Secret verified", zap.String("secret", secret))
	}
	
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
			Args:    []string{"-sf", "http://localhost:2019/health"},
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
		Args:    []string{"-sf", "http://localhost:2019/config/"},
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
				execute.Run(rc.Ctx, execute.Options{
					Command: "vault",
					Args:    []string{"kv", "delete", secret},
					Capture: true,
				})
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
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "vault",
			Args:    []string{"status", "-format=json"},
			Capture: true,
		})
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