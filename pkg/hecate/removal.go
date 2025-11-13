// pkg/hecate/removal.go

package hecate

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveHecateCompletely removes all Hecate components using  and manual cleanup
func RemoveHecateCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting complete Hecate removal",
		zap.Bool("keep_data", keepData))

	// ASSESS - Check what Hecate components exist
	if err := assessHecateComponents(rc); err != nil {
		logger.Warn("Failed to assess Hecate components", zap.Error(err))
	}

	// INTERVENE - Remove components in reverse order
	if err := removeHecateServices(rc, keepData); err != nil {
		logger.Error("Failed to remove Hecate services", zap.Error(err))
		return fmt.Errorf("failed to remove Hecate services: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyHecateRemoval(rc); err != nil {
		logger.Warn("Hecate removal verification failed", zap.Error(err))
	}

	logger.Info("Hecate removal completed")
	return nil
}

// assessHecateComponents checks what Hecate components are currently deployed
func assessHecateComponents(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing Hecate components for removal")

	// Check Nomad jobs
	hecateJobs := []string{
		"hecate-caddy",
		"hecate-authentik-server",
		"hecate-authentik-worker",
		"hecate-redis",
		"hecate-postgres",
	}

	var activeJobs []string
	for _, job := range hecateJobs {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-json", job},
			Capture: true,
		})
		if err == nil && strings.Contains(output, `"Status":"running"`) {
			activeJobs = append(activeJobs, job)
			logger.Info("Found active Hecate job", zap.String("job", job))
		}
	}

	// Check for Hecate directories
	hecateDirectories := []string{
		"/opt/hecate",
		"/etc/hecate",
		"/var/lib/hecate",
		"/var/log/hecate",
	}

	var existingDirs []string
	for _, dir := range hecateDirectories {
		if _, err := os.Stat(dir); err == nil {
			existingDirs = append(existingDirs, dir)
			logger.Info("Found Hecate directory", zap.String("directory", dir))
		}
	}

	// Check for Vault secrets
	hecateSecrets := []string{
		"secret/hecate/postgres/root_password",
		"secret/hecate/postgres/password",
		"secret/hecate/redis/password",
		"secret/hecate/authentik/secret_key",
		"secret/hecate/authentik/admin",
	}

	var existingSecrets []string
	for _, secret := range hecateSecrets {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "vault",
			Args:    []string{"kv", "get", "-field=value", secret},
			Capture: true,
		})
		if err == nil {
			existingSecrets = append(existingSecrets, secret)
			logger.Debug("Found Hecate secret", zap.String("secret", secret))
		}
	}

	logger.Info("Hecate assessment completed",
		zap.Strings("active_jobs", activeJobs),
		zap.Strings("directories", existingDirs),
		zap.Int("secrets_count", len(existingSecrets)))

	return nil
}

// removeHecateServices removes all Hecate services and components
func removeHecateServices(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing Hecate services")

	// Phase 1: Stop and remove Nomad jobs
	if err := stopHecateNomadJobs(rc); err != nil {
		logger.Error("Failed to stop Nomad jobs", zap.Error(err))
		return fmt.Errorf("failed to stop Nomad jobs: %w", err)
	}

	// Phase 2: Remove -managed components via  removal state
	if err := removeBy(rc); err != nil {
		logger.Warn("-based removal failed, continuing with manual removal", zap.Error(err))
	}

	// Phase 3: Remove Vault secrets
	if err := removeHecateVaultSecrets(rc); err != nil {
		logger.Warn("Failed to remove Vault secrets", zap.Error(err))
	}

	// Phase 4: Remove directories and files
	if err := removeHecateDirectories(rc, keepData); err != nil {
		logger.Warn("Failed to remove some directories", zap.Error(err))
	}

	// Phase 5: Clean up systemd services if any
	if err := removeHecateSystemdServices(rc); err != nil {
		logger.Warn("Failed to clean up systemd services", zap.Error(err))
	}

	return nil
}

// stopHecateNomadJobs stops and purges all Hecate Nomad jobs
func stopHecateNomadJobs(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping Hecate Nomad jobs")

	hecateJobs := []string{
		"hecate-caddy",
		"hecate-authentik-server",
		"hecate-authentik-worker",
		"hecate-redis",
		"hecate-postgres",
	}

	for _, job := range hecateJobs {
		logger.Info("Stopping Nomad job", zap.String("job", job))

		// Stop and purge the job
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "stop", "-purge", job},
			Capture: true,
		})

		if err != nil {
			logger.Debug("Job stop failed (may not exist)",
				zap.String("job", job),
				zap.Error(err))
		} else {
			logger.Info("Job stopped successfully",
				zap.String("job", job),
				zap.String("output", output))
		}
	}

	// Wait for jobs to fully terminate with retry logic
	logger.Info("Waiting for jobs to terminate...")
	maxRetries := 12 // 60 seconds total (5 second intervals)

	for retry := 0; retry < maxRetries; retry++ {
		time.Sleep(5 * time.Second)

		var stillRunning []string
		for _, job := range hecateJobs {
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"job", "status", job},
				Capture: true,
			})
			if err == nil {
				stillRunning = append(stillRunning, job)
			}
		}

		if len(stillRunning) == 0 {
			logger.Info("All Hecate jobs terminated successfully")
			break
		}

		logger.Info("Still waiting for jobs to terminate",
			zap.Strings("jobs", stillRunning),
			zap.Int("retry", retry+1),
			zap.Int("max_retries", maxRetries))

		// Force-kill remaining jobs if we're on the last retry
		if retry == maxRetries-1 {
			logger.Warn("Forcing termination of remaining jobs")
			for _, job := range stillRunning {
				logger.Info("Force stopping job", zap.String("job", job))
				_, _ = execute.Run(rc.Ctx, execute.Options{
					Command: "nomad",
					Args:    []string{"job", "stop", "-purge", "-force", job},
					Capture: true,
				})
			}
			time.Sleep(5 * time.Second) // Final wait after force termination
		}
	}

	// Force Nomad garbage collection to clean up any remaining allocations
	logger.Info("Running Nomad garbage collection to clean up allocations")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"system", "gc"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Nomad garbage collection failed", zap.Error(err))
	} else {
		logger.Info("Nomad garbage collection completed")
	}

	return nil
}

// removeBy attempts to remove Hecate using  removal states
func removeBy(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Attempting -based Hecate removal")

	// First check if -call is available
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"-call"},
		Capture: true,
	})
	if err != nil {
		logger.Info(" not available, skipping -based removal")
		return fmt.Errorf("-call not available: %w", err)
	}

	// Check if  removal state exists
	removalState := "hecate.remove"

	// Try to apply the removal state
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "-call",
		Args: []string{
			"state.apply",
			removalState,
			"--output=json",
			"--log-level=info",
		},
		Capture: true,
	})

	if err != nil {
		logger.Debug(" removal state failed or doesn't exist",
			zap.String("state", removalState),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf(" removal failed: command failed after 0 attempts: %w", err)
	}

	logger.Info("-based removal completed",
		zap.String("state", removalState))

	return nil
}

// removeHecateVaultSecrets removes all Hecate secrets from Vault
func removeHecateVaultSecrets(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing Hecate secrets from Vault")

	hecateSecrets := []string{
		"secret/hecate/postgres/root_password",
		"secret/hecate/postgres/password",
		"secret/hecate/redis/password",
		"secret/hecate/authentik/secret_key",
		"secret/hecate/authentik/admin",
	}

	for _, secret := range hecateSecrets {
		logger.Debug("Removing Vault secret", zap.String("secret", secret))

		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "vault",
			Args:    []string{"kv", "delete", secret},
			Capture: true,
		})

		if err != nil {
			logger.Debug("Secret removal failed (may not exist)",
				zap.String("secret", secret),
				zap.Error(err))
		} else {
			logger.Info("Secret removed", zap.String("secret", secret))
		}
	}

	// Also remove the entire hecate secret path if it exists
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "delete", "-mount=secret", "hecate"},
		Capture: true,
	})
	if err != nil {
		logger.Debug("Failed to remove hecate secret mount", zap.Error(err))
	}

	return nil
}

// removeHecateDirectories removes Hecate directories and configuration files
func removeHecateDirectories(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing Hecate directories", zap.Bool("keep_data", keepData))

	// Define directories with data classification
	directories := []struct {
		path   string
		isData bool
		desc   string
	}{
		{"/opt/hecate", false, "Hecate application directory"},
		{"/etc/hecate", false, "Hecate configuration directory"},
		{"/var/lib/hecate", true, "Hecate data directory"},
		{"/var/log/hecate", true, "Hecate log directory"},
		{"/srv//hecate", false, "Hecate  states"},
		{"/srv//hecate", false, "Hecate   data"},
	}

	for _, dir := range directories {
		// Skip data directories if keepData is true
		if dir.isData && keepData {
			logger.Info("Keeping data directory",
				zap.String("directory", dir.path),
				zap.String("description", dir.desc))
			continue
		}

		if _, err := os.Stat(dir.path); err == nil {
			logger.Info("Removing directory",
				zap.String("directory", dir.path),
				zap.String("description", dir.desc))

			if err := os.RemoveAll(dir.path); err != nil {
				logger.Error("Failed to remove directory",
					zap.String("directory", dir.path),
					zap.Error(err))
			} else {
				logger.Info("Directory removed successfully",
					zap.String("directory", dir.path))
			}
		} else {
			logger.Debug("Directory not found",
				zap.String("directory", dir.path))
		}
	}

	// Remove specific configuration files
	configFiles := []string{
		"/etc/caddy/Caddyfile.hecate",
		"/etc/systemd/system/hecate-*.service",
		"/etc/nginx/sites-available/hecate",
		"/etc/nginx/sites-enabled/hecate",
	}

	for _, file := range configFiles {
		if strings.Contains(file, "*") {
			// Handle glob patterns
			matches, err := os.ReadDir("/etc/systemd/system/")
			if err == nil {
				for _, entry := range matches {
					if strings.HasPrefix(entry.Name(), "hecate-") && strings.HasSuffix(entry.Name(), ".service") {
						fullPath := "/etc/systemd/system/" + entry.Name()
						logger.Info("Removing service file", zap.String("file", fullPath))
						_ = os.Remove(fullPath)
					}
				}
			}
		} else {
			if _, err := os.Stat(file); err == nil {
				logger.Info("Removing config file", zap.String("file", file))
				if err := os.Remove(file); err != nil {
					logger.Error("Failed to remove config file",
						zap.String("file", file),
						zap.Error(err))
				}
			}
		}
	}

	return nil
}

// removeHecateSystemdServices removes any Hecate systemd services
func removeHecateSystemdServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Cleaning up Hecate systemd services")

	// Stop and disable any Hecate services
	possibleServices := []string{
		"hecate",
		"hecate-caddy",
		"hecate-authentik",
	}

	for _, service := range possibleServices {
		// Check if service exists
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"list-unit-files", service + ".service"},
			Capture: true,
		})

		if err == nil {
			logger.Info("Found Hecate service, stopping and disabling",
				zap.String("service", service))

			// Stop service
			_, _ = execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"stop", service},
				Capture: true,
			})

			// Disable service
			_, _ = execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"disable", service},
				Capture: true,
			})
		}
	}

	// Reload systemd to clean up
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: true,
	})

	return nil
}

// verifyHecateRemoval verifies that Hecate components have been successfully removed
func verifyHecateRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Hecate removal")

	var remainingComponents []string

	// Check for remaining Nomad jobs
	hecateJobs := []string{
		"hecate-caddy",
		"hecate-authentik-server",
		"hecate-authentik-worker",
		"hecate-redis",
		"hecate-postgres",
	}

	for _, job := range hecateJobs {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", job},
			Capture: true,
		})
		if err == nil {
			remainingComponents = append(remainingComponents, "nomad-job:"+job)
		}
	}

	// Check for remaining directories
	checkDirs := []string{
		"/opt/hecate",
		"/etc/hecate",
	}

	for _, dir := range checkDirs {
		if _, err := os.Stat(dir); err == nil {
			remainingComponents = append(remainingComponents, "directory:"+dir)
		}
	}

	// Check for remaining secrets
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "list", "secret/hecate"},
		Capture: true,
	})
	if err == nil {
		remainingComponents = append(remainingComponents, "vault-secrets:secret/hecate")
	}

	if len(remainingComponents) > 0 {
		logger.Warn("Some Hecate components may still be present",
			zap.Strings("remaining", remainingComponents))
		remainingList := strings.Join(remainingComponents, ", ")
		return eos_err.NewUserError("Hecate removal incomplete. Remaining components: %s", remainingList)
	}

	logger.Info("Hecate removal verification passed - all components removed")
	return nil
}
