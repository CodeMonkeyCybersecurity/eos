// pkg/hecate/add/add.go

package add

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AddService adds a new service to Hecate
// This is the main entry point that orchestrates all operations
func AddService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for root permissions
	if os.Geteuid() != 0 {
		return eos_err.NewUserError(
			"Permission denied: /opt/hecate requires root access\n\n" +
				"Run with sudo:\n" +
				"  sudo eos update hecate add [service] --dns [domain] --upstream [backend]")
	}

	// Display header
	logger.Info("Adding new service to Hecate",
		zap.String("service", opts.Service),
		zap.String("dns", opts.DNS),
		zap.String("backend", opts.Backend),
		zap.Bool("sso", opts.SSO))

	// If dry-run, show what would be done and exit
	if opts.DryRun {
		return runDryRun(rc, opts)
	}

	// Phase 1: Validation
	if err := runValidationPhase(rc, opts); err != nil {
		return err
	}

	// Phase 2: Pre-flight checks
	if err := runPreflightChecks(rc, opts); err != nil {
		return err
	}

	// Phase 2.5: Service-specific integration (if registered)
	if err := runServiceIntegration(rc, opts); err != nil {
		return err
	}

	// Phase 3: Backup
	backupPath, err := runBackupPhase(rc, opts)
	if err != nil {
		return err
	}

	// Phase 4: Generate and append route
	if err := runAppendRoutePhase(rc, opts); err != nil {
		// Restore backup on failure
		logger.Error("Failed to append route, restoring backup", zap.Error(err))
		if restoreErr := RestoreBackup(rc, backupPath); restoreErr != nil {
			logger.Error("CRITICAL: Failed to restore backup", zap.Error(restoreErr))
		} else {
			// CRITICAL: Must reload Caddy with restored config
			// Without this, Caddy still has bad config in memory even though file is restored
			logger.Info("Backup restored to disk, reloading Caddy with restored config")
			if reloadErr := ReloadCaddy(rc, CaddyfilePath); reloadErr != nil {
				logger.Error("CRITICAL: Backup restored but Caddy reload failed",
					zap.Error(reloadErr))
				logger.Error("Manual intervention required: restart Caddy or reload config manually")
				logger.Error("  docker restart " + hecate.CaddyContainerName)
			} else {
				logger.Info("Caddy successfully reloaded with restored configuration")
			}
		}
		return err
	}

	// Phase 5: Validate and reload Caddy
	if err := runCaddyReloadPhase(rc, backupPath); err != nil {
		return err
	}

	// Phase 6: Verify route
	if err := runVerificationPhase(rc, opts); err != nil {
		// Non-fatal warning
		logger.Warn("Route verification had issues", zap.Error(err))
	}

	// Phase 7: Cleanup old backups
	if err := CleanupOldBackups(rc, opts.BackupRetentionDays); err != nil {
		// Non-fatal warning
		logger.Warn("Failed to cleanup old backups", zap.Error(err))
	}

	// Success!
	printSuccessMessage(logger, opts)

	return nil
}

// runDryRun shows what would be changed without actually changing anything
func runDryRun(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("DRY RUN MODE - No changes will be made")
	logger.Info("")

	// Generate route config
	routeConfig, err := GenerateRouteConfig(opts)
	if err != nil {
		return fmt.Errorf("failed to generate route config: %w", err)
	}

	logger.Info("Would add the following route to Caddyfile:")
	logger.Info("---")
	logger.Info(routeConfig)
	logger.Info("---")
	logger.Info("")

	logger.Info("Would execute:")
	logger.Info("  1. Validate input (service, DNS, backend)")
	logger.Info("  2. Check Hecate installation")
	if opts.SSO {
		logger.Info("  3. Check Authentik installation (SSO enabled)")
	}
	if !opts.SkipDNSCheck {
		logger.Info("  4. Verify DNS points to this server")
	}
	if !opts.SkipBackendCheck {
		logger.Info("  5. Check backend connectivity")
	}
	logger.Info("  6. Create timestamped backup of Caddyfile")
	logger.Info("  7. Append new route to Caddyfile")
	logger.Info("  8. Validate Caddy configuration")
	logger.Info("  9. Reload Caddy (no restart, zero downtime)")
	logger.Info("  10. Verify route is accessible")
	if opts.BackupRetentionDays > 0 {
		logger.Info(fmt.Sprintf("  11. Clean up backups older than %d days", opts.BackupRetentionDays))
	}
	logger.Info("")

	logger.Info("To apply these changes, run without --dry-run")

	return nil
}

// runValidationPhase validates all inputs
func runValidationPhase(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 1/6: Validating input...")

	// Validate basic inputs
	result := ValidateInput(rc, opts)
	if !result.Valid {
		return eos_err.NewUserError(result.Message)
	}

	// Validate custom directives
	if err := ValidateCustomDirectives(opts.CustomDirectives); err != nil {
		return eos_err.NewUserError(fmt.Sprintf("invalid custom directive: %v", err))
	}

	logger.Info("✓ Input validation passed")
	return nil
}

// runPreflightChecks runs all pre-flight checks
func runPreflightChecks(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 2/6: Running pre-flight checks...")

	// Check Hecate installation
	if err := CheckHecateInstallation(rc); err != nil {
		return eos_err.NewUserError(err.Error())
	}
	logger.Info("✓ Hecate installation verified")

	// Check for duplicates
	if err := CheckDuplicateService(rc, CaddyfilePath, opts.Service, opts.DNS); err != nil {
		return eos_err.NewUserError(err.Error())
	}
	logger.Info("✓ No duplicate service or DNS found")

	// Check Caddy is running
	isRunning, err := IsCaddyRunning(rc)
	if err != nil {
		return fmt.Errorf("failed to check Caddy status: %w", err)
	}
	if !isRunning {
		return eos_err.NewUserError(
			"Caddy container is not running\n\n" +
				"Start Hecate with:\n" +
				"  cd /opt/hecate && docker-compose up -d")
	}
	logger.Info("✓ Caddy container is running")

	// Check Authentik if SSO is enabled
	if opts.SSO {
		if err := CheckAuthentikInstallation(rc); err != nil {
			return eos_err.NewUserError(err.Error())
		}
		logger.Info("✓ Authentik installation verified")
	}

	// Check DNS resolution
	if !opts.SkipDNSCheck {
		dnsResult := CheckDNSResolution(rc, opts.DNS)
		if !dnsResult.Reachable {
			logger.Warn("DNS check failed",
				zap.String("dns", opts.DNS),
				zap.String("error", dnsResult.Error))
			logger.Warn("⚠ DNS does not point to this server")
			logger.Warn("The route will be added, but won't be accessible until DNS is configured")
			logger.Warn(fmt.Sprintf("Ensure %s points to this server's IP address", opts.DNS))
		} else {
			// Safe type assertion with fallback
			matchedIP, ok := dnsResult.Details["matched_ip"].(string)
			if !ok {
				matchedIP = "unknown"
			}
			logger.Info("✓ DNS points to this server",
				zap.String("matched_ip", matchedIP))
		}
	}

	// Check backend connectivity
	if !opts.SkipBackendCheck {
		backendResult := CheckBackendConnectivity(rc, opts.Backend)
		if !backendResult.Reachable {
			logger.Warn("Backend check failed",
				zap.String("backend", opts.Backend),
				zap.String("error", backendResult.Error))
			logger.Warn("⚠ Backend is not reachable")
			logger.Warn("The route will be added, but requests will fail until the backend is available")
			logger.Warn(fmt.Sprintf("Ensure service is running and accessible at %s", opts.Backend))
		} else {
			logger.Info("✓ Backend is reachable",
				zap.Duration("latency", backendResult.Latency))
		}
	}

	logger.Info("✓ Pre-flight checks completed")
	return nil
}

// runBackupPhase creates a backup of the Caddyfile
func runBackupPhase(rc *eos_io.RuntimeContext, opts *ServiceOptions) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 3/6: Creating backup...")

	backupPath, err := BackupCaddyfile(rc)
	if err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	logger.Info("✓ Backup created", zap.String("path", backupPath))
	return backupPath, nil
}

// runAppendRoutePhase generates and appends the new route
func runAppendRoutePhase(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 4/6: Updating Caddyfile...")

	// Generate route configuration
	routeConfig, err := GenerateRouteConfig(opts)
	if err != nil {
		return fmt.Errorf("failed to generate route config: %w", err)
	}

	// Append to Caddyfile
	if err := AppendRoute(rc, routeConfig); err != nil {
		return fmt.Errorf("failed to append route: %w", err)
	}

	logger.Info("✓ Route appended to Caddyfile")
	return nil
}

// runCaddyReloadPhase validates and reloads Caddy
func runCaddyReloadPhase(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 5/6: Validating and reloading Caddy...")

	// Validate configuration
	if err := ValidateCaddyConfig(rc, CaddyfilePath); err != nil {
		// Restore backup on validation failure
		logger.Error("Caddy configuration validation failed, restoring backup")
		if restoreErr := RestoreBackup(rc, backupPath); restoreErr != nil {
			logger.Error("CRITICAL: Failed to restore backup", zap.Error(restoreErr))
		} else {
			// CRITICAL: Must reload Caddy with restored config
			logger.Info("Backup restored to disk, reloading Caddy with restored config")
			if reloadErr := ReloadCaddy(rc, CaddyfilePath); reloadErr != nil {
				logger.Error("CRITICAL: Backup restored but Caddy reload failed",
					zap.Error(reloadErr))
				logger.Error("Manual intervention required: restart Caddy or reload config manually")
				logger.Error("  docker restart " + hecate.CaddyContainerName)
			} else {
				logger.Info("Caddy successfully reloaded with restored configuration")
			}
		}
		return err
	}
	logger.Info("✓ Caddy configuration validated")

	// Reload Caddy
	if err := ReloadCaddy(rc, CaddyfilePath); err != nil {
		// Restore backup on reload failure
		logger.Error("Caddy reload failed, restoring backup")
		if restoreErr := RestoreBackup(rc, backupPath); restoreErr != nil {
			logger.Error("CRITICAL: Failed to restore backup", zap.Error(restoreErr))
		} else {
			// CRITICAL: Must reload Caddy with restored config
			logger.Info("Backup restored to disk, attempting to reload Caddy with restored config")
			if reloadErr := ReloadCaddy(rc, CaddyfilePath); reloadErr != nil {
				logger.Error("CRITICAL: Backup restored but Caddy reload still failing",
					zap.Error(reloadErr))
				logger.Error("Manual intervention required: restart Caddy or reload config manually")
				logger.Error("  docker restart " + hecate.CaddyContainerName)
			} else {
				logger.Info("Caddy successfully reloaded with restored configuration")
			}
		}
		return err
	}
	logger.Info("✓ Caddy reloaded successfully (zero downtime)")

	return nil
}

// runVerificationPhase verifies the new route is working
func runVerificationPhase(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 6/6: Verifying new route...")

	// Wait for DNS propagation and route setup (see hecate.RouteVerificationWaitDuration)
	time.Sleep(hecate.RouteVerificationWaitDuration)

	// Try to connect to the new route
	url := fmt.Sprintf("https://%s", opts.DNS)

	client := &http.Client{
		Timeout: hecate.RouteVerificationTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		logger.Warn("Failed to connect to new route",
			zap.String("url", url),
			zap.Error(err))
		logger.Warn("⚠ Route may not be accessible yet")
		logger.Warn("This might be due to:")
		logger.Warn("  - DNS propagation delay")
		logger.Warn("  - Backend not ready")
		logger.Warn("  - SSL certificate provisioning in progress")
		return fmt.Errorf("route verification failed: %w", err)
	}
	defer resp.Body.Close()

	// Accept 2xx, 3xx, 401, 403 as "working"
	// (401/403 might mean auth is working correctly)
	if (resp.StatusCode >= 200 && resp.StatusCode < 400) ||
		resp.StatusCode == 401 || resp.StatusCode == 403 {
		logger.Info("✓ Route is accessible",
			zap.String("url", url),
			zap.Int("status_code", resp.StatusCode))
		return nil
	}

	logger.Warn("Route returned unexpected status",
		zap.String("url", url),
		zap.Int("status_code", resp.StatusCode))
	logger.Warn("⚠ Route may be experiencing issues")
	return fmt.Errorf("route returned status %d", resp.StatusCode)
}

// runServiceIntegration runs service-specific integration if a plugin is registered
func runServiceIntegration(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if service has a registered integrator
	integrator, exists := GetServiceIntegrator(opts.Service)
	if !exists {
		// No service-specific integration registered - that's OK
		logger.Debug("No service-specific integration registered for service", zap.String("service", opts.Service))
		return nil
	}

	logger.Info("Running service-specific integration", zap.String("service", opts.Service))

	// Step 1: Validate service is running at backend
	if err := integrator.ValidateService(rc, opts); err != nil {
		return fmt.Errorf("service validation failed: %w", err)
	}

	// Step 2: Configure authentication (OAuth2, SSO, etc.)
	if err := integrator.ConfigureAuthentication(rc, opts); err != nil {
		// Attempt rollback on authentication configuration failure
		logger.Error("Authentication configuration failed, attempting rollback", zap.Error(err))
		if rollbackErr := integrator.Rollback(rc); rollbackErr != nil {
			logger.Error("Rollback failed - manual cleanup may be required",
				zap.Error(rollbackErr),
				zap.String("service", opts.Service))
		} else {
			logger.Info("Rollback completed successfully")
		}
		return fmt.Errorf("authentication configuration failed: %w", err)
	}

	// Step 3: Health check
	if err := integrator.HealthCheck(rc, opts); err != nil {
		// Non-fatal: log warning but continue
		logger.Warn("Service-specific health check failed", zap.Error(err))
	}

	logger.Info("✓ Service-specific integration complete")
	return nil
}

// printSuccessMessage prints the final success message
func printSuccessMessage(logger otelzap.LoggerWithCtx, opts *ServiceOptions) {
	logger.Info("")
	logger.Info("✅ Service added successfully!")
	logger.Info("")
	logger.Info(fmt.Sprintf("Service: %s", opts.Service))
	logger.Info(fmt.Sprintf("Domain: https://%s", opts.DNS))
	logger.Info(fmt.Sprintf("Backend: %s", opts.Backend))
	if opts.SSO {
		logger.Info(fmt.Sprintf("SSO: Enabled (%s)", opts.SSOProvider))
	}
	logger.Info("")

	// BionicGPT-specific success information
	if opts.Service == "bionicgpt" && opts.SSO {
		logger.Info("BionicGPT Authentication Flow:")
		logger.Info("  User -> Caddy forward_auth -> Authentik -> BionicGPT")
		logger.Info("")
		logger.Info(fmt.Sprintf("  1. User visits https://%s", opts.DNS))
		logger.Info("  2. Caddy checks authentication via Authentik forward auth")
		logger.Info("  3. If not authenticated, Authentik shows login page")
		logger.Info("  4. After login, Authentik returns X-Authentik-* headers")
		logger.Info("  5. Caddy forwards request to BionicGPT with headers")
		logger.Info("")
		logger.Info("Admin Credentials:")
		logger.Info("  Username: bionicgpt-admin")
		logger.Info("  Password: Retrieve with:")
		logger.Info("    sudo cat /opt/bionicgpt/.env.admin | grep BIONICGPT_ADMIN_PASSWORD")
		logger.Info("")
		logger.Info("Authentik Groups Created:")
		logger.Info("  - bionicgpt-superadmin (admin users)")
		logger.Info("  - bionicgpt-demo (demo/viewer users)")
		logger.Info("")
		logger.Info("Troubleshooting:")
		logger.Info("  - Check Authentik outpost: https://hera.your-domain/if/admin/#/outpost/outposts")
		logger.Info("  - Check proxy provider assignment")
		logger.Info("  - Verify /outpost.goauthentik.io/* route in Caddyfile")
		logger.Info("  - Check Caddy logs for forward_auth errors")
		logger.Info("")
	} else if opts.SSO {
		// Generic SSO success message
		logger.Info("Next steps:")
		logger.Info(fmt.Sprintf("  1. Ensure DNS for %s points to this server", opts.DNS))
		logger.Info(fmt.Sprintf("  2. Verify the backend service is running at %s", opts.Backend))
		logger.Info("  3. Configure SSO application in Authentik")
		logger.Info("     Visit: https://hera.your-domain/if/admin/")
		logger.Info(fmt.Sprintf("  4. Test your service at https://%s", opts.DNS))
		logger.Info("")
	} else {
		// No SSO
		logger.Info("Next steps:")
		logger.Info(fmt.Sprintf("  1. Ensure DNS for %s points to this server", opts.DNS))
		logger.Info(fmt.Sprintf("  2. Verify the backend service is running at %s", opts.Backend))
		logger.Info(fmt.Sprintf("  3. Test your service at https://%s", opts.DNS))
		logger.Info("")
	}

	logger.Info("View Caddy logs with:")
	logger.Info(fmt.Sprintf("  docker logs %s", hecate.CaddyContainerName))
	logger.Info("")
	logger.Info("View service-specific logs:")
	logger.Info(fmt.Sprintf("  docker exec %s tail -f /var/log/caddy/%s.log", hecate.CaddyContainerName, opts.Service))
}
