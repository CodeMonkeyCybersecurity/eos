// pkg/hecate/add/add.go

package add

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// errServiceAlreadyConfigured is a sentinel error indicating the service is already configured
// and no further processing is needed (success, but stop pipeline)
var errServiceAlreadyConfigured = errors.New("service already configured")

// AddService adds a new service to Hecate
// This is the main entry point that orchestrates all operations
func AddService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Display header with telemetry (BEFORE permission check for complete metrics)
	invocationMethod := opts.InvocationMethod
	if invocationMethod == "" {
		invocationMethod = "unknown" // Explicit "unknown" clearer than empty string
	}

	logger.Info("Adding new service to Hecate",
		zap.String("service", opts.Service),
		zap.String("dns", opts.DNS),
		zap.String("backend", opts.Backend),
		zap.Bool("sso", opts.SSO),
		zap.String("invocation_method", invocationMethod)) // Track UX preference

	// Check for root permissions
	if os.Geteuid() != 0 {
		return eos_err.NewUserError(
			"Permission denied: /opt/hecate requires root access\n\n" +
				"Run with sudo (either syntax works):\n" +
				"  sudo eos update hecate --add [service] --dns [domain] --upstream [backend]\n" +
				"  sudo eos update hecate add [service] --dns [domain] --upstream [backend]")
	}

	// If dry-run, show what would be done and exit (no lock needed for read-only)
	if opts.DryRun {
		return runDryRun(rc, opts)
	}

	// CRITICAL P0.4: Acquire file lock to prevent concurrent Caddyfile modifications
	// This prevents race conditions where two admins run --add simultaneously
	lock, err := hecate.AcquireCaddyfileLock(rc)
	if err != nil {
		return fmt.Errorf("failed to acquire Caddyfile lock: %w", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			logger.Error("Failed to release Caddyfile lock", zap.Error(releaseErr))
		}
	}()

	// Phase 1: Validation
	if err := runValidationPhase(rc, opts); err != nil {
		return err
	}

	// Phase 2: Pre-flight checks
	if err := runPreflightChecks(rc, opts); err != nil {
		// Check for sentinel error indicating service is already configured
		if errors.Is(err, errServiceAlreadyConfigured) {
			return nil // Success - service already configured, nothing more to do
		}
		return err
	}

	// Phase 3: Backup (BEFORE service integration)
	// CRITICAL P0.5: Backup MUST happen before service integration
	// RATIONALE: Service integration may create external resources (Authentik providers)
	//            that cannot be rolled back. If integration succeeds but Caddyfile append
	//            fails, we can restore the Caddyfile backup. If integration fails, no backup
	//            needed since Caddyfile wasn't modified yet.
	backupPath, err := runBackupPhase(rc, opts)
	if err != nil {
		return err
	}

	// Phase 4: Service-specific integration (if registered)
	// Runs AFTER backup so Caddyfile can be restored if integration creates external
	// resources (e.g., Authentik proxy providers) but subsequent operations fail
	if err := runServiceIntegration(rc, opts); err != nil {
		// Integration failed - restore backup
		logger.Error("Service integration failed, restoring backup", zap.Error(err))
		if restoreErr := RestoreBackup(rc, backupPath); restoreErr != nil {
			logger.Error("CRITICAL: Failed to restore backup after integration failure", zap.Error(restoreErr))
			return fmt.Errorf("service integration failed and backup restore failed: %w (restore error: %v)", err, restoreErr)
		}
		logger.Info("Backup restored after integration failure")
		return fmt.Errorf("service integration failed: %w", err)
	}

	// Phase 5: Generate and append route
	if err := runAppendRoutePhase(rc, opts); err != nil {
		// Restore backup on failure
		logger.Error("Failed to append route, restoring backup", zap.Error(err))
		if restoreErr := RestoreBackup(rc, backupPath); restoreErr != nil {
			logger.Error("CRITICAL: Failed to restore backup", zap.Error(restoreErr))
			return fmt.Errorf("append route failed and backup restore failed: %w (restore error: %v)", err, restoreErr)
		}

		// CRITICAL: Must reload Caddy with restored config
		// ReloadCaddy now has restart fallback built-in
		logger.Info("Backup restored to disk, reloading Caddy with restored config")
		if reloadErr := ReloadCaddy(rc, CaddyfilePath); reloadErr != nil {
			logger.Error("CRITICAL: Backup restored but Caddy reload failed",
				zap.Error(reloadErr))
			logger.Error("Manual intervention required: restart Caddy manually")
			logger.Error("  docker restart " + hecate.CaddyContainerName)
			return fmt.Errorf("append route failed and restored config reload failed: %w (reload error: %v)", err, reloadErr)
		}

		logger.Info("Caddy successfully reloaded with restored configuration")
		return err // Return original error after successful rollback
	}

	// Phase 6: Validate and reload Caddy
	if err := runCaddyReloadPhase(rc, backupPath); err != nil {
		return err
	}

	// Phase 7: Verify route
	verificationErr := runVerificationPhase(rc, opts)
	if verificationErr != nil {
		// Non-fatal warning - config is applied, verification timing issue
		logger.Warn("Route verification had issues", zap.Error(verificationErr))
	}

	// Phase 8: Cleanup old backups
	if err := CleanupOldBackups(rc, opts.BackupRetentionDays); err != nil {
		// Non-fatal warning
		logger.Warn("Failed to cleanup old backups", zap.Error(err))
	}

	// Success! (pass verification status to message)
	printSuccessMessage(logger, opts, verificationErr)

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

	// Check for duplicates (idempotency check)
	duplicateResult, err := CheckDuplicateService(rc, CaddyfilePath, opts.Service, opts.DNS)
	if err != nil {
		return fmt.Errorf("failed to check for duplicates: %w", err)
	}

	// IDEMPOTENCY: If service already exists, check if we should still run integration
	if duplicateResult.HasDuplicate {
		// SPECIAL CASE: BionicGPT with SSO flag - may need to configure Authentik integration
		// even if Caddyfile route exists (user may have added route manually or integration failed)
		if opts.Service == "bionicgpt" && opts.SSO {
			logger.Info("BionicGPT route already exists, checking if SSO integration is complete...")

			// Check if Authentik application exists for this service
			authentikConfigured, checkErr := isBionicGPTAuthentikConfigured(rc, opts.DNS)

			// If fully configured (route + SSO), exit gracefully
			if checkErr == nil && authentikConfigured {
				logger.Info("✓ BionicGPT route AND Authentik SSO already configured",
					zap.String("service", opts.Service),
					zap.String("dns", opts.DNS))
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: ✓ Service is fully configured (Caddyfile route + Authentik SSO)")
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: Service: bionicgpt")
				logger.Info("terminal prompt: DNS: " + opts.DNS)
				logger.Info("terminal prompt: SSO: Enabled via Authentik")
				logger.Info("terminal prompt: ")
				return errServiceAlreadyConfigured // Sentinel: fully configured, stop processing
			}

			// If not configured OR verification failed, configure SSO
			if checkErr != nil {
				logger.Warn("Could not verify Authentik configuration, will attempt integration", zap.Error(checkErr))
			} else {
				logger.Info("BionicGPT route exists but Authentik SSO not configured - will configure SSO only")
			}

			// Skip to Phase 4 (service integration) - don't re-add Caddyfile route
			logger.Info("Phase 2/6: Skipping pre-flight checks (route exists)")
			logger.Info("Phase 3/6: Skipping backup (no Caddyfile changes)")

			// Run service integration directly
			if err := runServiceIntegration(rc, opts); err != nil {
				return fmt.Errorf("SSO integration failed: %w", err)
			}

			logger.Info("✓ Authentik SSO configured for existing BionicGPT route")
			logger.Info("")
			logger.Info("BionicGPT is now accessible with Authentik authentication:")
			logger.Info(fmt.Sprintf("  URL: https://%s", opts.DNS))
			logger.Info("  SSO: Enabled via Authentik forward auth")
			logger.Info("")
			return errServiceAlreadyConfigured // Sentinel: SSO configured, Caddyfile route exists, stop processing
		}

		// Standard duplicate handling for non-BionicGPT or non-SSO cases
		if duplicateResult.DuplicateType == "service" {
			logger.Info("✓ Service already configured",
				zap.String("service", opts.Service))
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: ⚠️  Service '" + opts.Service + "' is already configured in Hecate")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: Current configuration:")
			logger.Info("terminal prompt:   Service: " + opts.Service)
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: To modify this service:")
			logger.Info("terminal prompt:   1. Remove: eos update hecate --remove " + opts.Service)
			logger.Info("terminal prompt:   2. Re-add: eos update hecate --add " + opts.Service + " --dns <domain> --upstream <backend>")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: To avoid accidental changes, 'eos update hecate --add' will not modify existing services.")
			return errServiceAlreadyConfigured // Sentinel: service already configured, stop processing
		}

		if duplicateResult.DuplicateType == "dns" {
			logger.Info("✓ DNS already configured",
				zap.String("dns", opts.DNS))
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: ⚠️  DNS '" + opts.DNS + "' is already configured in Hecate")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: Each domain can only have one route.")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: Check existing routes:")
			logger.Info("terminal prompt:   eos list hecate routes")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: To modify this route:")
			logger.Info("terminal prompt:   1. Find service name in route list")
			logger.Info("terminal prompt:   2. Remove: eos update hecate --remove <service>")
			logger.Info("terminal prompt:   3. Re-add: eos update hecate --add <service> --dns " + opts.DNS + " --upstream <backend>")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: To avoid accidental changes, 'eos update hecate --add' will not modify existing routes.")
			return errServiceAlreadyConfigured // Sentinel: DNS already configured, stop processing
		}
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

	// Check Admin API reachability (determines validation strategy)
	if IsAdminAPIReachable(rc) {
		logger.Info("✓ Caddy Admin API is accessible (will use zero-downtime reload)")
	} else {
		logger.Warn("Caddy Admin API not accessible from host",
			zap.String("url", fmt.Sprintf("http://%s:%d", hecate.CaddyAdminAPIHost, hecate.CaddyAdminAPIPort)))
		logger.Warn("This is expected if port 2019 is not exposed in docker-compose.yml")
		logger.Warn("Validation will use docker exec reload method (minimal downtime: ~50ms)")
		logger.Warn("")
		logger.Warn("To enable even faster reloads (Admin API - ~35μs):")
		logger.Warn("  1. Edit /opt/hecate/docker-compose.yml")
		logger.Warn("  2. Add to caddy ports: - \"127.0.0.1:2019:2019\"")
		logger.Warn("  3. Restart: cd /opt/hecate && docker-compose up -d")
		logger.Warn("")
	}

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

			// Warn about high latency (>200ms suggests poor UX)
			// Typical causes: Cross-region backends, VPN overhead, network congestion
			if backendResult.Latency > 200*time.Millisecond {
				logger.Warn("⚠️  High backend latency detected",
					zap.Duration("latency", backendResult.Latency),
					zap.String("threshold", "200ms"))
				logger.Warn("Users may experience slow response times")
				logger.Warn("Consider:")
				logger.Warn("  • Deploying backend closer to proxy server (reduce network hops)")
				logger.Warn("  • Checking for network congestion or VPN overhead")
				logger.Warn("  • Using CDN or edge caching if backend is remote")
			}
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

	// SAFETY CHECK: Re-verify no duplicate before appending
	// This prevents race conditions and guards against logic bugs
	duplicateResult, err := CheckDuplicateService(rc, CaddyfilePath, opts.Service, opts.DNS)
	if err != nil {
		return fmt.Errorf("failed to check for duplicates before append: %w", err)
	}

	if duplicateResult.HasDuplicate {
		logger.Warn("Route already exists in Caddyfile - skipping append to prevent duplicate",
			zap.String("dns", opts.DNS),
			zap.String("service", opts.Service))
		logger.Info("✓ Route already configured (no changes needed)")
		return nil
	}

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
			return fmt.Errorf("validation failed and backup restore failed: %w (restore error: %v)", err, restoreErr)
		}

		// CRITICAL: Must reload Caddy with restored config
		// ReloadCaddy now has restart fallback built-in, so this will work even if Admin API unavailable
		logger.Info("Backup restored to disk, reloading Caddy with restored config")
		if reloadErr := ReloadCaddy(rc, CaddyfilePath); reloadErr != nil {
			logger.Error("CRITICAL: Backup restored but Caddy reload failed",
				zap.Error(reloadErr))
			logger.Error("Manual intervention required: restart Caddy manually")
			logger.Error("  docker restart " + hecate.CaddyContainerName)
			return fmt.Errorf("validation failed and restored config reload failed: %w (reload error: %v)", err, reloadErr)
		}

		logger.Info("Caddy successfully reloaded with restored configuration")
		return err // Return original validation error after successful rollback
	}
	logger.Info("✓ Caddy configuration validated")

	// Reload Caddy with new configuration
	if err := ReloadCaddy(rc, CaddyfilePath); err != nil {
		// Restore backup on reload failure
		logger.Error("Caddy reload failed, restoring backup")
		if restoreErr := RestoreBackup(rc, backupPath); restoreErr != nil {
			logger.Error("CRITICAL: Failed to restore backup", zap.Error(restoreErr))
			return fmt.Errorf("reload failed and backup restore failed: %w (restore error: %v)", err, restoreErr)
		}

		// Reload with restored config (restart fallback built-in)
		logger.Info("Backup restored to disk, reloading Caddy with restored config")
		if reloadErr := ReloadCaddy(rc, CaddyfilePath); reloadErr != nil {
			logger.Error("CRITICAL: Backup restored but Caddy reload still failing",
				zap.Error(reloadErr))
			logger.Error("Manual intervention required: restart Caddy manually")
			logger.Error("  docker restart " + hecate.CaddyContainerName)
			return fmt.Errorf("reload failed and restored config reload failed: %w (reload error: %v)", err, reloadErr)
		}

		logger.Info("Caddy successfully reloaded with restored configuration")
		return err // Return original reload error after successful rollback
	}
	logger.Info("✓ Caddy reloaded successfully")

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

// isBionicGPTAuthentikConfigured checks if BionicGPT application exists in Authentik
func isBionicGPTAuthentikConfigured(rc *eos_io.RuntimeContext, dns string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use BionicGPT integrator's credential discovery logic (P0 #1 fix: reuse existing helper)
	integrator := &BionicGPTIntegrator{resources: &IntegrationResources{}}
	authentikToken, authentikURL, err := integrator.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	// Connect to Authentik API
	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Check if BionicGPT application exists for THIS SPECIFIC DNS
	// P1 #5 FIX: Check DNS-specific app configuration, not just "any bionicgpt app exists"
	apps, err := authentikClient.ListApplications(rc.Ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list Authentik applications: %w", err)
	}

	expectedLaunchURL := fmt.Sprintf("https://%s", dns)

	for _, app := range apps {
		if app.Slug == "bionicgpt" && app.MetaLaunchURL == expectedLaunchURL {
			logger.Debug("BionicGPT application found in Authentik for this DNS",
				zap.String("slug", app.Slug),
				zap.String("name", app.Name),
				zap.String("launch_url", app.MetaLaunchURL))
			return true, nil
		}
	}

	logger.Debug("BionicGPT application not found in Authentik for this DNS",
		zap.String("expected_launch_url", expectedLaunchURL))
	return false, nil
}

// printSuccessMessage prints the final success message
// verificationErr indicates if route verification failed (non-fatal, but affects message)
func printSuccessMessage(logger otelzap.LoggerWithCtx, opts *ServiceOptions, verificationErr error) {
	logger.Info("")

	// Distinguish between config success and route accessibility
	if verificationErr != nil {
		logger.Info("✅ Configuration updated successfully!")
		logger.Info("⚠️  Route verification failed - this is usually a timing issue")
		logger.Info("")
		logger.Info("Common causes:")
		logger.Info("  • TLS certificate still provisioning (Let's Encrypt ACME challenge in progress)")
		logger.Info("  • DNS propagation delay (if you just updated DNS)")
		logger.Info("  • Backend service starting up")
		logger.Info("")
		logger.Info("What to do:")
		logger.Info("  1. Wait 2-3 minutes for TLS certificate provisioning to complete")
		logger.Info(fmt.Sprintf("  2. Test manually: curl -v https://%s/", opts.DNS))
		logger.Info("  3. Check Caddy logs: docker logs hecate-caddy")
		logger.Info(fmt.Sprintf("  4. Run diagnostics: eos debug hecate --bionicgpt"))
		logger.Info("")
	} else {
		logger.Info("✅ Service added successfully!")
		logger.Info("✅ Route verification passed - service is accessible")
		logger.Info("")
	}

	logger.Info(fmt.Sprintf("Service: %s", opts.Service))
	logger.Info(fmt.Sprintf("Domain: https://%s", opts.DNS))
	logger.Info(fmt.Sprintf("Backend: %s", opts.Backend))
	if opts.SSO || opts.Service == "bionicgpt" {
		logger.Info(fmt.Sprintf("SSO: Enabled (Authentik forward auth)"))
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
