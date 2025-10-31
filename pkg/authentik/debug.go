// pkg/authentik/debug.go
// *Last Updated: 2025-10-28*

package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikCheckResult represents the result of a diagnostic check
type AuthentikCheckResult struct {
	CheckName   string
	Category    string
	Passed      bool
	Warning     bool
	Error       error
	Details     string
	Remediation []string
}

// DebugConfig contains configuration for Authentik debugging
type DebugConfig struct {
	HecatePath string
	Verbose    bool
}

// RunAuthentikDebug runs comprehensive Authentik diagnostics
// Assess → Intervene → Evaluate pattern
func RunAuthentikDebug(rc *eos_io.RuntimeContext, config *DebugConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate configuration
	logger.Debug("Pre-operation diagnostics",
		zap.String("hecate_path", config.HecatePath),
		zap.Bool("verbose", config.Verbose))

	if config.HecatePath == "" {
		config.HecatePath = "/opt/hecate"
	}

	// Check if hecate directory exists
	if _, err := os.Stat(config.HecatePath); os.IsNotExist(err) {
		return fmt.Errorf("hecate installation not found at %s\n"+
			"Install Hecate first: eos create hecate", config.HecatePath)
	}

	logger.Info("Starting Authentik pre-upgrade health check",
		zap.String("path", config.HecatePath))

	fmt.Println("=========================================")
	fmt.Println("Authentik Pre-Upgrade Health Check")
	fmt.Println("=========================================")
	fmt.Println()

	// INTERVENE: Run all diagnostic checks
	var allResults []AuthentikCheckResult

	// 1. Current version check
	allResults = append(allResults, checkAuthentikVersion(rc, config.HecatePath)...)

	// 2. Disk space check
	allResults = append(allResults, checkAuthentikDiskSpace(rc, config.HecatePath)...)

	// 3. Container health
	allResults = append(allResults, checkContainerHealth(rc, config.HecatePath)...)

	// 4. PostgreSQL checks
	allResults = append(allResults, checkPostgreSQLEncoding(rc, config.HecatePath)...)

	// 5. Redis check
	allResults = append(allResults, checkRedisConnectivity(rc, config.HecatePath)...)

	// 6. Custom modifications check
	allResults = append(allResults, checkCustomModifications(rc, config.HecatePath)...)

	// 7. Environment file check
	allResults = append(allResults, checkEnvironmentFile(rc, config.HecatePath)...)

	// 8. Task queue check
	allResults = append(allResults, checkTaskQueue(rc, config.HecatePath)...)

	// 9. Memory check
	allResults = append(allResults, checkMemoryUsage(rc, config.HecatePath)...)

	// 10. Backup status check
	allResults = append(allResults, checkBackupStatus(rc, config.HecatePath)...)

	// 11. API connectivity check
	allResults = append(allResults, checkAuthentikAPI(rc, config.HecatePath)...)

	// 12. Embedded outpost diagnostics (process, ports, environment, health)
	allResults = append(allResults, checkEmbeddedOutpostDiagnostics(rc, config.HecatePath)...)

	// 13. Proxy provider configuration check
	allResults = append(allResults, checkAuthentikProxyConfiguration(rc, config.HecatePath)...)

	// EVALUATE: Display results and provide summary
	displayResults(allResults)
	displayPreUpgradeSummary(allResults)

	logger.Info("Authentik diagnostics completed",
		zap.Int("total_checks", len(allResults)),
		zap.Int("passed", countPassed(allResults)),
		zap.Int("failed", countFailed(allResults)),
		zap.Int("warnings", countWarnings(allResults)))

	// 14. Configuration Export - Show complete Authentik state
	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("Authentik Configuration Export")
	fmt.Println("=========================================")
	fmt.Println()

	if err := displayAuthentikConfiguration(rc, config.HecatePath); err != nil {
		logger.Warn("Failed to export Authentik configuration",
			zap.Error(err))
		fmt.Printf("\n❌ Configuration export failed: %v\n", err)
		fmt.Println("\nYou can manually check configuration in Authentik UI:")
		fmt.Println("  • http://localhost:9000/if/admin/#/core/brands")
		fmt.Println("  • http://localhost:9000/if/admin/#/flow/flows")
		fmt.Println("  • http://localhost:9000/if/admin/#/identity/groups")
	}

	return nil
}

// checkAuthentikVersion checks the current Authentik version
func checkAuthentikVersion(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	logger.Debug("Checking Authentik version",
		zap.String("command", "docker compose exec server ak version"))

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "server", "ak", "version")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Failed to determine Authentik version",
			zap.Error(err),
			zap.String("reason", "command execution failed"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Current Version",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("could not determine version"),
			Details:   "Unable to query Authentik version",
		})
		return results
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		version = "unknown"
	}

	logger.Info("Authentik version detected", zap.String("version", version))

	results = append(results, AuthentikCheckResult{
		CheckName: "Current Version",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   fmt.Sprintf("Current version: %s", version),
	})

	return results
}

// checkAuthentikDiskSpace checks available disk space
func checkAuthentikDiskSpace(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "df", "-h", hecatePath)
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Failed to check disk space", zap.Error(err))
		results = append(results, AuthentikCheckResult{
			CheckName: "Disk Space",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     err,
		})
		return results
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) >= 2 {
		fields := strings.Fields(lines[1])
		if len(fields) >= 5 {
			usage := fields[4]
			usageInt := 0
			_, _ = fmt.Sscanf(usage, "%d%%", &usageInt)

			if usageInt < 90 {
				results = append(results, AuthentikCheckResult{
					CheckName: "Disk Space",
					Category:  "Pre-Upgrade",
					Passed:    true,
					Details:   fmt.Sprintf("Disk usage: %s (OK)", usage),
				})
			} else {
				logger.Warn("Low disk space detected",
					zap.String("usage", usage),
					zap.String("remediation", "free up disk space before upgrading"))

				results = append(results, AuthentikCheckResult{
					CheckName: "Disk Space",
					Category:  "Pre-Upgrade",
					Passed:    false,
					Warning:   true,
					Details:   fmt.Sprintf("Disk usage: %s (Low space warning!)", usage),
					Remediation: []string{
						"Free up disk space before upgrading",
						"Consider cleaning old Docker images: docker image prune -a",
					},
				})
			}
		}
	}

	return results
}

// checkContainerHealth checks if Authentik containers are running
func checkContainerHealth(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "ps", "--format", "table {{.Name}}\t{{.Status}}\t{{.State}}")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Error("Failed to check container health",
			zap.Error(err),
			zap.String("remediation", "ensure docker is running"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Container Health",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     err,
		})
		return results
	}

	details := "Container status:\n" + string(output)
	allRunning := strings.Count(string(output), "running") > 0
	anyExited := strings.Contains(string(output), "exited") || strings.Contains(string(output), "dead")

	if anyExited {
		logger.Warn("Some containers are not running",
			zap.String("remediation", "start all containers with docker compose up -d"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Container Health",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   details,
			Remediation: []string{
				"Some containers are not running",
				"Start all containers: cd /opt/hecate && docker compose up -d",
			},
		})
	} else if allRunning {
		results = append(results, AuthentikCheckResult{
			CheckName: "Container Health",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "All containers are running",
		})
	}

	return results
}

// checkPostgreSQLEncoding checks database encoding (CRITICAL for 2025.8+)
func checkPostgreSQLEncoding(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	// Check encoding
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "postgresql",
		"psql", "-U", "authentik", "-d", "authentik", "-c", "SHOW SERVER_ENCODING;")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Error("Failed to check database encoding",
			zap.Error(err),
			zap.String("remediation", "ensure PostgreSQL is running"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Database Encoding",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     err,
			Remediation: []string{
				"Could not check database encoding",
				"Ensure PostgreSQL is running",
			},
		})
		return results
	}

	isUTF8 := strings.Contains(strings.ToUpper(string(output)), "UTF8") ||
		strings.Contains(strings.ToUpper(string(output)), "UTF-8")

	if isUTF8 {
		logger.Info("Database encoding check passed", zap.String("encoding", "UTF8"))
		results = append(results, AuthentikCheckResult{
			CheckName: "Database Encoding",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Database encoding is UTF8 (required for 2025.8+)",
		})
	} else {
		logger.Error("Database encoding is not UTF8 - CRITICAL ISSUE",
			zap.String("encoding", string(output)),
			zap.String("remediation", "database migration required"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Database Encoding",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf("database encoding is not UTF8"),
			Details:   "Database must use UTF8 encoding for Authentik 2025.8+",
			Remediation: []string{
				"WARNING: Database encoding must be UTF8",
				"This is a CRITICAL requirement for Authentik 2025.8+",
				"Database migration may be required",
			},
		})
	}

	// Check database size
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	sizeCmd := exec.CommandContext(ctx2, "docker", "compose", "exec", "-T", "postgresql",
		"psql", "-U", "authentik", "-d", "authentik", "-c",
		"SELECT pg_database_size('authentik')/1024/1024 as size_mb;")
	sizeCmd.Dir = hecatePath
	sizeOutput, _ := sizeCmd.Output()
	cancel2()

	if len(sizeOutput) > 0 {
		results = append(results, AuthentikCheckResult{
			CheckName: "Database Size",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Database size:\n" + string(sizeOutput),
		})
	}

	return results
}

// checkRedisConnectivity checks if Redis is responding
func checkRedisConnectivity(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	// P0 FIX: Add authentication support for Redis health check
	// RATIONALE: Redis may require AUTH if REDIS_PASSWORD is set in .env
	// EVIDENCE: Diagnostic shows "exit status 1" not "127" (command exists, auth likely failed)

	// Step 1: Check if Redis requires authentication
	envPath := filepath.Join(hecatePath, ".env")
	envVars, err := shared.ParseEnvFile(envPath)
	var redisPassword string
	if err == nil {
		redisPassword = envVars["REDIS_PASSWORD"] // May be empty if no auth
	}

	// Step 2: Build redis-cli command with optional auth
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	var cmd *exec.Cmd
	if redisPassword != "" {
		logger.Debug("Redis password found in .env, using authenticated ping")
		cmd = exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "redis",
			"redis-cli", "-a", redisPassword, "ping")
	} else {
		logger.Debug("No Redis password in .env, using unauthenticated ping")
		cmd = exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "redis",
			"redis-cli", "ping")
	}
	cmd.Dir = hecatePath
	output, err := cmd.CombinedOutput() // Use CombinedOutput to capture stderr (auth errors)
	cancel()

	logger.Debug("Redis ping result",
		zap.Error(err),
		zap.String("output", string(output)))

	if err != nil || !strings.Contains(string(output), "PONG") {
		logger.Error("Redis not responding",
			zap.Error(err),
			zap.String("output", string(output)), // Include output for debugging
			zap.String("remediation", "check Redis logs or restart container"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Redis Connectivity",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf("redis not responding"),
			Remediation: []string{
				"Ensure Redis is running",
				"Restart Redis: cd /opt/hecate && docker compose restart redis",
			},
		})
	} else {
		logger.Debug("Redis connectivity check passed")
		results = append(results, AuthentikCheckResult{
			CheckName: "Redis Connectivity",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Redis is responding to PING",
		})
	}

	return results
}

// checkCustomModifications checks for custom templates and blueprints
func checkCustomModifications(_ *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	var results []AuthentikCheckResult

	// Check for custom templates
	customTemplatesPath := filepath.Join(hecatePath, "custom-templates")
	if info, err := os.Stat(customTemplatesPath); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(customTemplatesPath)
		if len(entries) > 0 {
			results = append(results, AuthentikCheckResult{
				CheckName: "Custom Templates",
				Category:  "Pre-Upgrade",
				Passed:    true,
				Warning:   true,
				Details:   fmt.Sprintf("Found %d custom template(s) - review compatibility after upgrade", len(entries)),
			})
		}
	} else {
		results = append(results, AuthentikCheckResult{
			CheckName: "Custom Templates",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No custom templates detected",
		})
	}

	// Check for custom blueprints
	customBlueprintsPath := filepath.Join(hecatePath, "authentik/blueprints/custom")
	if info, err := os.Stat(customBlueprintsPath); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(customBlueprintsPath)
		if len(entries) > 0 {
			results = append(results, AuthentikCheckResult{
				CheckName: "Custom Blueprints",
				Category:  "Pre-Upgrade",
				Passed:    true,
				Warning:   true,
				Details:   fmt.Sprintf("Found %d custom blueprint(s) - review compatibility after upgrade", len(entries)),
			})
		}
	} else {
		results = append(results, AuthentikCheckResult{
			CheckName: "Custom Blueprints",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No custom blueprints detected",
		})
	}

	return results
}

// checkEnvironmentFile checks for deprecated and renamed settings
func checkEnvironmentFile(_ *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	var results []AuthentikCheckResult

	envPath := filepath.Join(hecatePath, ".env")
	data, err := os.ReadFile(envPath)
	if err != nil {
		results = append(results, AuthentikCheckResult{
			CheckName: "Environment File",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf(".env file not found"),
		})
		return results
	}

	content := string(data)

	// Check for deprecated settings
	deprecated := []string{
		"AUTHENTIK_BROKER__URL",
		"AUTHENTIK_BROKER__TRANSPORT_OPTIONS",
		"AUTHENTIK_RESULT_BACKEND__URL",
	}

	var foundDeprecated []string
	for _, setting := range deprecated {
		if strings.Contains(content, setting) {
			foundDeprecated = append(foundDeprecated, setting)
		}
	}

	if len(foundDeprecated) > 0 {
		results = append(results, AuthentikCheckResult{
			CheckName: "Deprecated Settings",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   fmt.Sprintf("Found deprecated settings: %s", strings.Join(foundDeprecated, ", ")),
			Remediation: []string{
				"These settings will be removed during upgrade",
				"They are no longer needed in Authentik 2025.8+",
			},
		})
	} else {
		results = append(results, AuthentikCheckResult{
			CheckName: "Deprecated Settings",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No deprecated settings found",
		})
	}

	// Check for renamed settings
	if strings.Contains(content, "AUTHENTIK_WORKER__CONCURRENCY") {
		results = append(results, AuthentikCheckResult{
			CheckName: "Renamed Settings",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "AUTHENTIK_WORKER__CONCURRENCY will be renamed to AUTHENTIK_WORKER__THREADS",
			Remediation: []string{
				"This will be handled automatically during upgrade",
			},
		})
	}

	return results
}

// checkTaskQueue checks for active tasks in the Celery queue
func checkTaskQueue(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "worker",
		"bash", "-c", "DJANGO_SETTINGS_MODULE=authentik.root.settings celery -A authentik.root.celery inspect active")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Could not check task queue status", zap.Error(err))
		results = append(results, AuthentikCheckResult{
			CheckName: "Task Queue",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "Could not check task queue status",
		})
		return results
	}

	isEmpty := strings.Contains(string(output), "empty")

	if isEmpty {
		results = append(results, AuthentikCheckResult{
			CheckName: "Task Queue",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "No active tasks in queue (good for upgrade)",
		})
	} else {
		results = append(results, AuthentikCheckResult{
			CheckName: "Task Queue",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "There may be active tasks in the queue",
			Remediation: []string{
				"Consider waiting for tasks to complete before upgrading",
				"Or proceed during a maintenance window",
			},
		})
	}

	return results
}

// checkMemoryUsage checks available system memory
func checkMemoryUsage(rc *eos_io.RuntimeContext, _ string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "free", "-m")
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Could not check memory usage", zap.Error(err))
		results = append(results, AuthentikCheckResult{
			CheckName: "Memory Usage",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "Could not check memory usage",
		})
		return results
	}

	lines := strings.Split(string(output), "\n")
	var availableMem int
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				_, _ = fmt.Sscanf(fields[6], "%d", &availableMem)
				break
			}
		}
	}

	details := string(output)

	if availableMem > 1000 {
		results = append(results, AuthentikCheckResult{
			CheckName: "Memory Usage",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   fmt.Sprintf("Sufficient memory available (%d MB)\n%s", availableMem, details),
		})
	} else {
		logger.Warn("Low memory detected",
			zap.Int("available_mb", availableMem),
			zap.String("remediation", "monitor memory usage during upgrade"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Memory Usage",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   fmt.Sprintf("Low memory (%d MB available) - monitor during upgrade\n%s", availableMem, details),
			Remediation: []string{
				"Monitor memory usage during upgrade",
				"Consider freeing up memory before upgrading",
			},
		})
	}

	return results
}

// checkBackupStatus checks if recent backups exist
func checkBackupStatus(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	backupDir := filepath.Join(hecatePath, "backups")
	entries, err := os.ReadDir(backupDir)

	if err != nil {
		results = append(results, AuthentikCheckResult{
			CheckName: "Backup Status",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("no backup directory found"),
			Remediation: []string{
				"Create a backup before upgrading",
				"Run: eos backup authentik",
			},
		})
		return results
	}

	if len(entries) == 0 {
		results = append(results, AuthentikCheckResult{
			CheckName: "Backup Status",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   "No backups found",
			Remediation: []string{
				"Create a backup before upgrading",
				"Run: eos backup authentik",
			},
		})
		return results
	}

	// Find most recent backup
	var latestBackup string
	var latestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			info, _ := entry.Info()
			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				latestBackup = entry.Name()
			}
		}
	}

	// P0 FIX: Validate backup is recent (within 24 hours)
	// RATIONALE: Pre-upgrade checks should ensure RECENT backups
	// SECURITY: Prevent data loss from stale backups
	if latestTime.IsZero() {
		// No valid backups found (all timestamps were zero)
		results = append(results, AuthentikCheckResult{
			CheckName: "Backup Status",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   "No valid backups found in backup directory",
			Remediation: []string{
				"Create a backup before upgrading",
				"Run: eos backup authentik",
			},
		})
		return results
	}

	backupAge := time.Since(latestTime)
	if backupAge > 24*time.Hour {
		logger.Warn("Backup is stale",
			zap.String("backup", latestBackup),
			zap.Duration("age", backupAge),
			zap.String("remediation", "create fresh backup before upgrade"))

		results = append(results, AuthentikCheckResult{
			CheckName: "Backup Status",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   fmt.Sprintf("Latest backup is %s old: %s (created %s)",
				backupAge.Round(time.Hour), latestBackup, latestTime.Format("2006-01-02 15:04:05")),
			Remediation: []string{
				"Backup is stale - create fresh backup before upgrade",
				"Run: eos backup authentik",
				fmt.Sprintf("Current backup age: %s (max recommended: 24 hours)", backupAge.Round(time.Hour)),
			},
		})
		return results
	}

	results = append(results, AuthentikCheckResult{
		CheckName: "Backup Status",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   fmt.Sprintf("Latest backup: %s (created %s ago at %s)",
			latestBackup, backupAge.Round(time.Minute), latestTime.Format("2006-01-02 15:04:05")),
	})

	return results
}

// checkAuthentikAPI checks API connectivity using the bootstrap token
// This validates that the AUTHENTIK_BOOTSTRAP_TOKEN in .env file is valid
// and can be used for API authentication (required for eos update hecate --add)
func checkAuthentikAPI(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	// Step 1: Parse .env file to get AUTHENTIK_BOOTSTRAP_TOKEN
	envPath := filepath.Join(hecatePath, ".env")
	envVars, err := shared.ParseEnvFile(envPath)
	if err != nil {
		logger.Error("Failed to parse .env file",
			zap.Error(err),
			zap.String("path", envPath))

		results = append(results, AuthentikCheckResult{
			CheckName: "API Token Configuration",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf(".env file not readable: %w", err),
			Remediation: []string{
				"Ensure .env file exists at " + envPath,
				"Check file permissions: sudo ls -la " + envPath,
			},
		})
		return results
	}

	// Step 2: Check for AUTHENTIK_BOOTSTRAP_TOKEN
	bootstrapToken := envVars["AUTHENTIK_BOOTSTRAP_TOKEN"]
	if bootstrapToken == "" {
		logger.Error("AUTHENTIK_BOOTSTRAP_TOKEN not found or empty in .env file")

		results = append(results, AuthentikCheckResult{
			CheckName: "API Token Configuration",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf("AUTHENTIK_BOOTSTRAP_TOKEN not found in .env"),
			Details:   "Bootstrap token is required for API authentication",
			Remediation: []string{
				"Bootstrap token should be auto-generated during Hecate installation",
				"Check .env file: sudo cat " + envPath + " | grep BOOTSTRAP_TOKEN",
				"If missing, regenerate with: eos create hecate",
			},
		})
		return results
	}

	logger.Debug("Found AUTHENTIK_BOOTSTRAP_TOKEN in .env file",
		zap.String("token_prefix", bootstrapToken[:min(4, len(bootstrapToken))]+"***"))

	// Step 3: Check basic API health (unauthenticated endpoint)
	// P0 FIX: Use Python instead of wget (Authentik containers don't include wget)
	// EVIDENCE: GitHub issue #15769 (July 2025) - wget not in container
	// VENDOR RECOMMENDATION: Use Python for health checks
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "server",
		"python3", "-c",
		`import urllib.request; print(urllib.request.urlopen("http://localhost:9000/-/health/live/").read().decode())`)
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Authentik API health endpoint not responding",
			zap.Error(err))

		results = append(results, AuthentikCheckResult{
			CheckName: "API Health Endpoint",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("API health check failed"),
			Remediation: []string{
				"Ensure Authentik server container is running",
				"Check container status: cd " + hecatePath + " && docker compose ps",
				"Check logs: cd " + hecatePath + " && docker compose logs server",
			},
		})
		return results
	}

	if !strings.Contains(string(output), "ok") && !strings.Contains(string(output), "live") {
		logger.Warn("Unexpected API health response",
			zap.String("response", string(output)))

		results = append(results, AuthentikCheckResult{
			CheckName: "API Health Endpoint",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   "API health endpoint returned unexpected response",
		})
		return results
	}

	logger.Debug("API health endpoint responding correctly")

	results = append(results, AuthentikCheckResult{
		CheckName: "API Health Endpoint",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   "Authentik API health endpoint is responding",
	})

	// Step 4: Test authenticated API call using bootstrap token
	// Use the /api/v3/core/users/ endpoint (requires authentication)
	// P0 FIX: Use Python instead of wget
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	pythonScript := fmt.Sprintf(`import urllib.request; req = urllib.request.Request("http://localhost:9000/api/v3/core/users/"); req.add_header("Authorization", "Bearer %s"); print(urllib.request.urlopen(req).read().decode())`, bootstrapToken)
	authCmd := exec.CommandContext(ctx2, "docker", "compose", "exec", "-T", "server",
		"python3", "-c", pythonScript)
	authCmd.Dir = hecatePath
	authOutput, authErr := authCmd.Output()
	cancel2()

	if authErr != nil {
		logger.Error("API authentication test failed",
			zap.Error(authErr),
			zap.String("endpoint", "/api/v3/core/users/"))

		results = append(results, AuthentikCheckResult{
			CheckName: "API Authentication",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Error:     fmt.Errorf("bootstrap token authentication failed"),
			Details:   "Could not authenticate to Authentik API using AUTHENTIK_BOOTSTRAP_TOKEN",
			Remediation: []string{
				"Bootstrap token may be invalid or expired",
				"Token is auto-generated during installation with 'intent: API access'",
				"Verify token in .env: sudo cat " + envPath + " | grep BOOTSTRAP_TOKEN",
				"If using manual token, ensure it was created with 'Intent: API' in Authentik admin UI",
			},
		})
		return results
	}

	// Check if response looks like valid JSON (users list)
	authResponse := string(authOutput)
	if !strings.Contains(authResponse, "results") && !strings.Contains(authResponse, "\"username\"") {
		logger.Warn("API authentication succeeded but unexpected response format",
			zap.String("response_preview", authResponse[:min(100, len(authResponse))]))

		results = append(results, AuthentikCheckResult{
			CheckName: "API Authentication",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "API authentication succeeded but response format unexpected (may indicate API version mismatch)",
		})
		return results
	}

	logger.Info("API authentication test passed using AUTHENTIK_BOOTSTRAP_TOKEN")

	results = append(results, AuthentikCheckResult{
		CheckName: "API Authentication",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   "Successfully authenticated to Authentik API using AUTHENTIK_BOOTSTRAP_TOKEN",
	})

	// Step 5: Provide informational message about API token usage
	apiToken := envVars["AUTHENTIK_API_TOKEN"]
	if apiToken == "" {
		results = append(results, AuthentikCheckResult{
			CheckName: "API Token (Optional)",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Warning:   true,
			Details:   "AUTHENTIK_API_TOKEN not set (using AUTHENTIK_BOOTSTRAP_TOKEN as fallback for automated operations)",
			Remediation: []string{
				"This is OK - bootstrap token works for API access",
				"Optional: Create dedicated API token in Authentik admin UI for better security",
				"Navigate to: Directory → Tokens → Create (Intent: API, Expiry: Never)",
			},
		})
	} else {
		results = append(results, AuthentikCheckResult{
			CheckName: "API Token (Optional)",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "AUTHENTIK_API_TOKEN is configured (will be used instead of bootstrap token)",
		})
	}

	return results
}

// checkEmbeddedOutpostDiagnostics performs low-level diagnostics of the embedded outpost
// Checks: process running, ports listening, environment variables, health endpoint
// CRITICAL: These checks identify WHY the outpost might not be responding
func checkEmbeddedOutpostDiagnostics(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	// Step 1: Check if embedded outpost process is running
	ctx1, cancel1 := context.WithTimeout(rc.Ctx, 5*time.Second)
	psCmd := exec.CommandContext(ctx1, "docker", "compose", "exec", "-T", "server",
		"ps", "aux")
	psCmd.Dir = hecatePath
	psOutput, psErr := psCmd.Output()
	cancel1()

	if psErr != nil {
		logger.Error("Failed to check server container processes",
			zap.Error(psErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Embedded Outpost Process",
			Category:  "Infrastructure",
			Passed:    false,
			Error:     fmt.Errorf("failed to list processes: %w", psErr),
			Remediation: []string{
				"Ensure Authentik server container is running",
				"Check container status: cd " + hecatePath + " && docker compose ps",
			},
		})
		return results
	}

	psResponse := string(psOutput)
	logger.Debug("Server container processes",
		zap.String("output_preview", psResponse[:min(300, len(psResponse))]))

	// Look for embedded outpost processes
	// Authentik 2024.x and newer run embedded outpost as part of server process
	hasServerProcess := strings.Contains(psResponse, "authentik server") ||
		strings.Contains(psResponse, "/lifecycle/ak server") ||
		strings.Contains(psResponse, "python -m authentik")

	if !hasServerProcess {
		logger.Warn("No Authentik server process found")
		results = append(results, AuthentikCheckResult{
			CheckName: "Embedded Outpost Process",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Authentik server process not detected in container",
			Remediation: []string{
				"Check server container logs: docker compose -f " + hecatePath + "/docker-compose.yml logs server",
				"Server process should be: 'authentik server' or '/lifecycle/ak server'",
			},
		})
	} else {
		logger.Info("Authentik server process detected")
		results = append(results, AuthentikCheckResult{
			CheckName: "Embedded Outpost Process",
			Category:  "Infrastructure",
			Passed:    true,
			Details:   "Authentik server process is running (embedded outpost runs within server process)",
		})
	}

	// Step 2: Check what ports are listening inside the container
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	netstatCmd := exec.CommandContext(ctx2, "docker", "compose", "exec", "-T", "server",
		"sh", "-c", "netstat -tlnp 2>/dev/null || ss -tlnp")
	netstatCmd.Dir = hecatePath
	netstatOutput, netstatErr := netstatCmd.Output()
	cancel2()

	if netstatErr != nil {
		logger.Warn("Failed to check listening ports",
			zap.Error(netstatErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Listening Ports",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Could not verify which ports are listening",
			Remediation: []string{
				"Manual check: docker exec hecate-server-1 ss -tlnp",
			},
		})
	} else {
		netstatResponse := string(netstatOutput)
		logger.Debug("Listening ports in server container",
			zap.String("output_preview", netstatResponse[:min(400, len(netstatResponse))]))

		// Check for expected ports
		has9000 := strings.Contains(netstatResponse, ":9000") || strings.Contains(netstatResponse, "0.0.0.0:9000")
		has9443 := strings.Contains(netstatResponse, ":9443") || strings.Contains(netstatResponse, "0.0.0.0:9443")

		if has9000 {
			logger.Info("Port 9000 is listening (main Authentik HTTP API)")
			results = append(results, AuthentikCheckResult{
				CheckName: "Port 9000 (HTTP)",
				Category:  "Infrastructure",
				Passed:    true,
				Details:   "Port 9000 is listening - main Authentik API endpoint",
			})
		} else {
			logger.Warn("Port 9000 not detected in listening ports")
			results = append(results, AuthentikCheckResult{
				CheckName: "Port 9000 (HTTP)",
				Category:  "Infrastructure",
				Passed:    false,
				Warning:   true,
				Details:   "Port 9000 not listening - Authentik API may not be accessible",
				Remediation: []string{
					"Check server logs: docker compose -f " + hecatePath + "/docker-compose.yml logs server",
					"Verify AUTHENTIK_LISTEN__HTTP environment variable",
				},
			})
		}

		if has9443 {
			logger.Info("Port 9443 is listening (embedded outpost HTTPS)")
			results = append(results, AuthentikCheckResult{
				CheckName: "Port 9443 (HTTPS/Metrics)",
				Category:  "Infrastructure",
				Passed:    true,
				Details:   "Port 9443 is listening - embedded outpost HTTPS endpoint",
			})
		} else {
			logger.Debug("Port 9443 not detected (may be expected - metrics endpoint is optional)")
		}
	}

	// Step 3: Check environment variables for outpost configuration
	ctx3, cancel3 := context.WithTimeout(rc.Ctx, 5*time.Second)
	envCmd := exec.CommandContext(ctx3, "docker", "compose", "exec", "-T", "server",
		"env")
	envCmd.Dir = hecatePath
	envOutput, envErr := envCmd.Output()
	cancel3()

	if envErr != nil {
		logger.Warn("Failed to check environment variables",
			zap.Error(envErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Environment Variables",
			Category:  "Configuration",
			Passed:    false,
			Warning:   true,
			Details:   "Could not verify outpost environment configuration",
		})
	} else {
		envResponse := string(envOutput)
		logger.Debug("Environment variables in server container",
			zap.Int("env_count", strings.Count(envResponse, "\n")))

		// Filter for AUTHENTIK_OUTPOSTS_* or AUTHENTIK_* variables
		authentikVars := []string{}
		for _, line := range strings.Split(envResponse, "\n") {
			if strings.HasPrefix(line, "AUTHENTIK_") {
				// Redact sensitive values
				if strings.Contains(line, "SECRET") || strings.Contains(line, "KEY") || strings.Contains(line, "TOKEN") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						authentikVars = append(authentikVars, parts[0]+"=***REDACTED***")
					}
				} else {
					authentikVars = append(authentikVars, line)
				}
			}
		}

		if len(authentikVars) > 0 {
			logger.Info("Found Authentik environment variables",
				zap.Int("count", len(authentikVars)))

			results = append(results, AuthentikCheckResult{
				CheckName: "Environment Variables",
				Category:  "Configuration",
				Passed:    true,
				Details:   fmt.Sprintf("Found %d Authentik environment variables configured", len(authentikVars)),
			})
		} else {
			logger.Warn("No AUTHENTIK_* environment variables found")
			results = append(results, AuthentikCheckResult{
				CheckName: "Environment Variables",
				Category:  "Configuration",
				Passed:    false,
				Warning:   true,
				Details:   "No AUTHENTIK_* environment variables detected",
				Remediation: []string{
					"Check .env file: cat " + hecatePath + "/.env | grep AUTHENTIK_",
					"Verify docker-compose.yml loads .env file correctly",
				},
			})
		}
	}

	// Step 4: Get authentication token for health check
	envPath := filepath.Join(hecatePath, ".env")
	envVars, err := shared.ParseEnvFile(envPath)
	if err != nil {
		logger.Warn("Could not parse .env file for health check",
			zap.Error(err))

		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Skipped - could not read API token from .env",
		})
		return results
	}

	// Get token (prefer API token, fallback to bootstrap token)
	token := envVars["AUTHENTIK_API_TOKEN"]
	if token == "" {
		token = envVars["AUTHENTIK_BOOTSTRAP_TOKEN"]
	}

	if token == "" {
		logger.Warn("No API token available for outpost health check")
		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Skipped - no API token configured",
		})
		return results
	}

	// Step 5: Check outpost instance health via API
	// First, get the outpost ID (usually the embedded outpost)
	ctx4, cancel4 := context.WithTimeout(rc.Ctx, 10*time.Second)
	outpostsCmd := exec.CommandContext(ctx4, "docker", "compose", "exec", "-T", "server",
		"wget", "-q", "-O", "-",
		"--header", "Authorization: Bearer "+token,
		"http://localhost:9000/api/v3/outposts/instances/")
	outpostsCmd.Dir = hecatePath
	outpostsOutput, outpostsErr := outpostsCmd.Output()
	cancel4()

	if outpostsErr != nil {
		logger.Warn("Failed to list outposts for health check",
			zap.Error(outpostsErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Could not query outpost instances",
		})
		return results
	}

	outpostsResponse := string(outpostsOutput)

	// Extract outpost UUID (look for embedded outpost)
	// Format: "pk": "uuid-here"
	var outpostID string
	for _, line := range strings.Split(outpostsResponse, "\n") {
		if strings.Contains(line, "\"pk\":") && strings.Contains(outpostsResponse[strings.Index(outpostsResponse, line):], "\"type\":\"embedded\"") {
			// Extract UUID from "pk": "uuid"
			pkStart := strings.Index(line, "\"pk\":") + 6
			pkEnd := strings.Index(line[pkStart:], "\"")
			if pkEnd > 0 {
				outpostID = strings.TrimSpace(line[pkStart : pkStart+pkEnd])
				break
			}
		}
	}

	// Fallback: try to find any UUID pattern in the response
	if outpostID == "" {
		for _, line := range strings.Split(outpostsResponse, "\n") {
			if strings.Contains(line, "\"pk\":") {
				pkStart := strings.Index(line, "\"pk\":\"") + 6
				remaining := line[pkStart:]
				pkEnd := strings.Index(remaining, "\"")
				if pkEnd > 0 {
					potentialID := remaining[:pkEnd]
					// Basic UUID format check (has dashes)
					if strings.Count(potentialID, "-") >= 4 {
						outpostID = potentialID
						break
					}
				}
			}
		}
	}

	if outpostID == "" {
		logger.Warn("Could not extract outpost ID from API response")
		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Could not identify embedded outpost UUID",
			Remediation: []string{
				"Manual check: docker exec hecate-caddy wget -qO- --header='Authorization: Bearer TOKEN' http://hecate-server-1:9000/api/v3/outposts/instances/ | jq '.'",
			},
		})
		return results
	}

	logger.Info("Found outpost ID for health check",
		zap.String("outpost_id", outpostID))

	// Query the health endpoint for this specific outpost
	// P0 FIX: Use Python instead of wget
	ctx5, cancel5 := context.WithTimeout(rc.Ctx, 10*time.Second)
	healthScript := fmt.Sprintf(`import urllib.request; req = urllib.request.Request("http://localhost:9000/api/v3/outposts/instances/%s/health/"); req.add_header("Authorization", "Bearer %s"); print(urllib.request.urlopen(req).read().decode())`, outpostID, token)
	healthCmd := exec.CommandContext(ctx5, "docker", "compose", "exec", "-T", "server",
		"python3", "-c", healthScript)
	healthCmd.Dir = hecatePath
	healthOutput, healthErr := healthCmd.Output()
	cancel5()

	if healthErr != nil {
		logger.Warn("Outpost health endpoint returned error",
			zap.Error(healthErr),
			zap.String("outpost_id", outpostID))

		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Outpost health endpoint query failed",
			Remediation: []string{
				fmt.Sprintf("Manual check: docker exec hecate-caddy wget -qO- --header='Authorization: Bearer TOKEN' http://hecate-server-1:9000/api/v3/outposts/instances/%s/health/", outpostID),
			},
		})
		return results
	}

	healthResponse := string(healthOutput)
	logger.Debug("Outpost health response",
		zap.String("response", healthResponse))

	// Check if health response indicates the outpost is healthy
	// Healthy response should contain: "uid", "last_seen", "version"
	hasUID := strings.Contains(healthResponse, "\"uid\":")
	hasLastSeen := strings.Contains(healthResponse, "\"last_seen\":")
	hasVersion := strings.Contains(healthResponse, "\"version\":")

	if hasUID && hasLastSeen && hasVersion {
		logger.Info("Embedded outpost is healthy")
		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    true,
			Details:   "Embedded outpost is healthy and reporting status correctly",
		})
	} else {
		logger.Warn("Outpost health response missing expected fields",
			zap.String("response", healthResponse[:min(200, len(healthResponse))]))

		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Health Endpoint",
			Category:  "Infrastructure",
			Passed:    false,
			Warning:   true,
			Details:   "Outpost health endpoint returned unexpected response format",
			Remediation: []string{
				"Check server logs: docker compose -f " + hecatePath + "/docker-compose.yml logs server",
				"Verify outpost is running: Admin → Outposts in Authentik UI",
			},
		})
	}

	return results
}

// checkAuthentikProxyConfiguration checks proxy provider, outpost, and application configuration
// This diagnoses issues with forward auth integration (e.g., 404 errors on /outpost.goauthentik.io/auth/caddy)
// CRITICAL: Required for services using Authentik forward auth (BionicGPT, Wazuh, etc.)
func checkAuthentikProxyConfiguration(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	// Step 1: Get authentication token (bootstrap or API token)
	envPath := filepath.Join(hecatePath, ".env")
	envVars, err := shared.ParseEnvFile(envPath)
	if err != nil {
		logger.Error("Failed to parse .env file for proxy config check",
			zap.Error(err),
			zap.String("path", envPath))

		results = append(results, AuthentikCheckResult{
			CheckName: "Proxy Configuration - Token",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("cannot read .env file: %w", err),
			Remediation: []string{
				"Ensure .env file exists at " + envPath,
			},
		})
		return results
	}

	// Prefer AUTHENTIK_API_TOKEN, fallback to AUTHENTIK_BOOTSTRAP_TOKEN
	token := envVars["AUTHENTIK_API_TOKEN"]
	tokenSource := "AUTHENTIK_API_TOKEN"
	if token == "" {
		token = envVars["AUTHENTIK_BOOTSTRAP_TOKEN"]
		tokenSource = "AUTHENTIK_BOOTSTRAP_TOKEN"
	}

	if token == "" {
		logger.Error("No API token available for proxy configuration check")
		results = append(results, AuthentikCheckResult{
			CheckName: "Proxy Configuration - Token",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("no API token found in .env"),
			Remediation: []string{
				"Ensure AUTHENTIK_BOOTSTRAP_TOKEN or AUTHENTIK_API_TOKEN is set in " + envPath,
			},
		})
		return results
	}

	logger.Debug("Using token for proxy configuration check",
		zap.String("source", tokenSource),
		zap.String("token_prefix", token[:min(4, len(token))]+"***"))

	// Step 2: List all proxy providers
	// P0 FIX: Use Python instead of wget
	ctx1, cancel1 := context.WithTimeout(rc.Ctx, 10*time.Second)
	providersScript := fmt.Sprintf(`import urllib.request; req = urllib.request.Request("http://localhost:9000/api/v3/providers/proxy/"); req.add_header("Authorization", "Bearer %s"); print(urllib.request.urlopen(req).read().decode())`, token)
	providersCmd := exec.CommandContext(ctx1, "docker", "compose", "exec", "-T", "server",
		"python3", "-c", providersScript)
	providersCmd.Dir = hecatePath
	providersOutput, providersErr := providersCmd.Output()
	cancel1()

	if providersErr != nil {
		logger.Error("Failed to list proxy providers",
			zap.Error(providersErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Proxy Providers",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("failed to query proxy providers: %w", providersErr),
			Remediation: []string{
				"Ensure Authentik server container is running",
				"Check API token has correct permissions",
				"Manual check: docker exec hecate-server-1 wget -qO- --header='Authorization: Bearer TOKEN' http://localhost:9000/api/v3/providers/proxy/",
			},
		})
		return results
	}

	providersResponse := string(providersOutput)
	logger.Debug("Proxy providers API response",
		zap.String("response_preview", providersResponse[:min(200, len(providersResponse))]))

	// Check if any providers exist
	hasProviders := strings.Contains(providersResponse, "\"results\"") &&
		!strings.Contains(providersResponse, "\"results\":[]") &&
		!strings.Contains(providersResponse, "\"results\": []")

	if !hasProviders {
		logger.Warn("No proxy providers configured")
		results = append(results, AuthentikCheckResult{
			CheckName: "Proxy Providers",
			Category:  "Configuration",
			Passed:    false,
			Warning:   true,
			Details:   "No proxy providers found - this is why forward auth returns 404",
			Remediation: []string{
				"Proxy providers are required for forward auth integration",
				"Create provider via Authentik UI: Admin → Applications → Providers → Create",
				"Or use: eos update hecate --add <service> to auto-configure",
				"Provider mode should be: 'Forward auth (single application)'",
				"See: https://docs.goauthentik.io/docs/providers/proxy/forward_auth",
			},
		})
	} else {
		// Count providers (rough estimate by counting "pk": occurrences)
		providerCount := strings.Count(providersResponse, "\"pk\":")
		logger.Info("Found proxy providers",
			zap.Int("count", providerCount))

		results = append(results, AuthentikCheckResult{
			CheckName: "Proxy Providers",
			Category:  "Configuration",
			Passed:    true,
			Details:   fmt.Sprintf("Found %d proxy provider(s) configured", providerCount),
		})
	}

	// Step 3: List all outposts
	// P0 FIX: Use Python instead of wget
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	outpostsScript := fmt.Sprintf(`import urllib.request; req = urllib.request.Request("http://localhost:9000/api/v3/outposts/instances/"); req.add_header("Authorization", "Bearer %s"); print(urllib.request.urlopen(req).read().decode())`, token)
	outpostsCmd := exec.CommandContext(ctx2, "docker", "compose", "exec", "-T", "server",
		"python3", "-c", outpostsScript)
	outpostsCmd.Dir = hecatePath
	outpostsOutput, outpostsErr := outpostsCmd.Output()
	cancel2()

	if outpostsErr != nil {
		logger.Error("Failed to list outposts",
			zap.Error(outpostsErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Outposts",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("failed to query outposts: %w", outpostsErr),
			Remediation: []string{
				"Ensure Authentik server container is running",
				"Manual check: docker exec hecate-server-1 wget -qO- --header='Authorization: Bearer TOKEN' http://localhost:9000/api/v3/outposts/instances/",
			},
		})
		return results
	}

	outpostsResponse := string(outpostsOutput)
	logger.Debug("Outposts API response",
		zap.String("response_preview", outpostsResponse[:min(200, len(outpostsResponse))]))

	// Check for embedded outpost
	hasEmbeddedOutpost := strings.Contains(outpostsResponse, "\"type\":\"embedded\"") ||
		strings.Contains(outpostsResponse, "\"type\": \"embedded\"")

	if hasEmbeddedOutpost {
		logger.Info("Found embedded outpost")

		// Check if outpost has providers assigned
		// Look for "providers": [] pattern (empty array means no providers assigned)
		hasEmptyProviders := strings.Contains(outpostsResponse, "\"providers\":[]") ||
			strings.Contains(outpostsResponse, "\"providers\": []")

		if hasEmptyProviders {
			logger.Warn("Embedded outpost has no providers assigned")
			results = append(results, AuthentikCheckResult{
				CheckName: "Outpost Configuration",
				Category:  "Configuration",
				Passed:    false,
				Warning:   true,
				Details:   "Embedded outpost found but has no providers assigned - forward auth will not work",
				Remediation: []string{
					"Outpost must be linked to proxy provider(s)",
					"Navigate to: Admin → Outposts → authentik Embedded Outpost → Edit",
					"Add your proxy provider(s) to the outpost",
					"Or use: eos update hecate --add <service> to auto-configure",
				},
			})
		} else {
			logger.Info("Embedded outpost has providers assigned")
			results = append(results, AuthentikCheckResult{
				CheckName: "Outpost Configuration",
				Category:  "Configuration",
				Passed:    true,
				Details:   "Embedded outpost is configured with provider(s)",
			})
		}
	} else {
		logger.Warn("No embedded outpost found")
		results = append(results, AuthentikCheckResult{
			CheckName: "Outpost Configuration",
			Category:  "Configuration",
			Passed:    false,
			Warning:   true,
			Details:   "No embedded outpost found - forward auth requires embedded outpost",
			Remediation: []string{
				"Embedded outpost should be created automatically by Authentik",
				"Check Authentik version (embedded outpost added in 2021.12+)",
				"Navigate to: Admin → Outposts to verify",
			},
		})
	}

	// Step 4: List all applications
	// P0 FIX: Use Python instead of wget
	ctx3, cancel3 := context.WithTimeout(rc.Ctx, 10*time.Second)
	appsScript := fmt.Sprintf(`import urllib.request; req = urllib.request.Request("http://localhost:9000/api/v3/core/applications/"); req.add_header("Authorization", "Bearer %s"); print(urllib.request.urlopen(req).read().decode())`, token)
	appsCmd := exec.CommandContext(ctx3, "docker", "compose", "exec", "-T", "server",
		"python3", "-c", appsScript)
	appsCmd.Dir = hecatePath
	appsOutput, appsErr := appsCmd.Output()
	cancel3()

	if appsErr != nil {
		logger.Error("Failed to list applications",
			zap.Error(appsErr))

		results = append(results, AuthentikCheckResult{
			CheckName: "Applications",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("failed to query applications: %w", appsErr),
			Remediation: []string{
				"Ensure Authentik server container is running",
				"Manual check: docker exec hecate-server-1 wget -qO- --header='Authorization: Bearer TOKEN' http://localhost:9000/api/v3/core/applications/",
			},
		})
		return results
	}

	appsResponse := string(appsOutput)
	logger.Debug("Applications API response",
		zap.String("response_preview", appsResponse[:min(200, len(appsResponse))]))

	// Check if any applications exist
	hasApplications := strings.Contains(appsResponse, "\"results\"") &&
		!strings.Contains(appsResponse, "\"results\":[]") &&
		!strings.Contains(appsResponse, "\"results\": []")

	if !hasApplications {
		logger.Warn("No applications configured")
		results = append(results, AuthentikCheckResult{
			CheckName: "Applications",
			Category:  "Configuration",
			Passed:    false,
			Warning:   true,
			Details:   "No applications found - users won't see any services in their portal",
			Remediation: []string{
				"Applications link users to providers",
				"Create application via Authentik UI: Admin → Applications → Create",
				"Or use: eos update hecate --add <service> to auto-configure",
				"Each application should be linked to a proxy provider",
			},
		})
	} else {
		// Count applications
		appCount := strings.Count(appsResponse, "\"pk\":")
		logger.Info("Found applications",
			zap.Int("count", appCount))

		results = append(results, AuthentikCheckResult{
			CheckName: "Applications",
			Category:  "Configuration",
			Passed:    true,
			Details:   fmt.Sprintf("Found %d application(s) configured", appCount),
		})
	}

	// Step 5: Test forward auth endpoint
	// P0 FIX: Use curl (caddy container has curl, not wget)
	// NOTE: Caddy container is Alpine-based with curl pre-installed
	ctx4, cancel4 := context.WithTimeout(rc.Ctx, 5*time.Second)
	forwardAuthCmd := exec.CommandContext(ctx4, "docker", "compose", "exec", "-T", "caddy",
		"curl", "-i", "-s",
		"http://hecate-server-1:9000/outpost.goauthentik.io/auth/caddy")
	forwardAuthCmd.Dir = hecatePath
	forwardAuthOutput, forwardAuthErr := forwardAuthCmd.CombinedOutput()
	cancel4()

	forwardAuthResponse := string(forwardAuthOutput)
	logger.Debug("Forward auth endpoint test",
		zap.Error(forwardAuthErr),
		zap.String("response_preview", forwardAuthResponse[:min(300, len(forwardAuthResponse))]))

	// 404 indicates no providers configured for embedded outpost
	if strings.Contains(forwardAuthResponse, "404 Not Found") {
		logger.Warn("Forward auth endpoint returns 404")
		results = append(results, AuthentikCheckResult{
			CheckName: "Forward Auth Endpoint",
			Category:  "Configuration",
			Passed:    false,
			Warning:   true,
			Details:   "Forward auth endpoint returns 404 - this is the root cause of authentication failures",
			Remediation: []string{
				"404 means: No proxy provider is assigned to the embedded outpost",
				"Fix: Create proxy provider AND assign it to embedded outpost",
				"Or use: eos update hecate --add <service> to auto-configure everything",
				"See diagnostic output above for provider/outpost/application status",
			},
		})
	} else if strings.Contains(forwardAuthResponse, "302 Found") || strings.Contains(forwardAuthResponse, "302") {
		logger.Info("Forward auth endpoint working correctly (302 redirect to login)")
		results = append(results, AuthentikCheckResult{
			CheckName: "Forward Auth Endpoint",
			Category:  "Configuration",
			Passed:    true,
			Details:   "Forward auth endpoint returns 302 redirect (expected behavior when not authenticated)",
		})
	} else if strings.Contains(forwardAuthResponse, "200 OK") || strings.Contains(forwardAuthResponse, "200") {
		logger.Info("Forward auth endpoint returns 200 (user may already be authenticated)")
		results = append(results, AuthentikCheckResult{
			CheckName: "Forward Auth Endpoint",
			Category:  "Configuration",
			Passed:    true,
			Details:   "Forward auth endpoint returns 200 OK (user already authenticated or no auth required)",
		})
	} else {
		logger.Warn("Forward auth endpoint returned unexpected response",
			zap.String("response", forwardAuthResponse[:min(100, len(forwardAuthResponse))]))
		results = append(results, AuthentikCheckResult{
			CheckName: "Forward Auth Endpoint",
			Category:  "Configuration",
			Passed:    false,
			Warning:   true,
			Details:   "Forward auth endpoint returned unexpected response (check logs for details)",
			Remediation: []string{
				"Check Authentik server logs: docker compose -f /opt/hecate/docker-compose.yml logs server",
				"Check embedded outpost logs in server container",
			},
		})
	}

	return results
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper functions for result counting
func countPassed(results []AuthentikCheckResult) int {
	count := 0
	for _, r := range results {
		if r.Passed && !r.Warning {
			count++
		}
	}
	return count
}

func countFailed(results []AuthentikCheckResult) int {
	count := 0
	for _, r := range results {
		if !r.Passed && !r.Warning {
			count++
		}
	}
	return count
}

func countWarnings(results []AuthentikCheckResult) int {
	count := 0
	for _, r := range results {
		if r.Warning {
			count++
		}
	}
	return count
}

// displayResults displays the diagnostic results
func displayResults(results []AuthentikCheckResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println("\nDiagnostic Results:")
	fmt.Println(strings.Repeat("=", 60))

	currentCategory := ""

	for _, result := range results {
		if result.Category != currentCategory {
			currentCategory = result.Category
			fmt.Printf("\n[%s]\n", strings.ToUpper(currentCategory))
		}

		icon := "✅"
		if !result.Passed {
			if result.Warning {
				icon = " "
			} else {
				icon = "❌"
			}
		}

		fmt.Printf("%s %s\n", icon, result.CheckName)

		if result.Details != "" {
			fmt.Printf("   %s\n", result.Details)
		}

		if result.Error != nil {
			fmt.Printf("   Error: %s\n", result.Error)
		}

		if len(result.Remediation) > 0 {
			fmt.Println("   Remediation:")
			for _, rem := range result.Remediation {
				fmt.Printf("     • %s\n", rem)
			}
		}
	}

	passed := countPassed(results)
	failed := countFailed(results)
	warnings := countWarnings(results)

	fmt.Printf("\n Summary: %d passed, %d failed, %d warnings\n\n", passed, failed, warnings)
}

// displayPreUpgradeSummary displays upgrade summary and recommendations
func displayPreUpgradeSummary(results []AuthentikCheckResult) {
	fmt.Println("=========================================")
	fmt.Println("Pre-Upgrade Summary")
	fmt.Println("=========================================")
	fmt.Println()
	fmt.Println("Key Breaking Changes in Authentik 2025.8:")
	fmt.Println("1. Worker and background tasks revamped")
	fmt.Println("2. Database must use UTF8 encoding")
	fmt.Println("3. AUTHENTIK_WORKER__CONCURRENCY renamed to AUTHENTIK_WORKER__THREADS")
	fmt.Println("4. Some broker settings removed")
	fmt.Println()

	criticalIssues := countFailed(results)
	warnings := countWarnings(results)

	if criticalIssues > 0 {
		fmt.Printf("  Found %d critical issue(s) that must be addressed\n", criticalIssues)
	}
	if warnings > 0 {
		fmt.Printf("  Found %d warning(s) to review\n", warnings)
	}
	if criticalIssues == 0 && warnings == 0 {
		fmt.Println("All checks passed! System is ready for upgrade.")
	}

	fmt.Println()
	fmt.Println("Recommended Actions:")
	fmt.Println("1. Review the checks above for any warnings")
	fmt.Println("2. Ensure you have a recent backup")
	fmt.Println("3. Run the upgrade during a maintenance window")
	fmt.Println("4. Monitor logs during and after upgrade")
	fmt.Println()
	fmt.Println("To proceed with upgrade, run:")
	fmt.Println("  eos update hecate --authentik")
	fmt.Println()
}

// displayAuthentikConfiguration exports and displays complete Authentik configuration
// Integrated into debug command to provide full observability
func displayAuthentikConfiguration(rc *eos_io.RuntimeContext, hecatePath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Read .env file to get API token
	envPath := filepath.Join(hecatePath, ".env")
	logger.Debug("Reading Authentik API token from .env",
		zap.String("env_path", envPath))

	// P0 FIX: Use correct variable names with fallback chain
	// RATIONALE: Authentik has TWO token types with different purposes
	// - AUTHENTIK_API_TOKEN: Scoped operational token (preferred)
	// - AUTHENTIK_BOOTSTRAP_TOKEN: Full-admin bootstrap token (fallback only)
	// - AUTHENTIK_TOKEN: Non-existent variable (was hardcoded incorrectly)
	// EVIDENCE: Your .env has AUTHENTIK_BOOTSTRAP_TOKEN, not AUTHENTIK_TOKEN
	envVars, err := shared.ParseEnvFile(envPath)
	if err != nil {
		return fmt.Errorf("failed to parse .env file: %w\nPath: %s", err, envPath)
	}

	// Try in order of preference (most secure → least secure)
	apiToken := envVars["AUTHENTIK_API_TOKEN"]
	tokenSource := "AUTHENTIK_API_TOKEN"

	if apiToken == "" {
		apiToken = envVars["AUTHENTIK_BOOTSTRAP_TOKEN"]
		tokenSource = "AUTHENTIK_BOOTSTRAP_TOKEN"
		logger.Warn("Using AUTHENTIK_BOOTSTRAP_TOKEN as fallback - create scoped API token instead",
			zap.String("remediation", "Directory → Tokens → Create (Intent: API, Expiry: Never)"))
	}

	if apiToken == "" {
		return fmt.Errorf("no API token found in .env\n"+
			"Expected: AUTHENTIK_API_TOKEN or AUTHENTIK_BOOTSTRAP_TOKEN\n"+
			"Path: %s", envPath)
	}

	logger.Debug("✓ API token found in .env",
		zap.String("source", tokenSource))

	// Authentik URL (localhost:9000 for host access)
	authentikURL := fmt.Sprintf("http://%s:%d", shared.GetInternalHostname(), shared.PortAuthentik)

	// Create Authentik API client
	authentikClient := NewClient(authentikURL, apiToken)

	// Fetch and display brands
	logger.Debug("Fetching brands configuration")
	brands, err := authentikClient.ListBrands(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to list brands: %w", err)
	}

	fmt.Printf("BRANDS (%d)\n", len(brands))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, brand := range brands {
		fmt.Printf("  • %s\n", brand.BrandingTitle)
		fmt.Printf("    Domain: %s\n", brand.Domain)
		fmt.Printf("    Brand UUID: %s\n", brand.PK)
		if brand.FlowEnrollment != "" {
			fmt.Printf("    Enrollment Flow: %s ✓\n", brand.FlowEnrollment)
		} else {
			fmt.Printf("    Enrollment Flow: Not configured\n")
		}
		fmt.Println()
	}

	// Fetch and display flows
	logger.Debug("Fetching flows configuration")
	flows, err := authentikClient.ListFlows(rc.Ctx, "") // All designations
	if err != nil {
		return fmt.Errorf("failed to list flows: %w", err)
	}

	fmt.Printf("\nFLOWS (%d)\n", len(flows))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Group flows by designation
	flowsByDesignation := make(map[string][]FlowResponse)
	for _, flow := range flows {
		flowsByDesignation[flow.Designation] = append(flowsByDesignation[flow.Designation], flow)
	}

	for designation, flows := range flowsByDesignation {
		fmt.Printf("\n  %s FLOWS:\n", strings.ToUpper(designation))
		for _, flow := range flows {
			fmt.Printf("    • %s (%s)\n", flow.Title, flow.Slug)
			fmt.Printf("      Flow PK: %s\n", flow.PK)

			// Show stages for this flow
			bindings, err := authentikClient.GetFlowStages(rc.Ctx, flow.PK)
			if err != nil {
				logger.Debug("Failed to fetch stages for flow",
					zap.String("flow_slug", flow.Slug),
					zap.Error(err))
			} else {
				fmt.Printf("      Stages: %d\n", len(bindings))
			}
		}
	}

	// Fetch and display groups
	logger.Debug("Fetching groups configuration")
	groups, err := authentikClient.ListGroups(rc.Ctx, "") // All groups
	if err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}

	fmt.Printf("\n\nGROUPS (%d)\n", len(groups))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, group := range groups {
		fmt.Printf("  • %s\n", group.Name)
		if group.IsSuperuser {
			fmt.Println("    Role: Superuser")
		} else {
			fmt.Println("    Role: Standard user")
		}
		if attrs, ok := group.Attributes["eos_managed"].(bool); ok && attrs {
			fmt.Println("    Managed by: Eos ✓")
		}
		fmt.Println()
	}

	// Fetch and display applications
	logger.Debug("Fetching applications configuration")
	applications, err := authentikClient.ListApplications(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to list applications: %w", err)
	}

	fmt.Printf("APPLICATIONS (%d)\n", len(applications))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, app := range applications {
		fmt.Printf("  • %s (%s)\n", app.Name, app.Slug)
		if app.Provider != 0 {
			fmt.Printf("    Provider PK: %d", app.Provider)
			if app.ProviderObj.Name != "" {
				fmt.Printf(" (%s)", app.ProviderObj.Name)
			}
			fmt.Println()
		}
		if app.MetaLaunchURL != "" {
			fmt.Printf("    Launch URL: %s\n", app.MetaLaunchURL)
		}
		fmt.Println()
	}

	// API Schema Information (for debugging API compatibility issues)
	fmt.Println("\n5. API Schema Information")
	fmt.Println("   (Brands PATCH endpoint - for debugging field name issues)")
	fmt.Println()

	// Query OpenAPI schema using Authentik client
	schemaURL := fmt.Sprintf("%s/api/v3/schema/", authentikURL)
	schemaReq, schemaErr := http.NewRequestWithContext(rc.Ctx, http.MethodGet, schemaURL, nil)
	if schemaErr != nil {
		logger.Warn("Failed to create schema request", zap.Error(schemaErr))
		fmt.Printf("   ⚠ Could not query API schema: %v\n", schemaErr)
	} else {
		schemaReq.Header.Set("Authorization", "Bearer "+apiToken)
		schemaReq.Header.Set("Accept", "application/json")

		schemaResp, schemaErr := authentikClient.HTTPClient.Do(schemaReq)
		if schemaErr != nil {
			logger.Warn("Failed to fetch API schema", zap.Error(schemaErr))
			fmt.Printf("   ⚠ Could not fetch API schema: %v\n", schemaErr)
		} else {
			defer schemaResp.Body.Close()

			if schemaResp.StatusCode == http.StatusOK {
				var schema map[string]interface{}
				if schemaErr := json.NewDecoder(schemaResp.Body).Decode(&schema); schemaErr != nil {
					logger.Warn("Failed to decode schema", zap.Error(schemaErr))
					fmt.Printf("   ⚠ Could not decode API schema: %v\n", schemaErr)
				} else {
					// Extract brands PATCH endpoint schema
					if paths, ok := schema["paths"].(map[string]interface{}); ok {
						if brandPath, ok := paths["/api/v3/core/brands/{brand_uuid}/"].(map[string]interface{}); ok {
							if patch, ok := brandPath["patch"].(map[string]interface{}); ok {
								if reqBody, ok := patch["requestBody"].(map[string]interface{}); ok {
									if content, ok := reqBody["content"].(map[string]interface{}); ok {
										if appJSON, ok := content["application/json"].(map[string]interface{}); ok {
											if schemaObj, ok := appJSON["schema"].(map[string]interface{}); ok {
												if properties, ok := schemaObj["properties"].(map[string]interface{}); ok {
													fmt.Println("   Available fields for brands PATCH:")

													// Check for flow_enrollment specifically
													if flowEnroll, ok := properties["flow_enrollment"]; ok {
														fmt.Println("   ✓ flow_enrollment field EXISTS")
														if flowMap, ok := flowEnroll.(map[string]interface{}); ok {
															if flowType, ok := flowMap["type"].(string); ok {
																fmt.Printf("     Type: %s\n", flowType)
															}
															if nullable, ok := flowMap["nullable"].(bool); ok {
																fmt.Printf("     Nullable: %t\n", nullable)
															}
														}
													} else {
														fmt.Println("   ✗ flow_enrollment field NOT FOUND")
														fmt.Println("   Available flow-related fields:")
														for key := range properties {
															if strings.Contains(strings.ToLower(key), "flow") {
																fmt.Printf("     - %s\n", key)
															}
														}
													}

													// List all field names
													fmt.Println("\n   All available brand fields:")
													fieldNames := make([]string, 0, len(properties))
													for key := range properties {
														fieldNames = append(fieldNames, key)
													}
													// Sort for readability
													for i := 0; i < len(fieldNames); i++ {
														for j := i + 1; j < len(fieldNames); j++ {
															if fieldNames[i] > fieldNames[j] {
																fieldNames[i], fieldNames[j] = fieldNames[j], fieldNames[i]
															}
														}
													}
													for _, field := range fieldNames {
														fmt.Printf("     - %s\n", field)
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			} else {
				fmt.Printf("   ⚠ API schema query returned status %d\n", schemaResp.StatusCode)
			}
		}
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	logger.Debug("✓ Authentik configuration export complete")
	return nil
}
