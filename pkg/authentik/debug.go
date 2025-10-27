// pkg/authentik/debug.go
// *Last Updated: 2025-10-21*

package authentik

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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

	// EVALUATE: Display results and provide summary
	displayResults(allResults)
	displayPreUpgradeSummary(allResults)

	logger.Info("Authentik diagnostics completed",
		zap.Int("total_checks", len(allResults)),
		zap.Int("passed", countPassed(allResults)),
		zap.Int("failed", countFailed(allResults)),
		zap.Int("warnings", countWarnings(allResults)))

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

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "redis", "redis-cli", "ping")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil || !strings.Contains(string(output), "PONG") {
		logger.Error("Redis not responding",
			zap.Error(err),
			zap.String("remediation", "restart Redis container"))

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
func checkBackupStatus(_ *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
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

	results = append(results, AuthentikCheckResult{
		CheckName: "Backup Status",
		Category:  "Pre-Upgrade",
		Passed:    true,
		Details:   fmt.Sprintf("Latest backup: %s (created %s)", latestBackup, latestTime.Format("2006-01-02 15:04:05")),
	})

	return results
}

// checkAuthentikAPI checks API connectivity (bonus check using authentik_client.go)
func checkAuthentikAPI(rc *eos_io.RuntimeContext, hecatePath string) []AuthentikCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []AuthentikCheckResult

	// Check if we can reach the Authentik server container
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "server", "wget", "-q", "-O", "-", "http://localhost:9000/-/health/live/")
	cmd.Dir = hecatePath
	output, err := cmd.Output()
	cancel()

	if err != nil {
		logger.Warn("Authentik API health check failed",
			zap.Error(err),
			zap.String("remediation", "check if Authentik server is running"))

		results = append(results, AuthentikCheckResult{
			CheckName: "API Health",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("API health check failed"),
			Remediation: []string{
				"Ensure Authentik server container is running",
				"Check logs: cd /opt/hecate && docker compose logs server",
			},
		})
		return results
	}

	if strings.Contains(string(output), "ok") || strings.Contains(string(output), "live") {
		logger.Debug("Authentik API health check passed")
		results = append(results, AuthentikCheckResult{
			CheckName: "API Health",
			Category:  "Pre-Upgrade",
			Passed:    true,
			Details:   "Authentik API is responding to health checks",
		})
	} else {
		results = append(results, AuthentikCheckResult{
			CheckName: "API Health",
			Category:  "Pre-Upgrade",
			Passed:    false,
			Warning:   true,
			Details:   "Unexpected API health response",
		})
	}

	return results
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
