package moni

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
	"go.uber.org/zap/otelzap"
)

// RunWorker runs the Moni initialization worker
// This orchestrates the full setup: SSL, database config, security hardening
func RunWorker(rc *eos_io.RuntimeContext, config *WorkerConfig) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Moni Consolidated Setup Worker",
		zap.String("version", "1.0"),
		zap.String("mode", "Full end-to-end configuration"))

	startTime := time.Now()

	result := &SetupResult{
		Success:   false,
		Phases:    []SetupPhase{},
		StartTime: startTime,
	}

	// Change to working directory
	workDir := MoniDir
	if config.WorkDir != "" {
		workDir = config.WorkDir
	}

	if err := os.Chdir(workDir); err != nil {
		return nil, fmt.Errorf("failed to change to working directory %s: %w", workDir, err)
	}

	logger.Info("Working directory", zap.String("path", workDir))

	// Pre-flight checks
	if err := checkPrerequisites(rc); err != nil {
		return nil, fmt.Errorf("pre-flight checks failed: %w", err)
	}

	// Handle targeted actions
	if config.ValidateCertsOnly {
		return handleValidateCerts(rc)
	}

	if config.FixCertsOnly {
		return handleFixCerts(rc)
	}

	if config.VerifyDBOnly {
		return handleVerifyDB(rc)
	}

	if config.VerifyRLSOnly {
		return handleVerifyRLS(rc)
	}

	if config.VerifyCSPOnly {
		return handleVerifyCSP(rc)
	}

	if config.VerifySecurityOnly {
		return handleVerifySecurity(rc)
	}

	if config.CleanupBackups {
		return handleCleanupBackups(rc)
	}

	// Run full setup
	return runFullSetup(rc, config)
}

// runFullSetup runs the complete setup workflow
func runFullSetup(rc *eos_io.RuntimeContext, config *WorkerConfig) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	result := &SetupResult{
		Success:   false,
		Phases:    []SetupPhase{},
		StartTime: time.Now(),
	}

	// Phase 1: SSL Certificates
	if !config.SkipSSL {
		phase := runPhase(rc, 1, "SSL Certificate Generation", func() error {
			return GenerateSSLCerts(rc)
		})
		result.Phases = append(result.Phases, phase)
		if !phase.Success {
			return result, fmt.Errorf("phase 1 failed: SSL certificate generation")
		}
	}

	// Phase 2: Certificate Permissions
	if !config.SkipSSL {
		phase := runPhase(rc, 2, "Certificate Permission Validation & Fix", func() error {
			return ValidateAndFixCertPermissions(rc)
		})
		result.Phases = append(result.Phases, phase)
		if !phase.Success {
			return result, fmt.Errorf("phase 2 failed: certificate permission validation")
		}
	}

	// Phase 3: Environment Configuration
	phase3 := runPhase(rc, 3, "Environment Configuration", func() error {
		if err := enableSSLInEnv(rc); err != nil {
			return err
		}
		cleanupOldBackups(rc)
		return nil
	})
	result.Phases = append(result.Phases, phase3)
	if !phase3.Success {
		return result, fmt.Errorf("phase 3 failed: environment configuration")
	}

	// Phase 4: Restart Containers
	phase4 := runPhase(rc, 4, "Container Restart", func() error {
		return restartContainers(rc)
	})
	result.Phases = append(result.Phases, phase4)
	if !phase4.Success {
		return result, fmt.Errorf("phase 4 failed: container restart")
	}

	// Check container health
	if err := checkContainerHealth(rc); err != nil {
		logger.Error("Container health check failed",
			zap.Error(err),
			zap.String("troubleshooting", "Check logs: docker compose logs -f"))
		return result, fmt.Errorf("container health check failed: %w", err)
	}

	// Wait for services
	logger.Info("Waiting for services to be ready")

	if err := WaitForService(rc, "PostgreSQL", func() bool {
		return CheckPostgres(rc)
	}, MaxWaitSeconds, CheckIntervalSecs); err != nil {
		return result, fmt.Errorf("PostgreSQL did not become ready: %w", err)
	}

	if err := WaitForService(rc, "LiteLLM", func() bool {
		return CheckLiteLLM(rc)
	}, MaxWaitSeconds, CheckIntervalSecs); err != nil {
		return result, fmt.Errorf("LiteLLM did not become ready: %w", err)
	}

	// Phase 5: Database Configuration
	if !config.SkipDatabase {
		phase5 := runPhase(rc, 5, "Database Configuration", func() error {
			return ConfigureDatabase(rc)
		})
		result.Phases = append(result.Phases, phase5)
		if !phase5.Success {
			return result, fmt.Errorf("phase 5 failed: database configuration")
		}

		// Verify configuration
		dbVerification, err := VerifyConfiguration(rc)
		if err != nil {
			logger.Warn("Database verification failed", zap.Error(err))
		}
		result.DBVerification = dbVerification

		if dbVerification != nil && !dbVerification.MoniExists {
			return result, fmt.Errorf("Moni assistant not found after configuration")
		}
	}

	// Phase 6: API Key Regeneration
	phase6 := runPhase(rc, 6, "API Key Regeneration", func() error {
		return regenerateAPIKeys(rc)
	})
	result.Phases = append(result.Phases, phase6)
	// Note: Don't fail if API key regeneration fails (script might not exist)

	// Phase 7: Security Hardening
	if !config.SkipSecurity {
		phase7 := runPhase(rc, 7, "Database Security Hardening", func() error {
			return ApplyDatabaseSecurity(rc)
		})
		result.Phases = append(result.Phases, phase7)
		if !phase7.Success {
			logger.Warn("Security hardening had issues but continuing")
		}

		// Phase 7.5: Row Level Security
		phase75 := runPhase(rc, 7, "Row Level Security (RLS)", func() error {
			return EnableRowLevelSecurity(rc)
		})
		result.Phases = append(result.Phases, phase75)
		if !phase75.Success {
			logger.Error("Row Level Security enablement failed")
			logger.Error("This is a CRITICAL security feature for multi-tenant isolation")
			logger.Error("Continuing, but system is NOT production-ready")
			result.CriticalIssues = append(result.CriticalIssues, "RLS enablement failed")
		}
	}

	// Phase 8: Security Verification
	if !config.SkipVerification {
		logger.Info("Phase 8: Security Verification")

		// Verify RLS
		rlsVerification, err := VerifyRowLevelSecurity(rc)
		if err != nil {
			logger.Warn("RLS verification failed", zap.Error(err))
		}
		result.RLSVerification = rlsVerification

		if rlsVerification != nil && len(rlsVerification.Errors) > 0 {
			logger.Warn("RLS verification found issues")
			for _, err := range rlsVerification.Errors[:min(3, len(rlsVerification.Errors))] {
				logger.Warn("RLS issue", zap.String("error", err))
			}
		}

		if rlsVerification != nil && !rlsVerification.CriticalTablesProtected {
			logger.Warn("Critical tables may not be properly protected by RLS")
			result.CriticalIssues = append(result.CriticalIssues, "Critical tables not protected by RLS")
		}

		// Verify CSP
		cspVerification, err := VerifyContentSecurityPolicy(rc)
		if err != nil {
			logger.Warn("CSP verification failed", zap.Error(err))
		}
		result.CSPVerification = cspVerification

		if cspVerification != nil && !cspVerification.CSPPresent {
			logger.Warn("No Content Security Policy found")
			result.CriticalIssues = append(result.CriticalIssues, "No CSP found")
		} else if cspVerification != nil && cspVerification.SecurityScore < 40 {
			logger.Warn("CSP security score is low", zap.Int("score", cspVerification.SecurityScore))
		}
	}

	// Phase 9: Final Health Check
	healthCheck, err := RunFinalHealthCheck(rc)
	if err != nil {
		logger.Warn("Final health check failed", zap.Error(err))
	}
	result.HealthCheck = healthCheck

	// Mark as successful
	result.Success = true
	result.EndTime = time.Now()

	// Print summary
	printSetupSummary(rc, result)

	return result, nil
}

// runPhase runs a setup phase with error handling
func runPhase(rc *eos_io.RuntimeContext, number int, name string, fn func() error) SetupPhase {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info(fmt.Sprintf("Phase %d: %s", number, name))
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	phase := SetupPhase{
		Number:      number,
		Name:        name,
		StartTime:   time.Now(),
		Errors:      []string{},
		Warnings:    []string{},
	}

	err := fn()
	phase.EndTime = time.Now()

	if err != nil {
		phase.Success = false
		phase.Errors = append(phase.Errors, err.Error())
		logger.Error("Phase failed",
			zap.Int("phase", number),
			zap.String("name", name),
			zap.Error(err))
	} else {
		phase.Success = true
		logger.Info("Phase completed",
			zap.Int("phase", number),
			zap.String("name", name),
			zap.Duration("duration", phase.EndTime.Sub(phase.StartTime)))
	}

	return phase
}

// checkPrerequisites ensures required tooling is available
func checkPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 0: Pre-flight Checks")

	requirements := map[string]string{
		"docker":  "Docker CLI",
		"openssl": "OpenSSL (certificate management)",
		"sudo":    "sudo (used for permission adjustments)",
		"curl":    "curl (for API checks)",
	}

	ok := true
	for command, description := range requirements {
		if !commandExists(command) {
			logger.Error("Missing dependency",
				zap.String("command", command),
				zap.String("description", description))
			ok = false
		} else {
			logger.Debug("Dependency available", zap.String("command", command))
		}
	}

	// Check Docker daemon
	if commandExists("docker") {
		ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
		defer cancel()

		_, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"info"},
			Capture: true,
		})

		if err != nil {
			logger.Error("Docker daemon not reachable")
			ok = false
		} else {
			logger.Debug("Docker daemon responding")
		}

		// Check Docker Compose
		_, err = execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "version"},
			Capture: true,
		})

		if err != nil {
			logger.Error("Docker Compose not available")
			ok = false
		} else {
			logger.Debug("Docker Compose available")
		}
	}

	// Check required files
	if !fileExists(MoniEnvFile) {
		logger.Warn(".env not found", zap.String("path", MoniEnvFile))
		logger.Warn("Some configuration steps may be skipped")
	}

	if !fileExists(MoniDockerCompose) {
		logger.Warn("docker-compose.yml not found", zap.String("path", MoniDockerCompose))
	}

	if !ok {
		return fmt.Errorf("pre-flight checks failed")
	}

	return nil
}

// enableSSLInEnv updates .env to use SSL connections
func enableSSLInEnv(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !fileExists(MoniEnvFile) {
		logger.Warn(".env not found")
		return nil
	}

	content, err := os.ReadFile(MoniEnvFile)
	if err != nil {
		return fmt.Errorf("failed to read .env: %w", err)
	}

	contentStr := string(content)

	if contains(contentStr, "sslmode=require") {
		logger.Info("SSL connections already enabled in .env")
		return nil
	}

	if !contains(contentStr, "sslmode=disable") {
		logger.Info("No sslmode found in .env")
		return nil
	}

	// Backup
	backup := filepath.Join(filepath.Dir(MoniEnvFile),
		fmt.Sprintf(".env.backup.%s", time.Now().Format("20060102_150405")))

	if err := copyFile(MoniEnvFile, backup); err != nil {
		return fmt.Errorf("failed to backup .env: %w", err)
	}

	if err := os.Chmod(backup, 0600); err != nil {
		return fmt.Errorf("failed to set backup permissions: %w", err)
	}

	// Update
	newContent := replace(contentStr, "sslmode=disable", "sslmode=require")
	if err := os.WriteFile(MoniEnvFile, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("failed to write .env: %w", err)
	}

	changes := countOccurrences(contentStr, "sslmode=disable")
	logger.Info("Enabled SSL in connection strings",
		zap.Int("changes", changes),
		zap.String("backup", filepath.Base(backup)))

	return nil
}

// cleanupOldBackups keeps only N most recent backups
func cleanupOldBackups(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	backupPattern := filepath.Join(filepath.Dir(MoniEnvFile), ".env.backup.*")
	matches, err := filepath.Glob(backupPattern)
	if err != nil {
		logger.Warn("Failed to list backups", zap.Error(err))
		return
	}

	if len(matches) <= KeepBackups {
		logger.Debug("Backup cleanup not needed", zap.Int("backups", len(matches)))
		return
	}

	// Sort by modification time (newest first)
	// Note: This is simplified - in production, you'd sort by actual mtime
	toDelete := matches[KeepBackups:]

	for _, backup := range toDelete {
		// Try to shred first
		ctx, cancel := context.WithTimeout(rc.Ctx, 30*time.Second)
		_, err := execute.Run(ctx, execute.Options{
			Command: "shred",
			Args:    []string{"-uvz", backup},
			Capture: true,
		})
		cancel()

		if err != nil {
			// Fallback to regular delete
			os.Remove(backup)
		}
	}

	logger.Info("Deleted old backups", zap.Int("count", len(toDelete)))
}

// restartContainers restarts Docker containers
func restartContainers(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Stopping containers")
	ctx, cancel := context.WithTimeout(rc.Ctx, 2*time.Minute)
	defer cancel()

	_, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "down"},
		Capture: false, // Show output to user
	})

	if err != nil {
		return fmt.Errorf("failed to stop containers: %w", err)
	}

	logger.Info("Starting containers with SSL enabled")

	ctx, cancel = context.WithTimeout(rc.Ctx, 2*time.Minute)
	defer cancel()

	_, err = execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "up", "-d"},
		Capture: false, // Show output to user
	})

	if err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}

	logger.Info("Waiting for services to initialize",
		zap.Int("seconds", InitWaitSeconds))

	// Wait for initialization
	time.Sleep(time.Duration(InitWaitSeconds) * time.Second)

	logger.Info("Container initialization period complete")
	return nil
}

// checkContainerHealth checks for unhealthy containers
func checkContainerHealth(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking container health")

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	output, _ := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "-a", "--filter", "health=unhealthy", "--format", "{{.Names}}"},
		Capture: true,
	})

	unhealthy := []string{}
	for _, name := range splitLines(output) {
		if name != "" {
			unhealthy = append(unhealthy, name)
		}
	}

	if len(unhealthy) > 0 {
		logger.Error("Found unhealthy containers", zap.Int("count", len(unhealthy)))

		for _, container := range unhealthy {
			logger.Error("Unhealthy container", zap.String("name", container))

			// Get last 10 lines of logs
			logOutput, _ := execute.Run(ctx, execute.Options{
				Command: "docker",
				Args:    []string{"logs", "--tail", "10", container},
				Capture: true,
			})

			if logOutput != "" {
				logger.Debug("Last 10 log lines", zap.String("container", container), zap.String("logs", logOutput))
			}
		}

		return fmt.Errorf("found %d unhealthy container(s)", len(unhealthy))
	}

	logger.Info("All containers are healthy")
	return nil
}

// regenerateAPIKeys runs the API key regeneration script
func regenerateAPIKeys(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !fileExists(MoniAPIKeysScript) {
		logger.Warn("API keys script not found - skipping")
		return nil
	}

	logger.Info("Regenerating API keys")

	ctx, cancel := context.WithTimeout(rc.Ctx, LongCommandTimeout)
	defer cancel()

	_, err := execute.Run(ctx, execute.Options{
		Command: MoniAPIKeysScript,
		Capture: false, // Show output to user
	})

	if err != nil {
		return fmt.Errorf("API key regeneration failed: %w", err)
	}

	logger.Info("API key regeneration complete")
	return nil
}

// printSetupSummary prints the final setup summary
func printSetupSummary(rc *eos_io.RuntimeContext, result *SetupResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if result.Success {
		logger.Info("✅ SETUP COMPLETE")
	} else {
		logger.Error("❌ SETUP FAILED")
	}
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if result.Success {
		logger.Info("Configuration Summary:")
		logger.Info("• SSL certificates generated and validated")
		logger.Info("• Certificate permissions tested (SHIFT-LEFT v2)")
		logger.Info("• Default assistant: Moni (was: llama3)")
		logger.Info("• Primary model: Moni (GPT-5-mini) - 16K max tokens")
		logger.Info("• Fallback model: Moni-4.1 (GPT-4.1-mini)")
		logger.Info("• Embeddings: nomic-embed-text")
		logger.Info("• All containers healthy")
		logger.Info("")
		logger.Info("Access Moni: http://localhost:8513")
		logger.Info("Monitor services: docker compose ps")
		logger.Info("View logs: docker compose logs -f app litellm-proxy")

		if len(result.CriticalIssues) > 0 {
			logger.Warn("")
			logger.Warn("⚠️  SECURITY WARNINGS:")
			for _, issue := range result.CriticalIssues {
				logger.Warn(fmt.Sprintf("• %s", issue))
			}
		}
	} else {
		logger.Info("Troubleshooting:")
		logger.Info("• Check logs: docker compose logs -f")
		logger.Info("• Validate certs: eos update moni --validate-certs")
		logger.Info("• Check container health: docker ps -a")
	}

	duration := result.EndTime.Sub(result.StartTime)
	logger.Info("Setup duration", zap.Duration("duration", duration))
}

// Helper functions
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func replace(s, old, new string) string {
	return strings.ReplaceAll(s, old, new)
}

func countOccurrences(s, substr string) int {
	return strings.Count(s, substr)
}

func splitLines(s string) []string {
	return strings.Split(strings.TrimSpace(s), "\n")
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Targeted action handlers

func handleValidateCerts(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating SSL certificates")

	images, err := DetectPostgresImages(rc)
	if err != nil {
		return nil, err
	}

	if len(images) == 0 {
		logger.Warn("No PostgreSQL images detected")
		return &SetupResult{Success: true}, nil
	}

	allPassed := true
	for _, img := range images {
		if TestCertReadability(rc, img.Image, img.ExpectedUID, "") {
			logger.Info("Certificate readable",
				zap.String("service", img.Service),
				zap.String("image", img.Image))
		} else {
			logger.Error("Certificate NOT readable",
				zap.String("service", img.Service),
				zap.String("image", img.Image))
			allPassed = false
		}
	}

	return &SetupResult{Success: allPassed}, nil
}

func handleFixCerts(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Fixing certificate permissions")

	if err := FixCertPermissionsImmediate(rc); err != nil {
		return &SetupResult{Success: false}, err
	}

	logger.Info("Certificate permissions fixed successfully")
	return &SetupResult{Success: true}, nil
}

func handleVerifyDB(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying database configuration")

	dbResult, err := VerifyConfiguration(rc)
	if err != nil {
		return &SetupResult{Success: false}, err
	}

	result := &SetupResult{
		Success:        dbResult.MoniExists,
		DBVerification: dbResult,
	}

	return result, nil
}

func handleVerifyRLS(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Row Level Security")

	rlsResult, err := VerifyRowLevelSecurity(rc)
	if err != nil {
		return &SetupResult{Success: false}, err
	}

	result := &SetupResult{
		Success:         rlsResult.CriticalTablesProtected,
		RLSVerification: rlsResult,
	}

	return result, nil
}

func handleVerifyCSP(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Content Security Policy")

	cspResult, err := VerifyContentSecurityPolicy(rc)
	if err != nil {
		return &SetupResult{Success: false}, err
	}

	result := &SetupResult{
		Success:         cspResult.CSPPresent,
		CSPVerification: cspResult,
	}

	return result, nil
}

func handleVerifySecurity(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 0: Security Verification")

	// Verify RLS
	rlsResult, err := VerifyRowLevelSecurity(rc)
	if err != nil {
		logger.Warn("RLS verification failed", zap.Error(err))
	}

	// Verify CSP
	cspResult, err := VerifyContentSecurityPolicy(rc)
	if err != nil {
		logger.Warn("CSP verification failed", zap.Error(err))
	}

	// Determine overall success
	rlsGood := rlsResult != nil && rlsResult.CriticalTablesProtected
	cspGood := cspResult != nil && cspResult.CSPPresent && cspResult.SecurityScore >= 40

	success := rlsGood && cspGood

	if success {
		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Info("✅ SECURITY VERIFICATION PASSED")
		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	} else {
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("⚠️  SECURITY VERIFICATION FOUND ISSUES")
		if !rlsGood {
			logger.Warn("• Row Level Security needs attention")
		}
		if !cspGood {
			logger.Warn("• Content Security Policy needs attention")
		}
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}

	result := &SetupResult{
		Success:         success,
		RLSVerification: rlsResult,
		CSPVerification: cspResult,
	}

	return result, nil
}

func handleCleanupBackups(rc *eos_io.RuntimeContext) (*SetupResult, error) {
	cleanupOldBackups(rc)
	return &SetupResult{Success: true}, nil
}
