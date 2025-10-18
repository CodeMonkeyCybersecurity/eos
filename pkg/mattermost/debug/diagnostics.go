// Package debug provides comprehensive troubleshooting diagnostics for Mattermost deployments
package debug

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config holds configuration for Mattermost debug operations
type Config struct {
	// DockerComposeDir is the directory containing docker-compose.yml
	DockerComposeDir string
	// MattermostVolumesDir is the base directory for Mattermost volumes
	MattermostVolumesDir string
	// LogTailLines is the number of log lines to display
	LogTailLines int
	// PostgresLogLines is the number of Postgres log lines to display
	PostgresLogLines int
}

// DiagnosticsResult holds the results of all diagnostic checks
type DiagnosticsResult struct {
	DockerComposeConfig string
	MattermostLogs      string
	PostgresLogs        string
	VolumePermissions   map[string]string
	PostgresStatus      string
	NetworkInfo         string
	NetworkDetails      string
	Issues              []string
	Recommendations     []string
}

// RunDiagnostics performs comprehensive Mattermost troubleshooting diagnostics
func RunDiagnostics(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Mattermost troubleshooting diagnostics")

	result := &DiagnosticsResult{
		VolumePermissions: make(map[string]string),
		Issues:            []string{},
		Recommendations:   []string{},
	}

	// Step 1: Check docker-compose configuration
	logger.Info("Step 1: Checking docker-compose configuration")
	if err := checkDockerComposeConfig(rc, config, result); err != nil {
		logger.Warn("Failed to check docker-compose config", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("Docker-compose config check failed: %v", err))
	}

	// Step 2: Check Mattermost container logs
	logger.Info("Step 2: Checking Mattermost container logs")
	if err := checkMattermostLogs(rc, config, result); err != nil {
		logger.Warn("Failed to check Mattermost logs", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("Mattermost logs check failed: %v", err))
	}

	// Step 3: Check Postgres container logs
	logger.Info("Step 3: Checking Postgres container logs")
	if err := checkPostgresLogs(rc, config, result); err != nil {
		logger.Warn("Failed to check Postgres logs", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("Postgres logs check failed: %v", err))
	}

	// Step 4: Check volume permissions
	logger.Info("Step 4: Checking volume permissions")
	if err := checkVolumePermissions(rc, config, result); err != nil {
		logger.Warn("Failed to check volume permissions", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("Volume permissions check failed: %v", err))
	}

	// Step 5: Check Postgres accessibility
	logger.Info("Step 5: Checking Postgres accessibility")
	if err := checkPostgresAccessibility(rc, config, result); err != nil {
		logger.Warn("Failed to check Postgres accessibility", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("Postgres accessibility check failed: %v", err))
	}

	// Step 6: Check network connectivity
	logger.Info("Step 6: Checking network connectivity")
	if err := checkNetworkConnectivity(rc, config, result); err != nil {
		logger.Warn("Failed to check network connectivity", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("Network connectivity check failed: %v", err))
	}

	// Display results
	displayResults(rc, result)

	logger.Info("Mattermost diagnostics complete")
	return nil
}

func checkDockerComposeConfig(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Docker Compose Configuration ===")
	fmt.Println("-------------------------------------------------------")
	
	cmd := exec.CommandContext(rc.Ctx, "cat", fmt.Sprintf("%s/docker-compose.yml", config.DockerComposeDir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}
	
	result.DockerComposeConfig = string(output)
	fmt.Println(result.DockerComposeConfig)
	
	logger.Info("Docker-compose configuration checked successfully")
	return nil
}

func checkMattermostLogs(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Printf("\n=== Mattermost Container Logs (last %d lines) ===\n", config.LogTailLines)
	fmt.Println("---------------------------------------------------------")
	
	cmd := exec.CommandContext(rc.Ctx, "docker", "logs", "--tail", fmt.Sprintf("%d", config.LogTailLines), "docker-mattermost-1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get Mattermost logs: %w", err)
	}
	
	result.MattermostLogs = string(output)
	fmt.Println(result.MattermostLogs)
	
	// Analyze logs for common issues
	analyzeMattermostLogs(result.MattermostLogs, result)
	
	logger.Info("Mattermost logs checked successfully")
	return nil
}

func checkPostgresLogs(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Printf("\n=== Postgres Container Logs (last %d lines) ===\n", config.PostgresLogLines)
	fmt.Println("------------------------------------------------")
	
	cmd := exec.CommandContext(rc.Ctx, "docker", "logs", "--tail", fmt.Sprintf("%d", config.PostgresLogLines), "docker-postgres-1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get Postgres logs: %w", err)
	}
	
	result.PostgresLogs = string(output)
	fmt.Println(result.PostgresLogs)
	
	// Analyze logs for common issues
	analyzePostgresLogs(result.PostgresLogs, result)
	
	logger.Info("Postgres logs checked successfully")
	return nil
}

func checkVolumePermissions(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Volume Permissions ===")
	fmt.Println("--------------------------------")
	
	// Check app volume permissions
	appVolume := fmt.Sprintf("%s/volumes/app", config.MattermostVolumesDir)
	cmd := exec.CommandContext(rc.Ctx, "ls", "-lah", appVolume)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn("Failed to check app volume permissions", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("App volume not accessible: %s", appVolume))
	} else {
		result.VolumePermissions["app"] = string(output)
		fmt.Printf("App volume (%s):\n%s\n", appVolume, string(output))
	}
	
	// Check db volume permissions
	dbVolume := fmt.Sprintf("%s/volumes/db", config.MattermostVolumesDir)
	cmd = exec.CommandContext(rc.Ctx, "ls", "-lah", dbVolume)
	output, err = cmd.CombinedOutput()
	if err != nil {
		logger.Warn("Failed to check db volume permissions", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("DB volume not accessible: %s", dbVolume))
	} else {
		result.VolumePermissions["db"] = string(output)
		fmt.Printf("DB volume (%s):\n%s\n", dbVolume, string(output))
	}
	
	logger.Info("Volume permissions checked successfully")
	return nil
}

func checkPostgresAccessibility(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Postgres Accessibility ===")
	fmt.Println("---------------------------------------")
	
	cmd := exec.CommandContext(rc.Ctx, "docker", "exec", "docker-postgres-1", "pg_isready", "-U", "mmuser", "-d", "mattermost")
	output, err := cmd.CombinedOutput()
	
	result.PostgresStatus = string(output)
	fmt.Println(result.PostgresStatus)
	
	if err != nil {
		result.Issues = append(result.Issues, "Postgres is not accessible")
		result.Recommendations = append(result.Recommendations, "Check if Postgres container is running: docker ps | grep postgres")
		result.Recommendations = append(result.Recommendations, "Check Postgres logs for connection issues")
		return fmt.Errorf("postgres not accessible: %w", err)
	}
	
	logger.Info("Postgres accessibility checked successfully")
	return nil
}

func checkNetworkConnectivity(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Network Connectivity ===")
	fmt.Println("----------------------------------")
	
	// List networks
	cmd := exec.CommandContext(rc.Ctx, "docker", "network", "ls")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}
	
	result.NetworkInfo = string(output)
	fmt.Println("Docker Networks:")
	fmt.Println(result.NetworkInfo)
	
	// Inspect default network
	cmd = exec.CommandContext(rc.Ctx, "docker", "network", "inspect", "docker_default")
	output, err = cmd.CombinedOutput()
	if err != nil {
		logger.Warn("Failed to inspect docker_default network", zap.Error(err))
		result.Issues = append(result.Issues, "Failed to inspect docker_default network")
	} else {
		result.NetworkDetails = string(output)
		fmt.Println("\nDocker Default Network Details:")
		fmt.Println(result.NetworkDetails)
	}
	
	logger.Info("Network connectivity checked successfully")
	return nil
}

func analyzeMattermostLogs(logs string, result *DiagnosticsResult) {
	// Check for common error patterns
	if strings.Contains(logs, "connection refused") {
		result.Issues = append(result.Issues, "Mattermost cannot connect to database")
		result.Recommendations = append(result.Recommendations, "Verify Postgres container is running and accessible")
		result.Recommendations = append(result.Recommendations, "Check database connection string in Mattermost configuration")
	}
	
	if strings.Contains(logs, "permission denied") {
		result.Issues = append(result.Issues, "Permission denied errors in Mattermost")
		result.Recommendations = append(result.Recommendations, "Check volume permissions for /opt/mattermost/volumes/app")
		result.Recommendations = append(result.Recommendations, "Ensure Mattermost user has correct ownership")
	}
	
	if strings.Contains(logs, "panic") || strings.Contains(logs, "fatal") {
		result.Issues = append(result.Issues, "Critical errors detected in Mattermost logs")
		result.Recommendations = append(result.Recommendations, "Review Mattermost logs for panic/fatal errors")
		result.Recommendations = append(result.Recommendations, "Consider restarting Mattermost container after fixing issues")
	}
	
	if strings.Contains(logs, "migration") && strings.Contains(logs, "failed") {
		result.Issues = append(result.Issues, "Database migration failed")
		result.Recommendations = append(result.Recommendations, "Check Postgres logs for migration errors")
		result.Recommendations = append(result.Recommendations, "Verify database schema is compatible with Mattermost version")
	}
}

func analyzePostgresLogs(logs string, result *DiagnosticsResult) {
	// Check for common error patterns
	if strings.Contains(logs, "authentication failed") {
		result.Issues = append(result.Issues, "Postgres authentication failed")
		result.Recommendations = append(result.Recommendations, "Verify database credentials in docker-compose.yml")
		result.Recommendations = append(result.Recommendations, "Check POSTGRES_USER and POSTGRES_PASSWORD environment variables")
	}
	
	if strings.Contains(logs, "could not open file") || strings.Contains(logs, "permission denied") {
		result.Issues = append(result.Issues, "Postgres file permission issues")
		result.Recommendations = append(result.Recommendations, "Check volume permissions for /opt/mattermost/volumes/db")
		result.Recommendations = append(result.Recommendations, "Ensure Postgres user has correct ownership")
	}
	
	if strings.Contains(logs, "database system was shut down") {
		result.Issues = append(result.Issues, "Postgres was not shut down cleanly")
		result.Recommendations = append(result.Recommendations, "Postgres may be recovering from unclean shutdown")
		result.Recommendations = append(result.Recommendations, "Wait for recovery to complete or check for corruption")
	}
	
	if strings.Contains(logs, "out of memory") {
		result.Issues = append(result.Issues, "Postgres out of memory")
		result.Recommendations = append(result.Recommendations, "Increase memory allocation for Postgres container")
		result.Recommendations = append(result.Recommendations, "Review shared_buffers and work_mem settings")
	}
}

func displayResults(rc *eos_io.RuntimeContext, result *DiagnosticsResult) {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Diagnostics Summary ===")
	fmt.Println("===========================")
	
	if len(result.Issues) == 0 {
		fmt.Println("\n✓ No critical issues detected")
		logger.Info("No critical issues detected")
	} else {
		fmt.Printf("\n⚠ Found %d issue(s):\n", len(result.Issues))
		for i, issue := range result.Issues {
			fmt.Printf("  %d. %s\n", i+1, issue)
			logger.Warn("Issue detected", zap.Int("number", i+1), zap.String("issue", issue))
		}
	}
	
	if len(result.Recommendations) > 0 {
		fmt.Printf("\n💡 Recommendations:\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
			logger.Info("Recommendation", zap.Int("number", i+1), zap.String("recommendation", rec))
		}
	}
	
	fmt.Println("\n=== Diagnostics Complete ===")
}
