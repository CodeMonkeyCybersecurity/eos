// Package debug provides comprehensive troubleshooting diagnostics for Mattermost deployments
package debug

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
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
	
	// Read docker-compose.yml file
	composeFile := fmt.Sprintf("%s/docker-compose.yml", config.DockerComposeDir)
	data, err := os.ReadFile(composeFile)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}
	
	result.DockerComposeConfig = string(data)
	fmt.Println(result.DockerComposeConfig)
	
	logger.Info("Docker-compose configuration checked successfully")
	return nil
}

func checkMattermostLogs(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Printf("\n=== Mattermost Container Logs (last %d lines) ===\n", config.LogTailLines)
	fmt.Println("---------------------------------------------------------")
	
	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()
	
	// Get container logs
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", config.LogTailLines),
	}
	
	logs, err := cli.ContainerLogs(rc.Ctx, "docker-mattermost-1", options)
	if err != nil {
		return fmt.Errorf("failed to get Mattermost logs: %w", err)
	}
	defer logs.Close()
	
	// Read logs
	logData, err := io.ReadAll(logs)
	if err != nil {
		return fmt.Errorf("failed to read Mattermost logs: %w", err)
	}
	
	result.MattermostLogs = string(logData)
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
	
	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()
	
	// Get container logs
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", config.PostgresLogLines),
	}
	
	logs, err := cli.ContainerLogs(rc.Ctx, "docker-postgres-1", options)
	if err != nil {
		return fmt.Errorf("failed to get Postgres logs: %w", err)
	}
	defer logs.Close()
	
	// Read logs
	logData, err := io.ReadAll(logs)
	if err != nil {
		return fmt.Errorf("failed to read Postgres logs: %w", err)
	}
	
	result.PostgresLogs = string(logData)
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
	if info, err := os.Stat(appVolume); err != nil {
		logger.Warn("Failed to check app volume permissions", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("App volume not accessible: %s", appVolume))
	} else {
		permInfo := fmt.Sprintf("Permissions: %s, Owner: %s", info.Mode().String(), "(use stat for details)")
		result.VolumePermissions["app"] = permInfo
		fmt.Printf("App volume (%s):\n%s\n", appVolume, permInfo)
		
		// List directory contents
		if entries, err := os.ReadDir(appVolume); err == nil {
			fmt.Printf("Contents (%d items):\n", len(entries))
			for _, entry := range entries {
				info, _ := entry.Info()
				fmt.Printf("  %s %10d %s\n", info.Mode().String(), info.Size(), entry.Name())
			}
		}
	}
	
	// Check db volume permissions
	dbVolume := fmt.Sprintf("%s/volumes/db", config.MattermostVolumesDir)
	if info, err := os.Stat(dbVolume); err != nil {
		logger.Warn("Failed to check db volume permissions", zap.Error(err))
		result.Issues = append(result.Issues, fmt.Sprintf("DB volume not accessible: %s", dbVolume))
	} else {
		permInfo := fmt.Sprintf("Permissions: %s, Owner: %s", info.Mode().String(), "(use stat for details)")
		result.VolumePermissions["db"] = permInfo
		fmt.Printf("DB volume (%s):\n%s\n", dbVolume, permInfo)
		
		// List directory contents
		if entries, err := os.ReadDir(dbVolume); err == nil {
			fmt.Printf("Contents (%d items):\n", len(entries))
			for _, entry := range entries {
				info, _ := entry.Info()
				fmt.Printf("  %s %10d %s\n", info.Mode().String(), info.Size(), entry.Name())
			}
		}
	}
	
	logger.Info("Volume permissions checked successfully")
	return nil
}

func checkPostgresAccessibility(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Postgres Accessibility ===")
	fmt.Println("---------------------------------------")
	
	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()
	
	// Create exec instance to run pg_isready
	execConfig := container.ExecOptions{
		Cmd:          []string{"pg_isready", "-U", "mmuser", "-d", "mattermost"},
		AttachStdout: true,
		AttachStderr: true,
	}
	
	execResp, err := cli.ContainerExecCreate(rc.Ctx, "docker-postgres-1", execConfig)
	if err != nil {
		return fmt.Errorf("failed to create exec instance: %w", err)
	}
	
	// Attach to exec
	attachResp, err := cli.ContainerExecAttach(rc.Ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer attachResp.Close()
	
	// Start exec
	if err := cli.ContainerExecStart(rc.Ctx, execResp.ID, container.ExecStartOptions{}); err != nil {
		return fmt.Errorf("failed to start exec: %w", err)
	}
	
	// Read output
	output, err := io.ReadAll(attachResp.Reader)
	if err != nil {
		return fmt.Errorf("failed to read exec output: %w", err)
	}
	
	result.PostgresStatus = string(output)
	fmt.Println(result.PostgresStatus)
	
	// Check exit code
	inspect, err := cli.ContainerExecInspect(rc.Ctx, execResp.ID)
	if err != nil {
		return fmt.Errorf("failed to inspect exec: %w", err)
	}
	
	if inspect.ExitCode != 0 {
		result.Issues = append(result.Issues, "Postgres is not accessible")
		result.Recommendations = append(result.Recommendations, "Check if Postgres container is running")
		result.Recommendations = append(result.Recommendations, "Check Postgres logs for connection issues")
		return fmt.Errorf("postgres not accessible, exit code: %d", inspect.ExitCode)
	}
	
	logger.Info("Postgres accessibility checked successfully")
	return nil
}

func checkNetworkConnectivity(rc *eos_io.RuntimeContext, config *Config, result *DiagnosticsResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	fmt.Println("\n=== Network Connectivity ===")
	fmt.Println("----------------------------------")
	
	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()
	
	// List networks
	networks, err := cli.NetworkList(rc.Ctx, network.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}
	
	fmt.Println("Docker Networks:")
	fmt.Printf("%-20s %-15s %-10s %s\n", "NETWORK ID", "NAME", "DRIVER", "SCOPE")
	var networkInfo strings.Builder
	for _, network := range networks {
		line := fmt.Sprintf("%-20s %-15s %-10s %s\n", 
			network.ID[:12], network.Name, network.Driver, network.Scope)
		fmt.Print(line)
		networkInfo.WriteString(line)
	}
	result.NetworkInfo = networkInfo.String()
	
	// Inspect docker_default network
	networkResource, err := cli.NetworkInspect(rc.Ctx, "docker_default", network.InspectOptions{})
	if err != nil {
		logger.Warn("Failed to inspect docker_default network", zap.Error(err))
		result.Issues = append(result.Issues, "Failed to inspect docker_default network")
	} else {
		fmt.Println("\nDocker Default Network Details:")
		fmt.Printf("  Name: %s\n", networkResource.Name)
		fmt.Printf("  ID: %s\n", networkResource.ID)
		fmt.Printf("  Driver: %s\n", networkResource.Driver)
		fmt.Printf("  Scope: %s\n", networkResource.Scope)
		fmt.Printf("  Containers: %d\n", len(networkResource.Containers))
		
		if len(networkResource.Containers) > 0 {
			fmt.Println("  Connected Containers:")
			for containerID, endpoint := range networkResource.Containers {
				fmt.Printf("    - %s: %s\n", containerID[:12], endpoint.Name)
			}
		}
		
		result.NetworkDetails = fmt.Sprintf("Name: %s, Driver: %s, Containers: %d",
			networkResource.Name, networkResource.Driver, len(networkResource.Containers))
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
