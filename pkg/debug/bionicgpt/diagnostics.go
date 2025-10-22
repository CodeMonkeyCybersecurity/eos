// pkg/debug/bionicgpt/diagnostics.go
// BionicGPT-specific diagnostic checks

package bionicgpt

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	DefaultInstallDir  = bionicgpt.DefaultInstallDir
	DefaultComposeFile = bionicgpt.DefaultInstallDir + "/docker-compose.yml"
	DefaultEnvFile     = bionicgpt.DefaultInstallDir + "/.env"
	DefaultPort        = bionicgpt.DefaultPort
)

// AllDiagnostics returns all BionicGPT diagnostic checks
func AllDiagnostics() []*debug.Diagnostic {
	return []*debug.Diagnostic{
		InstallationDiagnostic(),
		ComposeFileDiagnostic(),
		EnvFileDiagnostic(),
		EnvFileContentDiagnostic(),
		SrHDVariableCheckDiagnostic(),
		DockerDaemonDiagnostic(),
		ContainerStatusDiagnostic(),
		PostgresContainerDiagnostic(),
		AppContainerDiagnostic(),
		RAGEngineDiagnostic(),
		EmbeddingsAPIDiagnostic(),
		ChunkingEngineDiagnostic(),
		MigrationsDiagnostic(),
		MigrationsLogsDiagnostic(),
		LiteLLMProxyDiagnostic(),
		VolumesDiagnostic(),
		PostgresHealthDiagnostic(),
		PortBindingDiagnostic(),
		ResourceUsageDiagnostic(),
		LogHealthDiagnostic(),
		OllamaConnectivityDiagnostic(),
		AppContainerMissingDiagnostic(),
		LiteLLMHealthCheckDiagnostic(),
		LiteLLMErrorLogsDiagnostic(),
		DatabaseConnectionTestDiagnostic(),
		NetworkConnectivityDiagnostic(),
		PortListenerDiagnostic(),
		ZombieProcessesDiagnostic(),
		AuthenticationIssueDiagnostic(),
	}
}

// InstallationDiagnostic checks if BionicGPT is installed
func InstallationDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Installation Check",
		Category:    "Installation",
		Description: "Check if BionicGPT is installed",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check if installation directory exists
			info, err := os.Stat(DefaultInstallDir)
			result.Metadata["install_dir"] = DefaultInstallDir

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "BionicGPT not installed"
				result.Output = fmt.Sprintf("Installation directory not found: %s", DefaultInstallDir)
				result.Remediation = "Install BionicGPT: sudo eos create bionicgpt"
			} else if !info.IsDir() {
				result.Status = debug.StatusError
				result.Message = "Installation path exists but is not a directory"
				result.Remediation = fmt.Sprintf("Remove file and reinstall: rm %s && sudo eos create bionicgpt", DefaultInstallDir)
			} else {
				result.Status = debug.StatusOK
				result.Message = "BionicGPT installation directory exists"
				result.Output = fmt.Sprintf("Directory: %s", DefaultInstallDir)
			}

			return result, nil
		},
	}
}

// ComposeFileDiagnostic checks the docker-compose.yml file
func ComposeFileDiagnostic() *debug.Diagnostic {
	return debug.FileCheck("Docker Compose File", DefaultComposeFile, false)
}

// EnvFileDiagnostic checks the .env file
func EnvFileDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Environment File",
		Category:    "Configuration",
		Description: "Check .env file exists and has correct permissions",
		Condition: func(ctx context.Context) bool {
			_, err := os.Stat(DefaultInstallDir)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			info, err := os.Stat(DefaultEnvFile)
			result.Metadata["env_file"] = DefaultEnvFile

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = ".env file not found"
				result.Output = fmt.Sprintf("File not found: %s", DefaultEnvFile)
				result.Remediation = "Reinstall BionicGPT: sudo eos create bionicgpt"
			} else {
				perm := info.Mode().Perm()
				result.Metadata["permissions"] = fmt.Sprintf("%04o", perm)

				// .env should be readable but preferably 0600
				if perm != 0600 && perm != 0640 {
					result.Status = debug.StatusWarning
					result.Message = fmt.Sprintf(".env file has unusual permissions: %04o", perm)
					result.Output = fmt.Sprintf("File: %s\nPermissions: %04o (expected 0600 or 0640)", DefaultEnvFile, perm)
					result.Remediation = fmt.Sprintf("Fix permissions: sudo chmod 0600 %s", DefaultEnvFile)
				} else {
					result.Status = debug.StatusOK
					result.Message = fmt.Sprintf(".env file exists with correct permissions (%04o)", perm)
					result.Output = fmt.Sprintf("File: %s\nPermissions: %04o", DefaultEnvFile, perm)
				}
			}

			return result, nil
		},
	}
}

// DockerDaemonDiagnostic checks if Docker daemon is running
func DockerDaemonDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Docker Daemon",
		Category:    "Docker",
		Description: "Check if Docker daemon is running",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "docker", "info")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Docker daemon not running"
				result.Remediation = "Start Docker: sudo systemctl start docker"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Docker daemon is running"
			}

			return result, nil
		},
	}
}

// ContainerStatusDiagnostic checks the status of all BionicGPT containers
func ContainerStatusDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Container Status",
		Category:    "Docker",
		Description: "Check status of all BionicGPT containers",
		Condition: func(ctx context.Context) bool {
			_, err := os.Stat(DefaultComposeFile)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "docker", "compose", "-f", DefaultComposeFile, "ps", "--format", "json")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				logger.Warn("Failed to get container status", zap.Error(err))
				result.Status = debug.StatusError
				result.Message = "Cannot retrieve container status"
				result.Remediation = "Check if containers are running: docker compose -f /opt/bionicgpt/docker-compose.yml ps"
			} else {
				// Count running containers
				lines := strings.Split(string(output), "\n")
				runningCount := 0
				for _, line := range lines {
					if strings.Contains(line, "running") || strings.Contains(line, "Up") {
						runningCount++
					}
				}

				result.Metadata["running_containers"] = runningCount
				expectedContainers := 6 // app, postgres, embeddings, chunking, rag-engine, litellm

				if runningCount == 0 {
					result.Status = debug.StatusError
					result.Message = "No containers running"
					result.Remediation = "Start containers: cd /opt/bionicgpt && sudo docker compose up -d"
				} else if runningCount < expectedContainers {
					result.Status = debug.StatusWarning
					result.Message = fmt.Sprintf("Only %d of %d containers running", runningCount, expectedContainers)
					result.Remediation = "Check container logs: docker compose -f /opt/bionicgpt/docker-compose.yml logs"
				} else {
					result.Status = debug.StatusOK
					result.Message = fmt.Sprintf("All %d containers running", runningCount)
				}
			}

			return result, nil
		},
	}
}

// PostgresContainerDiagnostic checks the PostgreSQL container
func PostgresContainerDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("PostgreSQL Database", bionicgpt.ContainerPostgres, "Database container for BionicGPT data")
}

// AppContainerDiagnostic checks the main app container
func AppContainerDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("BionicGPT Application", bionicgpt.ContainerApp, "Main web application container")
}

// RAGEngineDiagnostic checks the RAG engine container
func RAGEngineDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("RAG Engine", bionicgpt.ContainerRAGEngine, "Retrieval-Augmented Generation engine")
}

// EmbeddingsAPIDiagnostic checks the embeddings API container
func EmbeddingsAPIDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("Embeddings API", bionicgpt.ContainerEmbeddings, "Document embeddings generation API")
}

// ChunkingEngineDiagnostic checks the chunking engine container
func ChunkingEngineDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("Chunking Engine", bionicgpt.ContainerChunking, "Document parsing and chunking service")
}

// MigrationsDiagnostic checks the migrations container
func MigrationsDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("Database Migrations", bionicgpt.ContainerMigrations, "Database schema migrations")
}

// LiteLLMProxyDiagnostic checks the LiteLLM proxy container
func LiteLLMProxyDiagnostic() *debug.Diagnostic {
	return containerDiagnostic("LiteLLM Proxy", bionicgpt.ContainerLiteLLM, "LiteLLM proxy for LLM API calls")
}

// containerDiagnostic is a helper to create individual container diagnostics
func containerDiagnostic(name, containerName, description string) *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        name,
		Category:    "Containers",
		Description: description,
		Condition: func(ctx context.Context) bool {
			_, err := os.Stat(DefaultComposeFile)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}
			result.Metadata["container_name"] = containerName

			cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Status}}", containerName)
			output, err := cmd.CombinedOutput()
			status := strings.TrimSpace(string(output))
			result.Output = status

			if err != nil {
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("Container %s not found", containerName)
				result.Remediation = "Start containers: cd /opt/bionicgpt && sudo docker compose up -d"
			} else if status != "running" {
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("Container %s is %s", containerName, status)
				result.Remediation = fmt.Sprintf("Check logs: docker logs %s", containerName)
			} else {
				result.Status = debug.StatusOK
				result.Message = fmt.Sprintf("Container %s is running", containerName)
			}

			return result, nil
		},
	}
}

// VolumesDiagnostic checks Docker volumes
func VolumesDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Docker Volumes",
		Category:    "Docker",
		Description: "Check BionicGPT data volumes exist",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			volumes := []string{
				bionicgpt.VolumePostgresData,
				bionicgpt.VolumeDocuments,
			}

			existingVolumes := []string{}
			missingVolumes := []string{}

			for _, vol := range volumes {
				cmd := exec.CommandContext(ctx, "docker", "volume", "inspect", vol)
				err := cmd.Run()

				if err == nil {
					existingVolumes = append(existingVolumes, vol)
				} else {
					missingVolumes = append(missingVolumes, vol)
				}
			}

			result.Metadata["existing_volumes"] = existingVolumes
			result.Metadata["missing_volumes"] = missingVolumes

			if len(missingVolumes) > 0 {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("Missing %d volumes", len(missingVolumes))
				result.Output = fmt.Sprintf("Missing: %v", missingVolumes)
				result.Remediation = "Volumes will be created automatically when containers start"
			} else {
				result.Status = debug.StatusOK
				result.Message = "All volumes exist"
				result.Output = fmt.Sprintf("Volumes: %v", existingVolumes)
			}

			return result, nil
		},
	}
}

// PostgresHealthDiagnostic checks PostgreSQL health
func PostgresHealthDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "PostgreSQL Health",
		Category:    "Database",
		Description: "Check PostgreSQL is accepting connections",
		Condition: func(ctx context.Context) bool {
			cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Status}}", bionicgpt.ContainerPostgres)
			output, err := cmd.Output()
			return err == nil && strings.TrimSpace(string(output)) == "running"
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerPostgres, "pg_isready", "-U", "postgres")
			cmd.Stdout = nil
			cmd.Stderr = nil
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "PostgreSQL not ready"
				result.Remediation = "Check PostgreSQL logs: docker logs bionicgpt-postgres"
			} else {
				result.Status = debug.StatusOK
				result.Message = "PostgreSQL is accepting connections"
			}

			return result, nil
		},
	}
}

// PortBindingDiagnostic checks if BionicGPT port is bound
func PortBindingDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Port Binding",
		Category:    "Network",
		Description: fmt.Sprintf("Check if port %d is bound", DefaultPort),
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}
			result.Metadata["port"] = DefaultPort

			cmd := exec.CommandContext(ctx, "ss", "-tlnp")
			output, err := cmd.CombinedOutput()

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Cannot check port bindings"
				result.Output = string(output)
			} else {
				portStr := fmt.Sprintf(":%d", DefaultPort)
				if strings.Contains(string(output), portStr) {
					result.Status = debug.StatusOK
					result.Message = fmt.Sprintf("Port %d is bound", DefaultPort)
				} else {
					result.Status = debug.StatusWarning
					result.Message = fmt.Sprintf("Port %d not bound", DefaultPort)
					result.Remediation = "Check if BionicGPT app container is running"
				}
			}

			return result, nil
		},
	}
}

// ResourceUsageDiagnostic checks container resource usage
func ResourceUsageDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Resource Usage",
		Category:    "Performance",
		Description: "Check container CPU and memory usage",
		Condition: func(ctx context.Context) bool {
			cmd := exec.CommandContext(ctx, "docker", "ps", "-q")
			output, err := cmd.Output()
			return err == nil && len(output) > 0
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Cannot retrieve resource stats"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Resource usage retrieved"
			}

			return result, nil
		},
	}
}

// LogHealthDiagnostic checks container logs for errors
func LogHealthDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Log Health Check",
		Category:    "Monitoring",
		Description: "Check container logs for errors",
		Condition: func(ctx context.Context) bool {
			_, err := os.Stat(DefaultComposeFile)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			containers := []string{bionicgpt.ContainerApp, bionicgpt.ContainerPostgres, bionicgpt.ContainerRAGEngine}
			errorCount := 0
			errorSummary := []string{}

			for _, container := range containers {
				cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", "50", container)
				output, err := cmd.CombinedOutput()

				if err == nil {
					lines := strings.Split(string(output), "\n")
					for _, line := range lines {
						if strings.Contains(strings.ToUpper(line), "ERROR") ||
							strings.Contains(strings.ToUpper(line), "FATAL") ||
							strings.Contains(line, "panic:") {
							errorCount++
							errorSummary = append(errorSummary, fmt.Sprintf("%s: %s", container, line))
						}
					}
				}
			}

			result.Metadata["error_count"] = errorCount

			if errorCount > 0 {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("Found %d errors in logs", errorCount)
				result.Output = strings.Join(errorSummary, "\n")
				result.Remediation = "Review container logs for details: docker compose -f /opt/bionicgpt/docker-compose.yml logs"
			} else {
				result.Status = debug.StatusOK
				result.Message = "No recent errors in logs"
			}

			return result, nil
		},
	}
}

// OllamaConnectivityDiagnostic checks if Ollama is reachable (for local embeddings)
func OllamaConnectivityDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Ollama Connectivity",
		Category:    "Integration",
		Description: "Check if Ollama is reachable for local embeddings",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check if ollama is running
			cmd := exec.CommandContext(ctx, "systemctl", "is-active", "ollama")
			output, err := cmd.Output()
			status := strings.TrimSpace(string(output))

			result.Metadata["ollama_service"] = status

			if err != nil || status != "active" {
				result.Status = debug.StatusWarning
				result.Message = "Ollama service not running (required for local embeddings)"
				result.Output = fmt.Sprintf("Service status: %s", status)
				result.Remediation = "Start Ollama: sudo systemctl start ollama (or install: sudo eos create ollama)"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Ollama service is running"
				result.Output = fmt.Sprintf("Service status: %s", status)
			}

			return result, nil
		},
	}
}

// EnvFileContentDiagnostic checks the content of .env files
func EnvFileContentDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Environment Files Content",
		Category:    "Configuration",
		Description: "Display contents of .env configuration files",
		Condition: func(ctx context.Context) bool {
			_, err := os.Stat(DefaultInstallDir)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			envFiles := []string{
				DefaultInstallDir + "/.env",
				DefaultInstallDir + "/.env.litellm",
				DefaultInstallDir + "/.env.azure_openai",
			}

			var output strings.Builder
			foundFiles := 0

			for _, envFile := range envFiles {
				if data, err := os.ReadFile(envFile); err == nil {
					foundFiles++
					output.WriteString(fmt.Sprintf("\n=== %s ===\n", envFile))
					output.WriteString(string(data))
					output.WriteString("\n")
				}
			}

			if foundFiles == 0 {
				result.Status = debug.StatusWarning
				result.Message = "No environment files found"
				result.Output = "Checked: " + strings.Join(envFiles, ", ")
				result.Remediation = "Environment files missing - reinstall: sudo eos create bionicgpt --force"
			} else {
				result.Status = debug.StatusOK
				result.Message = fmt.Sprintf("Found %d environment file(s)", foundFiles)
				result.Output = output.String()
			}

			return result, nil
		},
	}
}

// SrHDVariableCheckDiagnostic checks for the mysterious SrHD variable
// NOTE: SrHD is NOT a valid BionicGPT variable - it's likely file corruption or encoding issue
// If found, it should be removed from configuration files
func SrHDVariableCheckDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "SrHD Variable Check",
		Category:    "Configuration",
		Description: "Search for undefined SrHD variable in compose and env files",
		Condition: func(ctx context.Context) bool {
			_, err := os.Stat(DefaultInstallDir)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			searchFiles := []string{
				DefaultInstallDir + "/docker-compose.yml",
				DefaultInstallDir + "/.env",
				DefaultInstallDir + "/.env.litellm",
				DefaultInstallDir + "/.env.azure_openai",
			}

			var output strings.Builder
			foundSrHD := false

			for _, file := range searchFiles {
				data, err := os.ReadFile(file)
				if err != nil {
					continue // File doesn't exist, skip
				}

				lines := strings.Split(string(data), "\n")
				for lineNum, line := range lines {
					if strings.Contains(line, "SrHD") {
						foundSrHD = true
						output.WriteString(fmt.Sprintf("%s:%d: %s\n", file, lineNum+1, line))
					}
				}
			}

			if foundSrHD {
				result.Status = debug.StatusError
				result.Message = "Found undefined SrHD variable (likely corruption)"
				result.Output = output.String()
				result.Remediation = "SrHD is NOT a valid BionicGPT variable. This is likely file corruption.\nFix: sudo eos create bionicgpt --force"
			} else {
				result.Status = debug.StatusOK
				result.Message = "No SrHD variable found"
				result.Output = "Checked: " + strings.Join(searchFiles, ", ")
			}

			return result, nil
		},
	}
}

// MigrationsLogsDiagnostic gets the logs from the migrations container
func MigrationsLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Migrations Container Logs",
		Category:    "Containers",
		Description: "Retrieve last 50 lines of migrations container logs",
		Condition: func(ctx context.Context) bool {
			// Check if migrations container exists
			cmd := exec.Command("docker", "inspect", bionicgpt.ContainerMigrations)
			return cmd.Run() == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}
			result.Metadata["container_name"] = bionicgpt.ContainerMigrations

			logger := otelzap.Ctx(ctx)
			logger.Debug("Fetching migrations container logs",
				zap.String("container", bionicgpt.ContainerMigrations))

			cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", "50", bionicgpt.ContainerMigrations)
			output, err := cmd.CombinedOutput()

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Could not retrieve migrations logs"
				result.Output = string(output)
				result.Remediation = fmt.Sprintf("Check if container exists: docker ps -a | grep %s", bionicgpt.ContainerMigrations)
			} else {
				outputStr := string(output)
				result.Metadata["log_lines"] = strings.Count(outputStr, "\n")

				// Check for common error patterns
				if strings.Contains(outputStr, "exit 2") || strings.Contains(outputStr, "error") || strings.Contains(outputStr, "Error") || strings.Contains(outputStr, "FATAL") {
					result.Status = debug.StatusError
					result.Message = "Migrations container logs contain errors"
					result.Remediation = "Check database connectivity and migration scripts. View full logs: docker logs " + bionicgpt.ContainerMigrations
				} else if outputStr == "" {
					result.Status = debug.StatusWarning
					result.Message = "Migrations container has no logs"
				} else {
					result.Status = debug.StatusOK
					result.Message = "Migrations container logs retrieved"
				}

				result.Output = outputStr
			}

			return result, nil
		},
	}
}

// AppContainerMissingDiagnostic checks if bionicgpt-app container is running
// This diagnostic was added after discovering app container failures due to litellm dependency
func AppContainerMissingDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "App Container Running Check",
		Category:    "Containers",
		Description: "Check if bionicgpt-app container is running (often fails due to litellm dependency)",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check if app container is running
			cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=bionicgpt-app", "--format", "{{.Names}}")
			output, err := cmd.CombinedOutput()
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to check for app container"
				result.Error = err
				result.Remediation = "Ensure Docker is running and accessible"
				logger.Error("Failed to check app container", zap.Error(err))
				return result, nil
			}

			outputStr := strings.TrimSpace(string(output))
			if strings.Contains(outputStr, "bionicgpt-app") {
				result.Status = debug.StatusOK
				result.Message = "✓ bionicgpt-app is running"
				result.Output = "Container found: " + outputStr
			} else {
				result.Status = debug.StatusError
				result.Message = "✗ bionicgpt-app is NOT running"
				result.Output = "This container failed to start, likely due to litellm-proxy dependency or database authentication issues"
				result.Remediation = "Check litellm-proxy health and database credentials. Try: docker compose logs app"
			}

			return result, nil
		},
	}
}

// LiteLLMHealthCheckDiagnostic checks the health status of litellm-proxy container
func LiteLLMHealthCheckDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "LiteLLM Proxy Health",
		Category:    "Containers",
		Description: "Check health status and recent logs of litellm-proxy container",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var outputParts []string

			// Check health status
			healthCmd := exec.CommandContext(ctx, "docker", "inspect", bionicgpt.ContainerLiteLLM,
				"--format", "{{.State.Health.Status}}")
			healthOutput, healthErr := healthCmd.CombinedOutput()

			if healthErr != nil {
				result.Status = debug.StatusError
				result.Message = "LiteLLM container not found or not accessible"
				result.Error = healthErr
				logger.Warn("LiteLLM container check failed", zap.Error(healthErr))
			} else {
				healthStatus := strings.TrimSpace(string(healthOutput))
				outputParts = append(outputParts, fmt.Sprintf("Health Status: %s", healthStatus))

				if healthStatus == "healthy" {
					result.Status = debug.StatusOK
					result.Message = "LiteLLM proxy is healthy"
				} else if healthStatus == "starting" {
					result.Status = debug.StatusWarning
					result.Message = "LiteLLM proxy is still starting"
				} else {
					result.Status = debug.StatusError
					result.Message = fmt.Sprintf("LiteLLM proxy is unhealthy: %s", healthStatus)
					result.Remediation = "Check litellm_config.yaml and Azure OpenAI credentials. View logs: docker logs bionicgpt-litellm"
				}
			}

			// Get recent logs (last 30 lines)
			logsCmd := exec.CommandContext(ctx, "docker", "logs", bionicgpt.ContainerLiteLLM, "--tail", "30")
			logsOutput, logsErr := logsCmd.CombinedOutput()
			if logsErr == nil {
				outputParts = append(outputParts, "\nRecent Logs (last 30 lines):")
				outputParts = append(outputParts, string(logsOutput))
			}

			result.Output = strings.Join(outputParts, "\n")
			return result, nil
		},
	}
}

// DatabaseConnectionTestDiagnostic tests if bionic_application user can connect to database
func DatabaseConnectionTestDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Database Connection Test",
		Category:    "Database",
		Description: "Test if bionic_application user can authenticate to PostgreSQL database",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Test connection as bionic_application user
			cmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerPostgres,
				"psql", "-U", "bionic_application", "-d", "bionic-gpt",
				"-c", "SELECT current_user, current_database();")
			output, err := cmd.CombinedOutput()

			outputStr := string(output)
			result.Output = outputStr

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "✗ Database authentication failed for bionic_application user"
				result.Error = err
				result.Remediation = "User may not exist or password is incorrect. Check .env file for APP_DATABASE_URL. May need to run: docker exec bionicgpt-postgres psql -U postgres -d bionic-gpt -c \"CREATE USER bionic_application WITH PASSWORD 'your_password';\""
				logger.Error("Database connection test failed", zap.Error(err), zap.String("output", outputStr))
			} else {
				result.Status = debug.StatusOK
				result.Message = "✓ Database authentication successful"
				logger.Info("Database connection test passed")
			}

			return result, nil
		},
	}
}

// NetworkConnectivityDiagnostic tests network connectivity between containers
func NetworkConnectivityDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Container Network Connectivity",
		Category:    "Network",
		Description: "Test if containers can reach each other (e.g., app -> litellm-proxy)",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var outputParts []string

			// Test if postgres can reach litellm-proxy on port 4000
			// Using postgres container since it's always running
			cmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerPostgres,
				"sh", "-c", "command -v nc >/dev/null 2>&1 && nc -zv litellm-proxy 4000 || echo 'nc not available'")
			output, err := cmd.CombinedOutput()

			outputStr := strings.TrimSpace(string(output))
			outputParts = append(outputParts, fmt.Sprintf("litellm-proxy:4000 connectivity test:\n%s", outputStr))

			if err != nil {
				if strings.Contains(outputStr, "nc not available") {
					result.Status = debug.StatusWarning
					result.Message = "Network testing tools (nc) not available in container"
					logger.Warn("nc command not available for network testing")
				} else {
					result.Status = debug.StatusError
					result.Message = "Network connectivity test failed"
					result.Error = err
					result.Remediation = "Check Docker network configuration and ensure all containers are on the same network"
					logger.Error("Network connectivity test failed", zap.Error(err))
				}
			} else if strings.Contains(outputStr, "nc not available") {
				result.Status = debug.StatusWarning
				result.Message = "Network testing tools not available (nc missing)"
			} else if strings.Contains(outputStr, "succeeded") || strings.Contains(outputStr, "open") {
				result.Status = debug.StatusOK
				result.Message = "✓ Network connectivity test successful"
			} else {
				result.Status = debug.StatusError
				result.Message = "✗ Cannot reach litellm-proxy"
				result.Remediation = "Check if litellm-proxy container is running and healthy"
			}

			result.Output = strings.Join(outputParts, "\n")
			return result, nil
		},
	}
}

// PortListenerDiagnostic checks what's listening on the BionicGPT port (8513)
func PortListenerDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Port 8513 Listener Check",
		Category:    "Network",
		Description: "Check what process is listening on BionicGPT port 8513",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check what's listening on port 8513
			// Try netstat first, fall back to lsof
			cmd := exec.CommandContext(ctx, "sh", "-c", "netstat -tlnp 2>/dev/null | grep 8513 || lsof -i :8513 2>/dev/null || ss -tlnp | grep 8513")
			output, err := cmd.CombinedOutput()

			outputStr := strings.TrimSpace(string(output))

			if err != nil || outputStr == "" {
				result.Status = debug.StatusError
				result.Message = "✗ Nothing listening on port 8513"
				result.Output = "BionicGPT should be accessible on port 8513 but no listener found"
				result.Remediation = "Check if bionicgpt-app container is running: docker ps | grep bionicgpt-app"
				logger.Warn("No listener found on port 8513")
			} else {
				result.Status = debug.StatusOK
				result.Message = "✓ Service listening on port 8513"
				result.Output = outputStr
				logger.Info("Port 8513 listener found", zap.String("output", outputStr))
			}

			return result, nil
		},
	}
}

// ZombieProcessesDiagnostic checks for zombie (defunct) processes
func ZombieProcessesDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Zombie Processes Check",
		Category:    "System",
		Description: "Check for zombie (defunct) processes that might indicate issues",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Look for defunct processes
			cmd := exec.CommandContext(ctx, "sh", "-c", "ps aux | grep -i defunct | grep -v grep || echo 'none'")
			output, err := cmd.CombinedOutput()

			outputStr := strings.TrimSpace(string(output))

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Unable to check for zombie processes"
				result.Error = err
				logger.Warn("Failed to check for zombie processes", zap.Error(err))
			} else if outputStr == "none" || outputStr == "" {
				result.Status = debug.StatusOK
				result.Message = "✓ No zombie processes found"
				result.Output = "System is healthy - no defunct processes"
				logger.Info("No zombie processes found")
			} else {
				result.Status = debug.StatusWarning
				result.Message = "⚠ Zombie processes detected"
				result.Output = outputStr
				result.Remediation = "Zombie processes usually indicate a parent process not reaping its children. May need to restart affected services."
				result.Metadata["zombie_count"] = strings.Count(outputStr, "\n")
				logger.Warn("Zombie processes detected", zap.String("processes", outputStr))
			}

			return result, nil
		},
	}
}

// LiteLLMErrorLogsDiagnostic filters litellm logs for errors, failures, and exceptions
// This diagnostic uses Docker SDK to retrieve and filter logs efficiently
func LiteLLMErrorLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "LiteLLM Error Logs",
		Category:    "Containers",
		Description: "Filter litellm-proxy logs for errors, failures, and exceptions (last 20 matching lines)",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Create RuntimeContext for Docker manager
			rc := &eos_io.RuntimeContext{Ctx: ctx}

			// Initialize Docker manager using SDK
			mgr, err := container.NewManager(rc)
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to initialize Docker SDK client"
				result.Error = err
				result.Remediation = "Ensure Docker daemon is running and accessible"
				logger.Error("Failed to create Docker manager", zap.Error(err))
				return result, nil
			}
			defer mgr.Close()

			// Get logs from litellm container via SDK
			logReader, err := mgr.Logs(ctx, bionicgpt.ContainerLiteLLM, container.LogOptions{
				ShowStdout: true,
				ShowStderr: true,
				Tail:       "200", // Get more logs to filter through
				Timestamps: false,
			})
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to retrieve litellm logs"
				result.Error = err
				result.Remediation = "Check if litellm-proxy container exists and is running: docker ps | grep litellm"
				logger.Error("Failed to get litellm logs", zap.Error(err))
				return result, nil
			}
			defer logReader.Close()

			// Filter logs for error patterns
			errorLines := filterLogsForErrors(logReader, 20)

			if len(errorLines) == 0 {
				result.Status = debug.StatusOK
				result.Message = "✓ No errors, failures, or exceptions found in recent litellm logs"
				result.Output = "LiteLLM proxy logs are clean (checked last 200 lines)"
			} else {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("⚠ Found %d error/failure/exception lines in litellm logs", len(errorLines))
				result.Output = strings.Join(errorLines, "\n")
				result.Metadata["error_count"] = len(errorLines)
				result.Remediation = "Review errors above. Common issues: Azure OpenAI credentials, network connectivity, litellm_config.yaml syntax"
				logger.Warn("Found errors in litellm logs", zap.Int("count", len(errorLines)))
			}

			return result, nil
		},
	}
}

// Helper Functions for Docker SDK operations

// filterLogsForErrors reads container logs and filters for error patterns
// Returns the last N matching lines containing "error", "fail", or "exception" (case-insensitive)
func filterLogsForErrors(logReader io.ReadCloser, maxLines int) []string {
	var errorLines []string
	scanner := bufio.NewScanner(logReader)

	// Docker SDK returns logs with 8-byte header (stream type + size)
	// We need to strip this header for each line
	for scanner.Scan() {
		line := scanner.Text()

		// Strip Docker log header (8 bytes at start of each line)
		// Format: 1 byte stream type (stdout=1, stderr=2) + 3 bytes padding + 4 bytes size
		if len(line) > 8 {
			line = line[8:]
		}

		// Filter for error patterns (case-insensitive)
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "error") ||
			strings.Contains(lowerLine, "fail") ||
			strings.Contains(lowerLine, "exception") {
			errorLines = append(errorLines, line)
		}
	}

	// Return last N lines if we have more than maxLines
	if len(errorLines) > maxLines {
		return errorLines[len(errorLines)-maxLines:]
	}
	return errorLines
}

// getContainerLogs retrieves logs from a container using Docker SDK
// This helper function encapsulates the common pattern of getting logs with error handling
func getContainerLogs(ctx context.Context, containerName string, tail string) (string, error) {
	logger := otelzap.Ctx(ctx)

	// Create RuntimeContext for Docker manager
	rc := &eos_io.RuntimeContext{Ctx: ctx}

	// Initialize Docker manager
	mgr, err := container.NewManager(rc)
	if err != nil {
		logger.Error("Failed to create Docker manager", zap.Error(err))
		return "", fmt.Errorf("failed to initialize Docker SDK: %w", err)
	}
	defer mgr.Close()

	// Get logs via SDK
	logReader, err := mgr.Logs(ctx, containerName, container.LogOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Timestamps: false,
	})
	if err != nil {
		logger.Error("Failed to get container logs",
			zap.String("container", containerName),
			zap.Error(err))
		return "", fmt.Errorf("failed to get logs for %s: %w", containerName, err)
	}
	defer logReader.Close()

	// Read all log content
	logBytes, err := io.ReadAll(logReader)
	if err != nil {
		logger.Error("Failed to read log content",
			zap.String("container", containerName),
			zap.Error(err))
		return "", fmt.Errorf("failed to read logs: %w", err)
	}

	// Strip Docker log headers from output
	return stripDockerLogHeaders(string(logBytes)), nil
}

// stripDockerLogHeaders removes the 8-byte Docker log headers from log output
// Docker SDK includes headers: 1 byte stream type + 3 bytes padding + 4 bytes size
func stripDockerLogHeaders(logs string) string {
	lines := strings.Split(logs, "\n")
	var cleaned []string

	for _, line := range lines {
		if len(line) > 8 {
			// Strip the 8-byte header
			cleaned = append(cleaned, line[8:])
		} else if len(line) > 0 {
			// Keep short lines as-is (shouldn't happen but be safe)
			cleaned = append(cleaned, line)
		}
	}

	return strings.Join(cleaned, "\n")
}
