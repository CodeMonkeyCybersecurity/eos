// pkg/debug/bionicgpt/diagnostics.go
// BionicGPT-specific diagnostic checks

package bionicgpt

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
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
