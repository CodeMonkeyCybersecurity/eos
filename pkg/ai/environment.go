// pkg/ai/environment.go

package ai

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnvironmentAnalyzer analyzes the current environment
type EnvironmentAnalyzer struct {
	workingDir  string
	maxFiles    int
	maxLogLines int
}

// NewEnvironmentAnalyzer creates a new environment analyzer
func NewEnvironmentAnalyzer(workingDir string) *EnvironmentAnalyzer {
	if workingDir == "" {
		workingDir, _ = os.Getwd()
	}
	return &EnvironmentAnalyzer{
		workingDir:  workingDir,
		maxFiles:    50,
		maxLogLines: 100,
	}
}

// AnalyzeEnvironment performs a comprehensive analysis of the current environment
func (ea *EnvironmentAnalyzer) AnalyzeEnvironment(rc *eos_io.RuntimeContext) (*EnvironmentContext, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting environment analysis", zap.String("working_dir", ea.workingDir))

	ctx := &EnvironmentContext{
		WorkingDirectory: ea.workingDir,
	}

	// Analyze file system
	if fs, err := ea.analyzeFileSystem(rc); err != nil {
		logger.Warn("Failed to analyze file system", zap.Error(err))
	} else {
		ctx.FileSystem = fs
	}

	// Analyze services
	if services, err := ea.analyzeServices(rc); err != nil {
		logger.Warn("Failed to analyze services", zap.Error(err))
	} else {
		ctx.Services = services
	}

	// Analyze infrastructure
	if infra, err := ea.analyzeInfrastructure(rc); err != nil {
		logger.Warn("Failed to analyze infrastructure", zap.Error(err))
	} else {
		ctx.Infrastructure = infra
	}

	// Analyze logs
	if logs, err := ea.analyzeLogs(rc); err != nil {
		logger.Warn("Failed to analyze logs", zap.Error(err))
	} else {
		ctx.Logs = logs
	}

	// Get system info
	if sysInfo, err := ea.getSystemInfo(rc); err != nil {
		logger.Warn("Failed to get system info", zap.Error(err))
	} else {
		ctx.SystemInfo = sysInfo
	}

	logger.Info("Environment analysis completed")
	return ctx, nil
}

// analyzeFileSystem analyzes the file system for relevant files
func (ea *EnvironmentAnalyzer) analyzeFileSystem(rc *eos_io.RuntimeContext) (*FileSystemContext, error) {
	logger := otelzap.Ctx(rc.Ctx)

	fsCtx := &FileSystemContext{
		DirectoryTree: make(map[string][]string),
	}

	// Walk the file system
	err := filepath.WalkDir(ea.workingDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		// Skip hidden directories and common ignore patterns
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") && name != "." ||
				name == "node_modules" || name == "vendor" || name == ".terraform" {
				return filepath.SkipDir
			}
		}

		// Analyze files
		if !d.IsDir() {
			fileInfo, err := ea.analyzeFile(path)
			if err != nil {
				return nil // Continue on errors
			}

			// Categorize files
			ext := strings.ToLower(filepath.Ext(path))
			base := strings.ToLower(filepath.Base(path))

			switch {
			case base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml":
				fsCtx.ComposeFiles = append(fsCtx.ComposeFiles, *fileInfo)
			case ext == ".tf" || ext == ".tfvars":
				fsCtx.TerraformFiles = append(fsCtx.TerraformFiles, *fileInfo)
			case ext == ".yml" || ext == ".yaml" || ext == ".json" || ext == ".toml" ||
				base == "dockerfile" || strings.Contains(base, "config"):
				fsCtx.ConfigFiles = append(fsCtx.ConfigFiles, *fileInfo)
			}

			// Limit file count
			totalFiles := len(fsCtx.ComposeFiles) + len(fsCtx.TerraformFiles) + len(fsCtx.ConfigFiles)
			if totalFiles >= ea.maxFiles {
				return filepath.SkipAll
			}
		}

		return nil
	})

	if err != nil {
		logger.Error("Error walking file system", zap.Error(err))
		return fsCtx, err
	}

	return fsCtx, nil
}

// analyzeFile analyzes a single file
func (ea *EnvironmentAnalyzer) analyzeFile(path string) (*FileInfo, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileInfo := &FileInfo{
		Path:        path,
		Size:        stat.Size(),
		ModTime:     stat.ModTime(),
		IsDirectory: stat.IsDir(),
	}

	// Get file content excerpt for small files
	if !stat.IsDir() && stat.Size() < 10*1024 { // < 10KB
		if content, err := os.ReadFile(path); err == nil {
			lines := strings.Split(string(content), "\n")
			if len(lines) > 10 {
				fileInfo.Excerpt = strings.Join(lines[:10], "\n") + "\n... (truncated)"
			} else {
				fileInfo.Excerpt = string(content)
			}
		}
	}

	return fileInfo, nil
}

// analyzeServices analyzes running services
func (ea *EnvironmentAnalyzer) analyzeServices(rc *eos_io.RuntimeContext) (*ServicesContext, error) {
	services := &ServicesContext{}

	// Analyze Docker containers
	if containers, err := ea.getDockerContainers(rc); err == nil {
		services.DockerContainers = containers
	}

	// Analyze systemd services
	if sysServices, err := ea.getSystemdServices(rc); err == nil {
		services.SystemdServices = sysServices
	}

	// Analyze processes
	if processes, err := ea.getProcesses(rc); err == nil {
		services.Processes = processes
	}

	// Analyze network ports
	if ports, err := ea.getNetworkPorts(rc); err == nil {
		services.NetworkPorts = ports
	}

	return services, nil
}

// getDockerContainers gets information about Docker containers
func (ea *EnvironmentAnalyzer) getDockerContainers(rc *eos_io.RuntimeContext) ([]ContainerInfo, error) {
	cmd := exec.CommandContext(rc.Ctx, "docker", "ps", "-a", "--format", "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var containers []ContainerInfo
	lines := strings.Split(string(output), "\n")

	// Skip header line
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) >= 4 {
			container := ContainerInfo{
				ID:     strings.TrimSpace(fields[0]),
				Name:   strings.TrimSpace(fields[1]),
				Image:  strings.TrimSpace(fields[2]),
				Status: strings.TrimSpace(fields[3]),
			}
			if len(fields) >= 5 {
				container.Ports = strings.Split(strings.TrimSpace(fields[4]), ",")
			}
			containers = append(containers, container)
		}
	}

	return containers, nil
}

// getSystemdServices gets information about systemd services
func (ea *EnvironmentAnalyzer) getSystemdServices(rc *eos_io.RuntimeContext) ([]ServiceInfo, error) {
	cmd := exec.CommandContext(rc.Ctx, "systemctl", "list-units", "--type=service", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var services []ServiceInfo
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			service := ServiceInfo{
				Name:   fields[0],
				Loaded: fields[1] == "loaded",
				Active: fields[2] == "active",
				Status: fields[3],
			}
			services = append(services, service)
		}
	}

	return services, nil
}

// getProcesses gets information about running processes
func (ea *EnvironmentAnalyzer) getProcesses(rc *eos_io.RuntimeContext) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(rc.Ctx, "ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	lines := strings.Split(string(output), "\n")

	// Skip header line
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 11 {
			pid, _ := strconv.Atoi(fields[1])
			cpu, _ := strconv.ParseFloat(fields[2], 64)
			memory, _ := strconv.ParseFloat(fields[3], 64)

			process := ProcessInfo{
				PID:     pid,
				CPU:     cpu,
				Memory:  memory,
				Command: strings.Join(fields[10:], " "),
			}

			if len(fields) >= 11 {
				process.Name = fields[10]
			}

			processes = append(processes, process)
		}
	}

	return processes, nil
}

// getNetworkPorts gets information about network ports
func (ea *EnvironmentAnalyzer) getNetworkPorts(rc *eos_io.RuntimeContext) ([]PortInfo, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(rc.Ctx, "netstat", "-an")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "ss", "-tuln")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var ports []PortInfo
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "LISTENING") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				// Parse port from address field
				addr := fields[3]
				if strings.Contains(addr, ":") {
					parts := strings.Split(addr, ":")
					if len(parts) >= 2 {
						if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
							portInfo := PortInfo{
								Port:     port,
								Protocol: fields[0],
								Status:   "LISTEN",
							}
							ports = append(ports, portInfo)
						}
					}
				}
			}
		}
	}

	return ports, nil
}

// analyzeInfrastructure analyzes infrastructure state
func (ea *EnvironmentAnalyzer) analyzeInfrastructure(rc *eos_io.RuntimeContext) (*InfrastructureContext, error) {
	infra := &InfrastructureContext{}

	// Check Vault status
	if vaultStatus, err := ea.getVaultStatus(rc); err == nil {
		infra.VaultStatus = vaultStatus
	}

	// Check Consul status
	if consulStatus, err := ea.getConsulStatus(rc); err == nil {
		infra.ConsulStatus = consulStatus
	}

	// Check Terraform state
	if tfState, err := ea.getTerraformState(rc); err == nil {
		infra.TerraformState = tfState
	}

	return infra, nil
}

// getVaultStatus gets Vault status
func (ea *EnvironmentAnalyzer) getVaultStatus(rc *eos_io.RuntimeContext) (*VaultStatusInfo, error) {
	cmd := exec.CommandContext(rc.Ctx, "vault", "status", "-format=json")
	cmd.Env = append(os.Environ(), "VAULT_ADDR="+os.Getenv("VAULT_ADDR"))

	output, err := cmd.Output()
	if err != nil {
		// Vault might not be available or configured
		return &VaultStatusInfo{}, nil
	}

	// Parse JSON response (simplified)
	status := &VaultStatusInfo{}
	if strings.Contains(string(output), `"sealed":true`) {
		status.Sealed = true
	}
	if strings.Contains(string(output), `"initialized":true`) {
		status.Initialized = true
	}

	return status, nil
}

// getConsulStatus gets Consul status
func (ea *EnvironmentAnalyzer) getConsulStatus(rc *eos_io.RuntimeContext) (*ConsulStatusInfo, error) {
	cmd := exec.CommandContext(rc.Ctx, "consul", "info")
	output, err := cmd.Output()
	if err != nil {
		return &ConsulStatusInfo{}, nil
	}

	status := &ConsulStatusInfo{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "leader =") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				status.Leader = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "datacenter =") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				status.Datacenter = strings.TrimSpace(parts[1])
			}
		}
	}

	return status, nil
}

// getTerraformState gets Terraform state information
func (ea *EnvironmentAnalyzer) getTerraformState(rc *eos_io.RuntimeContext) (*TerraformStateInfo, error) {
	// Check if we're in a Terraform directory
	if _, err := os.Stat(filepath.Join(ea.workingDir, "main.tf")); os.IsNotExist(err) {
		return &TerraformStateInfo{}, nil
	}

	state := &TerraformStateInfo{
		Outputs: make(map[string]string),
	}

	// Get Terraform version
	cmd := exec.CommandContext(rc.Ctx, "terraform", "version")
	cmd.Dir = ea.workingDir
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 0 {
			state.Version = strings.TrimSpace(lines[0])
		}
	}

	return state, nil
}

// analyzeLogs analyzes recent logs
func (ea *EnvironmentAnalyzer) analyzeLogs(rc *eos_io.RuntimeContext) (*LogContext, error) {
	logs := &LogContext{}

	// Get system logs
	if sysLogs, err := ea.getSystemLogs(rc); err == nil {
		logs.SystemLogs = sysLogs
		// Filter for errors
		for _, log := range sysLogs {
			if strings.Contains(strings.ToLower(log.Level), "error") ||
				strings.Contains(strings.ToLower(log.Message), "error") ||
				strings.Contains(strings.ToLower(log.Message), "failed") {
				logs.ErrorLogs = append(logs.ErrorLogs, log)
			}
		}
	}

	// Get Docker logs if available
	if dockerLogs, err := ea.getDockerLogs(rc); err == nil {
		logs.ServiceLogs = append(logs.ServiceLogs, dockerLogs...)
	}

	return logs, nil
}

// getSystemLogs gets recent system logs
func (ea *EnvironmentAnalyzer) getSystemLogs(rc *eos_io.RuntimeContext) ([]LogEntry, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(rc.Ctx, "log", "show", "--last", "1h", "--style", "syslog")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "journalctl", "-n", "100", "--no-pager")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var logs []LogEntry
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Simple log parsing (can be enhanced)
		log := LogEntry{
			Timestamp: time.Now(), // Simplified - would parse actual timestamp
			Level:     "INFO",     // Simplified - would parse actual level
			Service:   "system",
			Message:   strings.TrimSpace(line),
			Source:    "system",
		}

		// Try to detect error level
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(strings.ToLower(line), "failed") ||
			strings.Contains(strings.ToLower(line), "warning") {
			log.Level = "ERROR"
		}

		logs = append(logs, log)
		if len(logs) >= ea.maxLogLines {
			break
		}
	}

	return logs, nil
}

// getDockerLogs gets recent Docker container logs
func (ea *EnvironmentAnalyzer) getDockerLogs(rc *eos_io.RuntimeContext) ([]LogEntry, error) {
	// Get list of running containers
	cmd := exec.CommandContext(rc.Ctx, "docker", "ps", "--format", "{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var logs []LogEntry
	containers := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, container := range containers {
		if container == "" {
			continue
		}

		// Get logs for this container
		logCmd := exec.CommandContext(rc.Ctx, "docker", "logs", "--tail", "20", container)
		logOutput, err := logCmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(logOutput), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}

			log := LogEntry{
				Timestamp: time.Now(),
				Level:     "INFO",
				Service:   container,
				Message:   strings.TrimSpace(line),
				Source:    "docker",
			}

			if strings.Contains(strings.ToLower(line), "error") ||
				strings.Contains(strings.ToLower(line), "failed") {
				log.Level = "ERROR"
			}

			logs = append(logs, log)
		}
	}

	return logs, nil
}

// getSystemInfo gets basic system information
func (ea *EnvironmentAnalyzer) getSystemInfo(rc *eos_io.RuntimeContext) (*SystemInfo, error) {
	info := &SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// Get uptime (Linux/macOS)
	if runtime.GOOS != "windows" {
		if cmd := exec.CommandContext(rc.Ctx, "uptime"); cmd != nil {
			if output, err := cmd.Output(); err == nil {
				info.Uptime = strings.TrimSpace(string(output))
			}
		}
	}

	return info, nil
}
