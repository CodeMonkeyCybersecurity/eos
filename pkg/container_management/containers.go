// pkg/container_management/containers.go
package container_management

import (
	"bufio"
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

// FindComposeProjects searches for Docker Compose projects in specified directories following Assess → Intervene → Evaluate pattern
func FindComposeProjects(rc *eos_io.RuntimeContext, config *ComposeConfig, searchPaths []string) (*ComposeSearchResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultComposeConfig()
	}
	
	if len(searchPaths) == 0 {
		searchPaths = expandSearchPaths(config)
	}
	
	logger.Info("Assessing Docker Compose project search",
		zap.Strings("search_paths", searchPaths),
		zap.Int("max_depth", config.MaxDepth))

	startTime := time.Now()

	result := &ComposeSearchResult{
		SearchPaths: searchPaths,
		Projects:    make([]ComposeProject, 0),
		Timestamp:   time.Now(),
	}

	// INTERVENE
	logger.Info("Searching for Docker Compose projects", zap.Strings("search_paths", searchPaths))

	for _, rootPath := range searchPaths {
		if !pathExists(rootPath) {
			logger.Debug("Search path does not exist", zap.String("path", rootPath))
			continue
		}

		projects, err := searchDirectory(rc, config, rootPath, 0)
		if err != nil {
			logger.Warn("Error searching directory", 
				zap.String("path", rootPath), 
				zap.Error(err))
			continue
		}

		result.Projects = append(result.Projects, projects...)
	}

	result.TotalFound = len(result.Projects)
	result.SearchDuration = time.Since(startTime)

	// EVALUATE
	logger.Info("Docker Compose project search completed successfully",
		zap.Int("projects_found", result.TotalFound),
		zap.Duration("search_duration", result.SearchDuration))

	return result, nil
}

// ListRunningContainers lists all running Docker containers following Assess → Intervene → Evaluate pattern
func ListRunningContainers(rc *eos_io.RuntimeContext, config *ComposeConfig) (*ContainerListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultComposeConfig()
	}
	
	logger.Info("Assessing container listing request")

	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker command not found: %w", err)
	}

	// INTERVENE
	logger.Info("Listing running Docker containers")

	cmd := exec.CommandContext(rc.Ctx, "docker", "ps", "--format", "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Labels}}")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to execute docker ps", zap.Error(err))
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	containers, err := parseContainerList(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}

	result := &ContainerListResult{
		Containers: containers,
		Total:      len(containers),
		Timestamp:  time.Now(),
	}

	// EVALUATE
	logger.Info("Container listing completed successfully", 
		zap.Int("container_count", result.Total))

	return result, nil
}

// StopAllComposeProjects stops all Docker Compose projects following Assess → Intervene → Evaluate pattern
func StopAllComposeProjects(rc *eos_io.RuntimeContext, config *ComposeConfig, options *ComposeStopOptions) (*ComposeMultiStopResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultComposeConfig()
	}
	
	if options == nil {
		options = &ComposeStopOptions{}
	}
	
	logger.Info("Assessing compose project stop operation",
		zap.Bool("force", options.Force),
		zap.Bool("dry_run", options.DryRun))

	startTime := time.Now()

	result := &ComposeMultiStopResult{
		Operations: make([]ComposeOperation, 0),
		Summary: ComposeStopSummary{
			Errors: make([]string, 0),
		},
	}

	// Find all compose projects
	searchResult, err := FindComposeProjects(rc, config, options.SearchPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to find compose projects: %w", err)
	}

	result.Summary.TotalProjects = searchResult.TotalFound

	// INTERVENE
	if options.DryRun {
		logger.Info("Dry run: would stop compose projects", zap.Int("project_count", len(searchResult.Projects)))
	} else {
		logger.Info("Stopping compose projects", zap.Int("project_count", len(searchResult.Projects)))
	}

	// Handle running containers if configured  
	if options.StopContainers {
		if err := handleRunningContainers(rc, config, options); err != nil {
			logger.Warn("Failed to handle running containers", zap.Error(err))
		}
	}

	// Stop each project
	for _, project := range searchResult.Projects {
		if !options.Force && !options.DryRun {
			if !promptForConfirmation(project.Path) {
				result.Summary.ProjectsSkipped++
				continue
			}
		}

		operation, err := StopComposeProject(rc, config, project, options)
		if err != nil {
			result.Summary.Errors = append(result.Summary.Errors, 
				fmt.Sprintf("Failed to stop %s: %v", project.Path, err))
			result.Summary.ProjectsFailed++
		} else if operation.Success {
			result.Summary.ProjectsStopped++
		} else {
			result.Summary.ProjectsFailed++
		}

		result.Operations = append(result.Operations, *operation)
	}

	result.Summary.Duration = time.Since(startTime)
	result.Summary.Success = result.Summary.ProjectsFailed == 0

	// EVALUATE
	logger.Info("Compose project stop operation completed",
		zap.Int("total_projects", result.Summary.TotalProjects),
		zap.Int("stopped", result.Summary.ProjectsStopped),
		zap.Int("failed", result.Summary.ProjectsFailed),
		zap.Bool("success", result.Summary.Success))

	return result, nil
}

// StopComposeProject stops a specific Docker Compose project following Assess → Intervene → Evaluate pattern
func StopComposeProject(rc *eos_io.RuntimeContext, config *ComposeConfig, project ComposeProject, options *ComposeStopOptions) (*ComposeOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	if config == nil {
		config = DefaultComposeConfig()
	}
	
	if options == nil {
		options = &ComposeStopOptions{}
	}
	
	logger.Info("Assessing compose project stop",
		zap.String("project_path", project.Path),
		zap.Bool("dry_run", options.DryRun))

	startTime := time.Now()
	operation := &ComposeOperation{
		Operation: "stop",
		Project:   project,
		Timestamp: time.Now(),
		DryRun:    options.DryRun,
	}

	// INTERVENE
	if options.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would stop compose project at %s", project.Path)
		operation.Duration = time.Since(startTime)
		logger.Info("Dry run: would stop compose project", zap.String("path", project.Path))
		return operation, nil
	}

	logger.Info("Stopping compose project", zap.String("project_path", project.Path))

	// Check if compose file exists
	composeFilePath := filepath.Join(project.Path, project.ComposeFile)
	if !pathExists(composeFilePath) {
		operation.Success = false
		operation.Message = fmt.Sprintf("Compose file not found: %s", composeFilePath)
		operation.Duration = time.Since(startTime)
		return operation, fmt.Errorf("compose file not found: %s", composeFilePath)
	}

	// Execute docker-compose down
	cmd := exec.CommandContext(rc.Ctx, "docker-compose", "-f", composeFilePath, "down")
	cmd.Dir = project.Path

	output, err := cmd.CombinedOutput()
	operation.Output = string(output)
	operation.Duration = time.Since(startTime)

	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to stop project: %v", err)
		logger.Error("Compose project stop failed", 
			zap.String("path", project.Path), 
			zap.Error(err))
		return operation, err
	}

	// EVALUATE
	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully stopped project at %s", project.Path)
	
	logger.Info("Compose project stopped successfully", 
		zap.String("project_path", project.Path),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// Helper functions

func expandSearchPaths(config *ComposeConfig) []string {
	if len(config.DefaultSearchPaths) > 0 {
		return config.DefaultSearchPaths
	}

	// Default search paths
	defaultPaths := []string{
		os.ExpandEnv("$HOME"),
		"/opt",
		"/srv",
		"/home",
	}

	var existingPaths []string
	for _, path := range defaultPaths {
		if pathExists(path) {
			existingPaths = append(existingPaths, path)
		}
	}

	return existingPaths
}

func searchDirectory(rc *eos_io.RuntimeContext, config *ComposeConfig, rootPath string, depth int) ([]ComposeProject, error) {
	var projects []ComposeProject

	if depth > config.MaxDepth {
		return projects, nil
	}

	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return projects, err
	}

	// Check if current directory has compose file
	for _, entry := range entries {
		if !entry.IsDir() && isComposeFile(entry.Name()) {
			if isExcluded(config, filepath.Base(rootPath)) {
				continue
			}

			project := ComposeProject{
				Path:        rootPath,
				Name:        filepath.Base(rootPath),
				ComposeFile: entry.Name(),
				LastSeen:    time.Now(),
			}

			// Get project status
			project.Status = getProjectStatus(rc, project)

			projects = append(projects, project)
			break // Found compose file, don't look for more in same directory
		}
	}

	// Recursively search subdirectories
	for _, entry := range entries {
		if entry.IsDir() && !isExcluded(config, entry.Name()) {
			subPath := filepath.Join(rootPath, entry.Name())
			subProjects, err := searchDirectory(rc, config, subPath, depth+1)
			if err != nil {
				continue // Skip directories we can't read
			}
			projects = append(projects, subProjects...)
		}
	}

	return projects, nil
}


func isComposeFile(filename string) bool {
	composeFiles := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
	}

	for _, cf := range composeFiles {
		if filename == cf {
			return true
		}
	}
	return false
}

func isExcluded(config *ComposeConfig, name string) bool {
	for _, pattern := range config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

func getProjectStatus(rc *eos_io.RuntimeContext, project ComposeProject) string {
	composeFilePath := filepath.Join(project.Path, project.ComposeFile)
	
	cmd := exec.CommandContext(rc.Ctx, "docker-compose", "-f", composeFilePath, "ps", "-q")
	cmd.Dir = project.Path
	
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return "stopped"
	}

	// Check if all containers are running
	for _, containerID := range lines {
		if containerID = strings.TrimSpace(containerID); containerID != "" {
			cmd := exec.CommandContext(rc.Ctx, "docker", "inspect", "--format", "{{.State.Status}}", containerID)
			statusOutput, err := cmd.Output()
			if err != nil {
				return "unknown"
			}
			status := strings.TrimSpace(string(statusOutput))
			if status != "running" {
				return "partial"
			}
		}
	}

	return "running"
}

func parseContainerList(output string) ([]ContainerInfo, error) {
	var containers []ContainerInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	// Skip header line
	if scanner.Scan() {
		// Header: CONTAINER ID   NAMES   IMAGE   STATUS   PORTS   LABELS
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}

		container := ContainerInfo{
			ID:     strings.TrimSpace(fields[0]),
			Name:   strings.TrimSpace(fields[1]),
			Image:  strings.TrimSpace(fields[2]),
			Status: strings.TrimSpace(fields[3]),
			Ports:  make(map[string]string),
			Labels: make(map[string]string),
		}

		// Parse ports
		portsStr := strings.TrimSpace(fields[4])
		if portsStr != "" {
			// Simple port parsing - could be enhanced
			container.Ports["raw"] = portsStr
		}

		// Parse labels
		labelsStr := strings.TrimSpace(fields[5])
		if labelsStr != "" {
			// Check for compose project label
			if strings.Contains(labelsStr, "com.docker.compose.project=") {
				parts := strings.Split(labelsStr, "com.docker.compose.project=")
				if len(parts) > 1 {
					projectName := strings.Split(parts[1], ",")[0]
					container.Project = projectName
				}
			}
			container.Labels["raw"] = labelsStr
		}

		// Set state based on status
		if strings.Contains(strings.ToLower(container.Status), "up") {
			container.State = "running"
		} else {
			container.State = "stopped"
		}

		containers = append(containers, container)
	}

	return containers, nil
}

func handleRunningContainers(rc *eos_io.RuntimeContext, config *ComposeConfig, options *ComposeStopOptions) error {
	// This would implement logic to handle running containers
	// For now, just log that we would handle them
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Handling running containers", zap.Bool("dry_run", options.DryRun))
	return nil
}

func promptForConfirmation(projectPath string) bool {
	// This would implement interactive confirmation
	// For now, return true to proceed (should be enhanced for real interactive use)
	return true
}