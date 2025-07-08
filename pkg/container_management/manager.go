package container_management

import (
	"bufio"
	"encoding/json"
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

func OutputComposeStopJSON(result *ComposeMultiStopResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputComposeStopTable(result *ComposeMultiStopResult) error {
	summary := result.Summary

	fmt.Printf("Compose Stop Summary:\n")
	fmt.Printf("  Total projects: %d\n", summary.TotalProjects)
	fmt.Printf("  Successfully stopped: %d\n", summary.ProjectsStopped)
	fmt.Printf("  Skipped: %d\n", summary.ProjectsSkipped)
	fmt.Printf("  Failed: %d\n", summary.ProjectsFailed)
	fmt.Printf("  Duration: %v\n", summary.Duration)
	fmt.Printf("  Success: %t\n\n", summary.Success)

	if len(result.Operations) > 0 {
		fmt.Println("Operations:")
		for _, op := range result.Operations {
			status := "✓"
			if !op.Success {
				status = "✗"
			}
			if op.DryRun {
				status = "[DRY RUN]"
			}

			fmt.Printf("  %s %s: %s\n", status, op.Project.Path, op.Message)
		}
	}

	if len(summary.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range summary.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
	}

	return nil
}

// ContainerManager handles container and compose operations
type ContainerManager struct {
	config *ComposeConfig
}

// NewContainerManager creates a new container manager
func NewContainerManager(config *ComposeConfig) *ContainerManager {
	if config == nil {
		config = DefaultComposeConfig()
	}

	return &ContainerManager{
		config: config,
	}
}

// FindComposeProjects searches for Docker Compose projects in specified directories
func (cm *ContainerManager) FindComposeProjects(rc *eos_io.RuntimeContext, searchPaths []string) (*ComposeSearchResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if len(searchPaths) == 0 {
		searchPaths = cm.expandSearchPaths()
	}

	logger.Info("Searching for Docker Compose projects",
		zap.Strings("search_paths", searchPaths),
		zap.Int("max_depth", cm.config.MaxDepth))

	result := &ComposeSearchResult{
		SearchPaths: searchPaths,
		Projects:    make([]ComposeProject, 0),
		Timestamp:   time.Now(),
	}

	for _, rootPath := range searchPaths {
		if !pathExists(rootPath) {
			logger.Debug("Search path does not exist", zap.String("path", rootPath))
			continue
		}

		projects, err := cm.searchDirectory(rc, rootPath, 0)
		if err != nil {
			logger.Warn("Failed to search directory", zap.String("path", rootPath), zap.Error(err))
			continue
		}

		result.Projects = append(result.Projects, projects...)
		logger.Debug("Found projects in directory",
			zap.String("path", rootPath),
			zap.Int("count", len(projects)))
	}

	result.TotalFound = len(result.Projects)
	result.SearchDuration = time.Since(startTime)

	logger.Info("Compose project search completed",
		zap.Int("total_found", result.TotalFound),
		zap.Duration("duration", result.SearchDuration))

	return result, nil
}

// ListRunningContainers lists all running Docker containers
func (cm *ContainerManager) ListRunningContainers(rc *eos_io.RuntimeContext) (*ContainerListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing running Docker containers")

	cmd := exec.CommandContext(rc.Ctx, "docker", "ps", "--format", "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to list containers", zap.Error(err))
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	containers, err := cm.parseContainerList(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}

	running := 0
	for _, container := range containers {
		if strings.Contains(container.Status, "Up") {
			running++
		}
	}

	result := &ContainerListResult{
		Containers: containers,
		Total:      len(containers),
		Running:    running,
		Stopped:    len(containers) - running,
		Timestamp:  time.Now(),
	}

	logger.Info("Container listing completed",
		zap.Int("total", result.Total),
		zap.Int("running", result.Running))

	return result, nil
}

// StopAllComposeProjects stops all found compose projects
func (cm *ContainerManager) StopAllComposeProjects(rc *eos_io.RuntimeContext, options *ComposeStopOptions) (*ComposeMultiStopResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if options == nil {
		options = DefaultComposeStopOptions()
	}

	logger.Info("Starting to stop all compose projects",
		zap.Bool("dry_run", options.DryRun),
		zap.Bool("force", options.Force))

	// Find all compose projects
	searchResult, err := cm.FindComposeProjects(rc, options.SearchPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to find compose projects: %w", err)
	}

	if len(searchResult.Projects) == 0 {
		logger.Info("No compose projects found")
		return &ComposeMultiStopResult{
			Operations: []ComposeOperation{},
			Summary: ComposeStopSummary{
				Success:  true,
				Duration: time.Since(startTime),
			},
			Timestamp: time.Now(),
		}, nil
	}

	// Check and stop running containers if requested
	if options.StopContainers && !options.IgnoreRunning {
		if err := cm.handleRunningContainers(rc, options); err != nil {
			return nil, fmt.Errorf("failed to handle running containers: %w", err)
		}
	}

	// Stop each compose project
	operations := make([]ComposeOperation, 0, len(searchResult.Projects))
	summary := ComposeStopSummary{
		TotalProjects: len(searchResult.Projects),
	}

	for _, project := range searchResult.Projects {
		if options.ConfirmEach && !options.Force && !options.DryRun {
			if !cm.promptForConfirmation(project.Path) {
				logger.Info("Skipping project", zap.String("path", project.Path))
				summary.ProjectsSkipped++
				continue
			}
		}

		operation, err := cm.StopComposeProject(rc, project, options)
		if err != nil {
			summary.ProjectsFailed++
			summary.Errors = append(summary.Errors, fmt.Sprintf("%s: %v", project.Path, err))
			logger.Error("Failed to stop project", zap.String("path", project.Path), zap.Error(err))
		} else if operation.Success {
			summary.ProjectsStopped++
		} else {
			summary.ProjectsFailed++
			summary.Errors = append(summary.Errors, fmt.Sprintf("%s: %s", project.Path, operation.Message))
		}

		operations = append(operations, *operation)
	}

	summary.Duration = time.Since(startTime)
	summary.Success = (summary.ProjectsFailed == 0)

	result := &ComposeMultiStopResult{
		Operations: operations,
		Summary:    summary,
		Timestamp:  time.Now(),
	}

	logger.Info("Compose project stop operation completed",
		zap.Int("total", summary.TotalProjects),
		zap.Int("stopped", summary.ProjectsStopped),
		zap.Int("failed", summary.ProjectsFailed),
		zap.Bool("success", summary.Success))

	return result, nil
}

// StopComposeProject stops a single compose project
func (cm *ContainerManager) StopComposeProject(rc *eos_io.RuntimeContext, project ComposeProject, options *ComposeStopOptions) (*ComposeOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	operation := &ComposeOperation{
		Operation: "down",
		Project:   project,
		Timestamp: time.Now(),
		DryRun:    options.DryRun,
	}

	logger.Info("Stopping compose project",
		zap.String("path", project.Path),
		zap.String("compose_file", project.ComposeFile),
		zap.Bool("dry_run", options.DryRun))

	if options.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would stop compose project: %s", project.Path)
		operation.Duration = time.Since(startTime)
		return operation, nil
	}

	// Build docker compose command
	args := []string{"compose", "-f", project.ComposeFile, "down"}

	if options.RemoveVolumes {
		args = append(args, "--volumes")
	}
	if options.RemoveImages {
		args = append(args, "--rmi", "all")
	}
	if options.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", options.Timeout))
	}

	cmd := exec.CommandContext(rc.Ctx, "docker", args...)
	cmd.Dir = project.Path

	output, err := cmd.CombinedOutput()
	operation.Output = string(output)
	operation.Duration = time.Since(startTime)

	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to stop project: %v", err)
		logger.Error("Compose down failed",
			zap.String("path", project.Path),
			zap.Error(err),
			zap.String("output", operation.Output))
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully stopped compose project: %s", project.Path)

	logger.Info("Compose project stopped successfully",
		zap.String("path", project.Path),
		zap.Duration("duration", operation.Duration))

	return operation, nil
}

// Helper methods

func (cm *ContainerManager) expandSearchPaths() []string {
	paths := make([]string, 0, len(cm.config.DefaultSearchPaths))
	for _, path := range cm.config.DefaultSearchPaths {
		expanded := os.ExpandEnv(path)
		if pathExists(expanded) {
			paths = append(paths, expanded)
		}
	}
	return paths
}

func (cm *ContainerManager) searchDirectory(rc *eos_io.RuntimeContext, rootPath string, depth int) ([]ComposeProject, error) {
	if depth > cm.config.MaxDepth {
		return nil, nil
	}

	var projects []ComposeProject

	// Check if this directory contains compose files
	for _, fileName := range cm.config.ComposeFileNames {
		composePath := filepath.Join(rootPath, fileName)
		if pathExists(composePath) {
			project := ComposeProject{
				Path:        rootPath,
				ComposeFile: fileName,
				LastSeen:    time.Now(),
			}

			// Extract project name from directory
			project.Name = filepath.Base(rootPath)

			// Check status if enabled
			if cm.config.CheckStatus {
				project.Status = cm.getProjectStatus(rc, project)
			}

			projects = append(projects, project)
			break // Only need one compose file per directory
		}
	}

	// Search subdirectories if we haven't reached max depth
	if depth < cm.config.MaxDepth {
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			return projects, nil // Return what we found so far
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			// Skip excluded patterns
			if cm.isExcluded(entry.Name()) {
				continue
			}

			subPath := filepath.Join(rootPath, entry.Name())
			subProjects, _ := cm.searchDirectory(rc, subPath, depth+1)
			projects = append(projects, subProjects...)
		}
	}

	return projects, nil
}

func (cm *ContainerManager) isExcluded(name string) bool {
	for _, pattern := range cm.config.ExcludePatterns {
		if strings.Contains(name, pattern) || name == pattern {
			return true
		}
	}
	return false
}

func (cm *ContainerManager) getProjectStatus(rc *eos_io.RuntimeContext, project ComposeProject) string {
	cmd := exec.CommandContext(rc.Ctx, "docker", "compose", "-f", project.ComposeFile, "ps", "--format", "json")
	cmd.Dir = project.Path

	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	if strings.TrimSpace(string(output)) == "" {
		return "stopped"
	}

	// Simple heuristic: if we got output, something is running
	return "running"
}

func (cm *ContainerManager) parseContainerList(output string) ([]ContainerInfo, error) {
	var containers []ContainerInfo
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Skip header line
	if scanner.Scan() {
		// Skip header
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}

		container := ContainerInfo{
			ID:     parts[0],
			Name:   parts[1],
			Image:  parts[2],
			Status: parts[3],
		}

		if len(parts) > 4 {
			container.Ports = parsePortString(parts[4])
		}

		// Determine state from status
		if strings.Contains(container.Status, "Up") {
			container.State = "running"
		} else {
			container.State = "stopped"
		}

		containers = append(containers, container)
	}

	return containers, nil
}

func (cm *ContainerManager) handleRunningContainers(rc *eos_io.RuntimeContext, options *ComposeStopOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	containerList, err := cm.ListRunningContainers(rc)
	if err != nil {
		return fmt.Errorf("failed to list running containers: %w", err)
	}

	if containerList.Running == 0 {
		logger.Info("No running containers found")
		return nil
	}

	logger.Info("Found running containers", zap.Int("count", containerList.Running))

	if !options.Force && !options.DryRun {
		fmt.Printf("There are %d running containers. Would you like to stop them? [y/N]: ", containerList.Running)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" {
			return fmt.Errorf("please stop running containers before proceeding")
		}
	}

	if options.DryRun {
		logger.Info("Dry run: would stop running containers")
		return nil
	}

	// Stop all running containers
	logger.Info("Stopping running containers")
	for _, container := range containerList.Containers {
		if container.State == "running" {
			cmd := exec.CommandContext(rc.Ctx, "docker", "stop", container.ID)
			if err := cmd.Run(); err != nil {
				logger.Warn("Failed to stop container",
					zap.String("id", container.ID),
					zap.String("name", container.Name),
					zap.Error(err))
			} else {
				logger.Debug("Stopped container",
					zap.String("id", container.ID),
					zap.String("name", container.Name))
			}
		}
	}

	return nil
}

func (cm *ContainerManager) promptForConfirmation(projectPath string) bool {
	fmt.Printf("Stop compose project in %s? [y/N]: ", projectPath)
	var response string
	fmt.Scanln(&response)
	return response == "y" || response == "Y" || response == "yes"
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func parsePortString(portStr string) map[string]string {
	ports := make(map[string]string)
	if portStr == "" {
		return ports
	}

	// Simple parsing for now - can be enhanced
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "->") {
			mapping := strings.Split(part, "->")
			if len(mapping) == 2 {
				ports[strings.TrimSpace(mapping[1])] = strings.TrimSpace(mapping[0])
			}
		}
	}

	return ports
}

