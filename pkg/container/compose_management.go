// pkg/container/compose_management.go
// Docker Compose project management functions
// Migrated from pkg/container_management for unified container operations

package container

import (
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

// ListRunningContainers lists all running Docker containers using SDK
func ListRunningContainers(rc *eos_io.RuntimeContext, config *ComposeManagementConfig) (*ContainerListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing running Docker containers via SDK")

	// Create Docker manager
	manager, err := NewManager(rc)
	if err != nil {
		logger.Error("Failed to create Docker manager", zap.Error(err))
		return nil, fmt.Errorf("failed to create docker manager: %w", err)
	}
	defer manager.Close()

	// List running containers using SDK
	containers, err := manager.ListRunning(rc.Ctx)
	if err != nil {
		logger.Error("Failed to list containers", zap.Error(err))
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Convert to ContainerInfo format
	containerInfos := make([]ContainerInfo, len(containers))
	runningCount := 0
	stoppedCount := 0

	for i, c := range containers {
		containerInfos[i] = ContainerInfo{
			ID:     c.ID,
			Name:   c.Name,
			Image:  c.Image,
			Status: string(c.Status),
			Size:   0, // Size not available from list operation
		}
		if c.IsRunning() {
			runningCount++
		} else {
			stoppedCount++
		}
	}

	result := &ContainerListResult{
		Containers: containerInfos,
		Total:      len(containerInfos),
		Running:    runningCount,
		Stopped:    stoppedCount,
		Timestamp:  time.Now(),
	}

	logger.Info("Container listing completed via SDK",
		zap.Int("container_count", result.Total),
		zap.Int("running", result.Running))

	return result, nil
}

// FindComposeProjects searches for Docker Compose projects in specified directories
func FindComposeProjects(rc *eos_io.RuntimeContext, config *ComposeManagementConfig, searchPaths []string) (*ComposeSearchResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	// Use default config if none provided
	if config == nil {
		config = DefaultComposeManagementConfig()
	}

	// Use default search paths if none provided
	if len(searchPaths) == 0 {
		searchPaths = expandSearchPaths(config)
	}

	logger.Info("Searching for Docker Compose projects",
		zap.Strings("search_paths", searchPaths))

	var allProjects []ComposeProject

	// Search each path
	for _, path := range searchPaths {
		projects, err := searchDirectory(rc, config, path, 0)
		if err != nil {
			logger.Warn("Failed to search directory",
				zap.String("path", path),
				zap.Error(err))
			continue
		}
		allProjects = append(allProjects, projects...)
	}

	result := &ComposeSearchResult{
		SearchPaths:    searchPaths,
		Projects:       allProjects,
		TotalFound:     len(allProjects),
		Timestamp:      time.Now(),
		SearchDuration: time.Since(startTime),
	}

	logger.Info("Compose project search completed",
		zap.Int("projects_found", result.TotalFound),
		zap.Duration("duration", result.SearchDuration))

	return result, nil
}

// Helper functions

func expandSearchPaths(config *ComposeManagementConfig) []string {
	if len(config.DefaultSearchPaths) > 0 {
		return config.DefaultSearchPaths
	}

	// Default search paths
	defaultPaths := []string{
		os.Getenv("HOME"),
		"/opt",
		"/srv",
		"/home",
	}

	// Filter out paths that don't exist
	var existingPaths []string
	for _, path := range defaultPaths {
		if path != "" && pathExists(path) {
			existingPaths = append(existingPaths, path)
		}
	}

	return existingPaths
}

func searchDirectory(rc *eos_io.RuntimeContext, config *ComposeManagementConfig, rootPath string, depth int) ([]ComposeProject, error) {
	var projects []ComposeProject

	if depth > config.MaxDepth {
		return nil, nil
	}

	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if isExcluded(config, entry.Name()) {
			continue
		}

		fullPath := filepath.Join(rootPath, entry.Name())

		if entry.IsDir() {
			// Check if this directory contains a compose file
			for _, composeFileName := range config.ComposeFileNames {
				composeFilePath := filepath.Join(fullPath, composeFileName)
				if pathExists(composeFilePath) {
					project := ComposeProject{
						Path:        fullPath,
						Name:        entry.Name(),
						ComposeFile: composeFileName,
						LastSeen:    time.Now(),
					}

					// Get status if configured
					if config.CheckStatus {
						project.Status = getProjectStatus(rc, project)
					}

					projects = append(projects, project)
					break // Found a compose file, don't check others
				}
			}

			// Recursively search subdirectories
			if config.FollowSymlinks || !isSymlink(fullPath) {
				subProjects, _ := searchDirectory(rc, config, fullPath, depth+1)
				projects = append(projects, subProjects...)
			}
		}
	}

	return projects, nil
}

func isExcluded(config *ComposeManagementConfig, name string) bool {
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
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
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

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}
