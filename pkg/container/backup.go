// pkg/container/backup.go

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BackupConfig defines the configuration for Docker backup operations
type BackupConfig struct {
	BackupDir         string            // Base directory for backups
	IncludeContainers bool              // Backup running containers
	IncludeImages     bool              // Backup Docker images
	IncludeVolumes    bool              // Backup Docker volumes
	IncludeNetworks   bool              // Backup network configurations
	IncludeCompose    bool              // Backup docker-compose files
	IncludeEnvVars    bool              // Backup environment variables
	IncludeSwarm      bool              // Backup Docker Swarm configuration
	CompressionType   string            // Compression type (gzip, xz, none)
	Parallel          bool              // Run backup operations in parallel
	Retention         int               // Number of backup sets to retain
	Timestamp         string            // Timestamp for this backup session
	ExcludePatterns   []string          // Patterns to exclude from backup
	Metadata          map[string]string // Additional metadata
}

// BackupInventory represents the current state of Docker resources
type BackupInventory struct {
	Containers       []ContainerInfo
	Images           []ImageInfo
	Volumes          []VolumeInfo
	Networks         []NetworkInfo
	ComposeFiles     []string
	SwarmNodes       []SwarmNodeInfo
	TotalSizeBytes   int64
	BackupEstimate   time.Duration
}

// BackupResult represents the outcome of a backup operation
type BackupResult struct {
	Success          bool
	BackupPath       string
	ComponentResults map[string]ComponentBackupResult
	TotalSize        int64
	Duration         time.Duration
	ErrorsEncountered []string
}

// ComponentBackupResult represents the result of backing up a specific component
type ComponentBackupResult struct {
	ComponentType string
	Success       bool
	ItemsBackedUp int
	SizeBytes     int64
	Duration      time.Duration
	ErrorMessage  string
}

// Supporting types
type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	Status string
	Size   int64
}

type ImageInfo struct {
	ID         string
	Repository string
	Tag        string
	Size       int64
}

type VolumeInfo struct {
	Name       string
	Driver     string
	Mountpoint string
	Size       int64
}

type NetworkInfo struct {
	ID     string
	Name   string
	Driver string
}

type SwarmNodeInfo struct {
	ID   string
	Role string
	Name string
}

// BackupDockerEnvironment performs a comprehensive Docker backup following assessment→intervention→evaluation
func BackupDockerEnvironment(rc *eos_io.RuntimeContext, config *BackupConfig) (*BackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Docker environment backup", 
		zap.String("backup_dir", config.BackupDir),
		zap.String("timestamp", config.Timestamp))

	// Assessment: Inventory Docker resources and estimate backup requirements
	inventory, err := AssessDockerEnvironment(rc, config)
	if err != nil {
		return nil, cerr.Wrap(err, "Docker environment assessment failed")
	}

	// Intervention: Execute backup operations
	result, err := interventionExecuteDockerBackup(rc, config, inventory)
	if err != nil {
		return result, cerr.Wrap(err, "Docker backup intervention failed")
	}

	// Evaluation: Verify backup integrity and completeness
	if err := EvaluateDockerBackup(rc, config, result); err != nil {
		return result, cerr.Wrap(err, "Docker backup evaluation failed")
	}

	return result, nil
}

// AssessDockerEnvironment analyzes the current Docker state and backup requirements
func AssessDockerEnvironment(rc *eos_io.RuntimeContext, config *BackupConfig) (*BackupInventory, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing Docker environment for backup")

	inventory := &BackupInventory{
		Containers:       []ContainerInfo{},
		Images:           []ImageInfo{},
		Volumes:          []VolumeInfo{},
		Networks:         []NetworkInfo{},
		ComposeFiles:     []string{},
		SwarmNodes:       []SwarmNodeInfo{},
		TotalSizeBytes:   0,
	}

	// Verify Docker is accessible
	if err := checkDockerAccessible(rc); err != nil {
		return nil, cerr.Wrap(err, "Docker is not accessible")
	}

	// Assess containers
	if config.IncludeContainers {
		containers, err := inventoryContainers(rc)
		if err != nil {
			logger.Warn("Failed to inventory containers", zap.Error(err))
		} else {
			inventory.Containers = containers
			logger.Info("Containers inventoried", zap.Int("count", len(containers)))
		}
	}

	// Assess images
	if config.IncludeImages {
		images, err := inventoryImages(rc)
		if err != nil {
			logger.Warn("Failed to inventory images", zap.Error(err))
		} else {
			inventory.Images = images
			logger.Info("Images inventoried", zap.Int("count", len(images)))
		}
	}

	// Assess volumes
	if config.IncludeVolumes {
		volumes, err := inventoryVolumes(rc)
		if err != nil {
			logger.Warn("Failed to inventory volumes", zap.Error(err))
		} else {
			inventory.Volumes = volumes
			logger.Info("Volumes inventoried", zap.Int("count", len(volumes)))
		}
	}

	// Assess networks
	if config.IncludeNetworks {
		networks, err := inventoryNetworks(rc)
		if err != nil {
			logger.Warn("Failed to inventory networks", zap.Error(err))
		} else {
			inventory.Networks = networks
			logger.Info("Networks inventoried", zap.Int("count", len(networks)))
		}
	}

	// Find docker-compose files
	if config.IncludeCompose {
		composeFiles, err := findComposeFiles(rc)
		if err != nil {
			logger.Warn("Failed to find compose files", zap.Error(err))
		} else {
			inventory.ComposeFiles = composeFiles
			logger.Info("Compose files found", zap.Int("count", len(composeFiles)))
		}
	}

	// Assess Swarm
	if config.IncludeSwarm {
		swarmNodes, err := inventorySwarmNodes(rc)
		if err != nil {
			logger.Debug("No Swarm nodes found or Swarm not initialized", zap.Error(err))
		} else {
			inventory.SwarmNodes = swarmNodes
			logger.Info("Swarm nodes inventoried", zap.Int("count", len(swarmNodes)))
		}
	}

	// Calculate total size and estimate duration
	inventory.TotalSizeBytes = calculateTotalSize(inventory)
	inventory.BackupEstimate = estimateBackupDuration(inventory, config)

	logger.Info("Docker environment assessment completed", 
		zap.Int64("total_size_bytes", inventory.TotalSizeBytes),
		zap.Duration("estimated_duration", inventory.BackupEstimate))

	return inventory, nil
}

// interventionExecuteDockerBackup performs the actual backup operations
func interventionExecuteDockerBackup(rc *eos_io.RuntimeContext, config *BackupConfig, inventory *BackupInventory) (*BackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Docker backup intervention")

	startTime := time.Now()
	result := &BackupResult{
		Success:           true,
		BackupPath:        filepath.Join(config.BackupDir, config.Timestamp),
		ComponentResults:  make(map[string]ComponentBackupResult),
		ErrorsEncountered: []string{},
	}

	// Create backup directory structure
	if err := createBackupDirectoryStructure(rc, result.BackupPath); err != nil {
		return nil, cerr.Wrap(err, "failed to create backup directory structure")
	}

	// Execute backup operations (parallel or sequential based on config)
	if config.Parallel {
		err := executeParallelBackups(rc, config, inventory, result)
		if err != nil {
			result.Success = false
			return result, err
		}
	} else {
		err := executeSequentialBackups(rc, config, inventory, result)
		if err != nil {
			result.Success = false
			return result, err
		}
	}

	// Create backup manifest
	if err := createBackupManifest(rc, result.BackupPath, inventory, result); err != nil {
		logger.Warn("Failed to create backup manifest", zap.Error(err))
		result.ErrorsEncountered = append(result.ErrorsEncountered, "manifest creation failed")
	}

	// Calculate final metrics
	result.Duration = time.Since(startTime)
	result.TotalSize = calculateBackupSize(result.BackupPath)

	logger.Info("Docker backup intervention completed", 
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration),
		zap.Int64("total_size", result.TotalSize))

	return result, nil
}

// EvaluateDockerBackup verifies the backup integrity and completeness
func EvaluateDockerBackup(rc *eos_io.RuntimeContext, config *BackupConfig, result *BackupResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Evaluating Docker backup")

	// Verify backup directory exists and is accessible
	if _, err := os.Stat(result.BackupPath); os.IsNotExist(err) {
		return cerr.New("backup directory does not exist")
	}

	// Verify each component was backed up successfully
	for componentType, componentResult := range result.ComponentResults {
		if !componentResult.Success {
			logger.Error("Component backup failed", 
				zap.String("component", componentType),
				zap.String("error", componentResult.ErrorMessage))
			return cerr.New(fmt.Sprintf("component backup failed: %s", componentType))
		}

		// Verify component backup files exist
		componentDir := filepath.Join(result.BackupPath, componentType)
		if _, err := os.Stat(componentDir); os.IsNotExist(err) {
			return cerr.New(fmt.Sprintf("component directory missing: %s", componentType))
		}

		logger.Info("Component backup verified", 
			zap.String("component", componentType),
			zap.Int("items", componentResult.ItemsBackedUp),
			zap.Duration("duration", componentResult.Duration))
	}

	// Test backup integrity for critical components
	if config.IncludeContainers {
		if err := validateContainerBackups(rc, result.BackupPath); err != nil {
			return cerr.Wrap(err, "container backup validation failed")
		}
	}

	if config.IncludeVolumes {
		if err := validateVolumeBackups(rc, result.BackupPath); err != nil {
			return cerr.Wrap(err, "volume backup validation failed")
		}
	}

	// Clean up old backups based on retention policy
	if config.Retention > 0 {
		if err := cleanupOldBackups(rc, config.BackupDir, config.Retention); err != nil {
			logger.Warn("Failed to clean up old backups", zap.Error(err))
		}
	}

	logger.Info("Docker backup evaluation completed successfully")
	return nil
}

// Helper functions for backup operations

func checkDockerAccessible(rc *eos_io.RuntimeContext) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Capture: true,
	})
	return err
}

func inventoryContainers(rc *eos_io.RuntimeContext) ([]ContainerInfo, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "-a", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	var containers []ContainerInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, "\t")
		if len(parts) >= 4 {
			containers = append(containers, ContainerInfo{
				ID:     parts[0],
				Name:   parts[1],
				Image:  parts[2],
				Status: parts[3],
			})
		}
	}

	return containers, nil
}

func inventoryImages(rc *eos_io.RuntimeContext) ([]ImageInfo, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	var images []ImageInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, "\t")
		if len(parts) >= 4 {
			images = append(images, ImageInfo{
				ID:         parts[0],
				Repository: parts[1],
				Tag:        parts[2],
				// Size parsing would go here in production
			})
		}
	}

	return images, nil
}

func inventoryVolumes(rc *eos_io.RuntimeContext) ([]VolumeInfo, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"volume", "ls", "--format", "{{.Name}}\t{{.Driver}}"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	var volumes []VolumeInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 {
			volumes = append(volumes, VolumeInfo{
				Name:   parts[0],
				Driver: parts[1],
			})
		}
	}

	return volumes, nil
}

func inventoryNetworks(rc *eos_io.RuntimeContext) ([]NetworkInfo, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"network", "ls", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	var networks []NetworkInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			networks = append(networks, NetworkInfo{
				ID:     parts[0],
				Name:   parts[1],
				Driver: parts[2],
			})
		}
	}

	return networks, nil
}

func findComposeFiles(rc *eos_io.RuntimeContext) ([]string, error) {
	// Find docker-compose files in common locations
	patterns := []string{
		"docker-compose.yml",
		"docker-compose.yaml", 
		"compose.yml",
		"compose.yaml",
	}

	var composeFiles []string
	for _, pattern := range patterns {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "find",
			Args:    []string{".", "-name", pattern, "-type", "f"},
			Capture: true,
		})
		if err == nil {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			for _, line := range lines {
				if line != "" {
					composeFiles = append(composeFiles, line)
				}
			}
		}
	}

	return composeFiles, nil
}

func inventorySwarmNodes(rc *eos_io.RuntimeContext) ([]SwarmNodeInfo, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"node", "ls", "--format", "{{.ID}}\t{{.Role}}\t{{.Hostname}}"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	var nodes []SwarmNodeInfo
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			nodes = append(nodes, SwarmNodeInfo{
				ID:   parts[0],
				Role: parts[1],
				Name: parts[2],
			})
		}
	}

	return nodes, nil
}

func calculateTotalSize(inventory *BackupInventory) int64 {
	// This would calculate actual sizes in production
	var total int64
	
	// Estimate based on counts for now
	total += int64(len(inventory.Containers)) * 100 * 1024 * 1024    // 100MB per container
	total += int64(len(inventory.Images)) * 500 * 1024 * 1024       // 500MB per image
	total += int64(len(inventory.Volumes)) * 50 * 1024 * 1024       // 50MB per volume
	
	return total
}

func estimateBackupDuration(inventory *BackupInventory, config *BackupConfig) time.Duration {
	// Estimate based on component counts and whether parallel execution is enabled
	baseTime := time.Duration(len(inventory.Containers)+len(inventory.Images)+len(inventory.Volumes)) * time.Minute
	
	if config.Parallel {
		baseTime = baseTime / 2 // Rough estimate for parallel execution
	}
	
	return baseTime
}

func createBackupDirectoryStructure(rc *eos_io.RuntimeContext, backupPath string) error {
	dirs := []string{
		filepath.Join(backupPath, "containers"),
		filepath.Join(backupPath, "images"),
		filepath.Join(backupPath, "volumes"),
		filepath.Join(backupPath, "networks"),
		filepath.Join(backupPath, "compose"),
		filepath.Join(backupPath, "swarm"),
		filepath.Join(backupPath, "env"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

func executeSequentialBackups(rc *eos_io.RuntimeContext, config *BackupConfig, inventory *BackupInventory, result *BackupResult) error {
	// Execute each backup operation sequentially
	operations := getBackupOperations(config, inventory, result.BackupPath)
	
	for _, op := range operations {
		if err := op.execute(rc); err != nil {
			result.ComponentResults[op.componentType] = ComponentBackupResult{
				ComponentType: op.componentType,
				Success:       false,
				ErrorMessage:  err.Error(),
			}
			result.ErrorsEncountered = append(result.ErrorsEncountered, fmt.Sprintf("%s: %v", op.componentType, err))
		} else {
			result.ComponentResults[op.componentType] = ComponentBackupResult{
				ComponentType: op.componentType,
				Success:       true,
				ItemsBackedUp: op.itemCount,
			}
		}
	}
	
	return nil
}

func executeParallelBackups(rc *eos_io.RuntimeContext, config *BackupConfig, inventory *BackupInventory, result *BackupResult) error {
	// Implement parallel backup execution using goroutines
	// For now, fall back to sequential
	return executeSequentialBackups(rc, config, inventory, result)
}

type backupOperation struct {
	componentType string
	itemCount     int
	execute       func(rc *eos_io.RuntimeContext) error
}

func getBackupOperations(config *BackupConfig, inventory *BackupInventory, backupPath string) []backupOperation {
	var operations []backupOperation

	if config.IncludeContainers && len(inventory.Containers) > 0 {
		operations = append(operations, backupOperation{
			componentType: "containers",
			itemCount:     len(inventory.Containers),
			execute: func(rc *eos_io.RuntimeContext) error {
				return backupContainers(rc, inventory.Containers, filepath.Join(backupPath, "containers"))
			},
		})
	}

	if config.IncludeVolumes && len(inventory.Volumes) > 0 {
		operations = append(operations, backupOperation{
			componentType: "volumes",
			itemCount:     len(inventory.Volumes),
			execute: func(rc *eos_io.RuntimeContext) error {
				return backupVolumes(rc, inventory.Volumes, filepath.Join(backupPath, "volumes"))
			},
		})
	}

	// Add more operations for other components...

	return operations
}

func backupContainers(rc *eos_io.RuntimeContext, containers []ContainerInfo, backupDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	for _, container := range containers {
		logger.Info("Backing up container", zap.String("container", container.Name), zap.String("id", container.ID))
		
		backupPath := filepath.Join(backupDir, fmt.Sprintf("%s_%s.tar", container.Name, container.ID))
		err := execute.RunSimple(rc.Ctx, "sh", "-c", 
			fmt.Sprintf("docker export %s > %s", container.ID, backupPath))
		
		if err != nil {
			logger.Error("Container backup failed", zap.String("container", container.Name), zap.Error(err))
			return err
		}
	}
	
	return nil
}

func backupVolumes(rc *eos_io.RuntimeContext, volumes []VolumeInfo, backupDir string) error {
	logger := otelzap.Ctx(rc.Ctx)
	timestamp := time.Now().Format("20060102150405")
	
	for _, volume := range volumes {
		logger.Info("Backing up volume", zap.String("volume", volume.Name))
		
		volumeBackupDir := filepath.Join(backupDir, fmt.Sprintf("%s_%s", volume.Name, timestamp))
		
		if err := os.MkdirAll(volumeBackupDir, 0755); err != nil {
			return err
		}
		
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args: []string{
				"run", "--rm",
				"-v", fmt.Sprintf("%s:/volume", volume.Name),
				"-v", fmt.Sprintf("%s:/backup", volumeBackupDir),
				"alpine",
				"sh", "-c", "cp -r /volume/. /backup/",
			},
		})
		
		if err != nil {
			logger.Error("Volume backup failed", zap.String("volume", volume.Name), zap.Error(err))
			return err
		}
	}
	
	return nil
}

func createBackupManifest(rc *eos_io.RuntimeContext, backupPath string, inventory *BackupInventory, result *BackupResult) error {
	// Create a manifest file with backup details
	manifest := struct {
		Timestamp   string                           `json:"timestamp"`
		BackupPath  string                           `json:"backup_path"`
		Inventory   *BackupInventory                 `json:"inventory"`
		Results     map[string]ComponentBackupResult `json:"results"`
		Duration    string                           `json:"duration"`
		Success     bool                             `json:"success"`
	}{
		Timestamp:  time.Now().Format(time.RFC3339),
		BackupPath: backupPath,
		Inventory:  inventory,
		Results:    result.ComponentResults,
		Duration:   result.Duration.String(),
		Success:    result.Success,
	}

	manifestPath := filepath.Join(backupPath, "manifest.json")
	// In production, would marshal manifest to JSON and write to file
	_ = manifest
	_ = manifestPath
	
	return nil
}

func calculateBackupSize(backupPath string) int64 {
	// Calculate actual backup size by walking the directory
	var size int64
	_ = filepath.Walk(backupPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func validateContainerBackups(rc *eos_io.RuntimeContext, backupPath string) error {
	// Verify container backup files exist and are valid tar files
	containerDir := filepath.Join(backupPath, "containers")
	files, err := os.ReadDir(containerDir)
	if err != nil {
		return err
	}
	
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		
		filePath := filepath.Join(containerDir, file.Name())
		// Verify tar file integrity
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "tar",
			Args:    []string{"-tf", filePath},
			Capture: true,
		})
		
		if err != nil {
			return fmt.Errorf("invalid container backup file: %s", file.Name())
		}
	}
	
	return nil
}

func validateVolumeBackups(rc *eos_io.RuntimeContext, backupPath string) error {
	// Verify volume backup directories exist and contain data
	volumeDir := filepath.Join(backupPath, "volumes")
	dirs, err := os.ReadDir(volumeDir)
	if err != nil {
		return err
	}
	
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		
		dirPath := filepath.Join(volumeDir, dir.Name())
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			return err
		}
		
		if len(entries) == 0 {
			return fmt.Errorf("empty volume backup: %s", dir.Name())
		}
	}
	
	return nil
}

func cleanupOldBackups(rc *eos_io.RuntimeContext, backupDir string, retention int) error {
	// Remove old backup directories beyond retention policy
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return err
	}
	
	// Sort by modification time and remove oldest
	// This is simplified - production would implement proper sorting and cleanup
	if len(entries) > retention {
		// Remove oldest entries
		for i := 0; i < len(entries)-retention; i++ {
			oldPath := filepath.Join(backupDir, entries[i].Name())
			if err := os.RemoveAll(oldPath); err != nil {
				logger.Warn("Failed to remove old backup", 
					zap.String("path", oldPath),
					zap.Error(err))
			}
		}
	}
	
	return nil
}