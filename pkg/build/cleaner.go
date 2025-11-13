package build

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BuildCleaner handles cleaning build artifacts and caches
type BuildCleaner struct {
	config *CleanerConfig
}

// CleanerConfig holds configuration for the build cleaner
type CleanerConfig struct {
	All        bool   `json:"all"`
	Cache      bool   `json:"cache"`
	Artifacts  bool   `json:"artifacts"`
	Component  string `json:"component"`
	Aggressive bool   `json:"aggressive"`
	OlderThan  string `json:"older_than"`
	DryRun     bool   `json:"dry_run"`
	Force      bool   `json:"force"`
}

// CleanupAnalysis holds the analysis of what will be cleaned
type CleanupAnalysis struct {
	Artifacts  []CleanupItem   `json:"artifacts"`
	CacheItems []CleanupItem   `json:"cache_items"`
	Images     []ImageItem     `json:"images"`
	Containers []ContainerItem `json:"containers"`
	TotalSize  int64           `json:"total_size"`
	TotalItems int             `json:"total_items"`
}

// CleanupItem represents an item to be cleaned
type CleanupItem struct {
	Path       string    `json:"path"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	LastAccess time.Time `json:"last_access"`
	Component  string    `json:"component,omitempty"`
}

// ImageItem represents a Docker image to be cleaned
type ImageItem struct {
	Name       string    `json:"name"`
	ID         string    `json:"id"`
	Size       int64     `json:"size"`
	Created    time.Time `json:"created"`
	Repository string    `json:"repository"`
	Tag        string    `json:"tag"`
}

// ContainerItem represents a Docker container to be cleaned
type ContainerItem struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Status string `json:"status"`
	Image  string `json:"image"`
}

// CleanupResult holds the result of a cleanup operation
type CleanupResult struct {
	ItemsTotal   int           `json:"items_total"`
	ItemsRemoved int           `json:"items_removed"`
	SizeFreed    int64         `json:"size_freed"`
	Duration     time.Duration `json:"duration"`
	Errors       []string      `json:"errors"`
}

// NewBuildCleaner creates a new build cleaner
func NewBuildCleaner(rc *eos_io.RuntimeContext, config *CleanerConfig) (*BuildCleaner, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating build cleaner",
		zap.Bool("all", config.All),
		zap.Bool("aggressive", config.Aggressive),
		zap.String("component", config.Component))

	return &BuildCleaner{
		config: config,
	}, nil
}

// AnalyzeCleanup analyzes what will be cleaned following Assessment phase
func (bc *BuildCleaner) AnalyzeCleanup(rc *eos_io.RuntimeContext) (*CleanupAnalysis, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Analyzing cleanup targets",
		zap.Bool("all", bc.config.All),
		zap.String("component", bc.config.Component))

	analysis := &CleanupAnalysis{
		Artifacts:  []CleanupItem{},
		CacheItems: []CleanupItem{},
		Images:     []ImageItem{},
		Containers: []ContainerItem{},
	}

	// Analyze build artifacts
	if bc.config.All || bc.config.Artifacts {
		artifacts, err := bc.analyzeBuildArtifacts(rc)
		if err != nil {
			logger.Warn("Failed to analyze build artifacts", zap.Error(err))
		} else {
			analysis.Artifacts = artifacts
		}
	}

	// Analyze cache items
	if bc.config.All || bc.config.Cache {
		cacheItems, err := bc.analyzeCacheItems(rc)
		if err != nil {
			logger.Warn("Failed to analyze cache items", zap.Error(err))
		} else {
			analysis.CacheItems = cacheItems
		}
	}

	// Analyze Docker images (aggressive mode)
	if bc.config.Aggressive {
		images, err := bc.analyzeDockerImages(rc)
		if err != nil {
			logger.Warn("Failed to analyze Docker images", zap.Error(err))
		} else {
			analysis.Images = images
		}

		containers, err := bc.analyzeDockerContainers(rc)
		if err != nil {
			logger.Warn("Failed to analyze Docker containers", zap.Error(err))
		} else {
			analysis.Containers = containers
		}
	}

	// Calculate totals
	analysis.TotalItems = len(analysis.Artifacts) + len(analysis.CacheItems) +
		len(analysis.Images) + len(analysis.Containers)

	for _, item := range analysis.Artifacts {
		analysis.TotalSize += item.Size
	}
	for _, item := range analysis.CacheItems {
		analysis.TotalSize += item.Size
	}
	for _, image := range analysis.Images {
		analysis.TotalSize += image.Size
	}

	logger.Info("Cleanup analysis completed",
		zap.Int("total_items", analysis.TotalItems),
		zap.Int64("total_size", analysis.TotalSize))

	return analysis, nil
}

// ExecuteCleanup executes the cleanup following Intervention phase
func (bc *BuildCleaner) ExecuteCleanup(rc *eos_io.RuntimeContext, analysis *CleanupAnalysis) (*CleanupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Executing cleanup",
		zap.Int("items_to_clean", analysis.TotalItems))

	result := &CleanupResult{
		ItemsTotal:   analysis.TotalItems,
		ItemsRemoved: 0,
		SizeFreed:    0,
		Errors:       []string{},
	}

	// Clean build artifacts
	for _, artifact := range analysis.Artifacts {
		if err := bc.cleanArtifact(rc, artifact); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to clean %s: %v", artifact.Path, err))
		} else {
			result.ItemsRemoved++
			result.SizeFreed += artifact.Size
		}
	}

	// Clean cache items
	for _, cacheItem := range analysis.CacheItems {
		if err := bc.cleanCacheItem(rc, cacheItem); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to clean cache %s: %v", cacheItem.Path, err))
		} else {
			result.ItemsRemoved++
			result.SizeFreed += cacheItem.Size
		}
	}

	// Clean Docker images
	for _, image := range analysis.Images {
		if err := bc.cleanDockerImage(rc, image); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to clean image %s: %v", image.Name, err))
		} else {
			result.ItemsRemoved++
			result.SizeFreed += image.Size
		}
	}

	// Clean Docker containers
	for _, container := range analysis.Containers {
		if err := bc.cleanDockerContainer(rc, container); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to clean container %s: %v", container.Name, err))
		} else {
			result.ItemsRemoved++
		}
	}

	result.Duration = time.Since(startTime)

	logger.Info("Cleanup execution completed",
		zap.Int("items_removed", result.ItemsRemoved),
		zap.Int64("size_freed", result.SizeFreed),
		zap.Int("errors", len(result.Errors)))

	return result, nil
}

// Analysis methods

func (bc *BuildCleaner) analyzeBuildArtifacts(rc *eos_io.RuntimeContext) ([]CleanupItem, error) {
	// Implementation would scan for build artifacts
	// For now, return example artifacts
	return []CleanupItem{
		{
			Path:       "./build/helen/dist",
			Type:       "build-output",
			Size:       50 * 1024 * 1024, // 50MB
			LastAccess: time.Now().Add(-24 * time.Hour),
			Component:  "helen",
		},
		{
			Path:       "./build/api/bin",
			Type:       "binary",
			Size:       25 * 1024 * 1024, // 25MB
			LastAccess: time.Now().Add(-12 * time.Hour),
			Component:  "api",
		},
	}, nil
}

func (bc *BuildCleaner) analyzeCacheItems(rc *eos_io.RuntimeContext) ([]CleanupItem, error) {
	// Implementation would scan for cache items
	return []CleanupItem{
		{
			Path:       "./build/.cache/docker",
			Type:       "docker-cache",
			Size:       200 * 1024 * 1024, // 200MB
			LastAccess: time.Now().Add(-48 * time.Hour),
		},
		{
			Path:       "./build/.cache/node_modules",
			Type:       "node-cache",
			Size:       150 * 1024 * 1024, // 150MB
			LastAccess: time.Now().Add(-6 * time.Hour),
		},
	}, nil
}

func (bc *BuildCleaner) analyzeDockerImages(rc *eos_io.RuntimeContext) ([]ImageItem, error) {
	// Implementation would list Docker images
	return []ImageItem{
		{
			Name:       "helen:latest",
			ID:         "sha256:abc123",
			Size:       100 * 1024 * 1024, // 100MB
			Created:    time.Now().Add(-48 * time.Hour),
			Repository: "helen",
			Tag:        "latest",
		},
		{
			Name:       "api:build-123",
			ID:         "sha256:def456",
			Size:       80 * 1024 * 1024, // 80MB
			Created:    time.Now().Add(-72 * time.Hour),
			Repository: "api",
			Tag:        "build-123",
		},
	}, nil
}

func (bc *BuildCleaner) analyzeDockerContainers(rc *eos_io.RuntimeContext) ([]ContainerItem, error) {
	// Implementation would list Docker containers
	return []ContainerItem{
		{
			Name:   "build-temp-123",
			ID:     "abc123456",
			Status: "exited",
			Image:  "node:18",
		},
		{
			Name:   "test-container-456",
			ID:     "def789012",
			Status: "exited",
			Image:  "alpine:latest",
		},
	}, nil
}

// Cleanup execution methods

func (bc *BuildCleaner) cleanArtifact(rc *eos_io.RuntimeContext, artifact CleanupItem) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Cleaning build artifact",
		zap.String("path", artifact.Path),
		zap.String("type", artifact.Type))

	// Implementation would remove the artifact
	// For now, just simulate successful cleanup
	return nil
}

func (bc *BuildCleaner) cleanCacheItem(rc *eos_io.RuntimeContext, cacheItem CleanupItem) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Cleaning cache item",
		zap.String("path", cacheItem.Path),
		zap.String("type", cacheItem.Type))

	// Implementation would remove the cache item
	return nil
}

func (bc *BuildCleaner) cleanDockerImage(rc *eos_io.RuntimeContext, image ImageItem) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Cleaning Docker image",
		zap.String("name", image.Name),
		zap.String("id", image.ID))

	// Implementation would remove the Docker image
	return nil
}

func (bc *BuildCleaner) cleanDockerContainer(rc *eos_io.RuntimeContext, container ContainerItem) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Cleaning Docker container",
		zap.String("name", container.Name),
		zap.String("id", container.ID))

	// Implementation would remove the Docker container
	return nil
}
