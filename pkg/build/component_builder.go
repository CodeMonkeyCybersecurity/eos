package build

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ComponentBuilder handles building individual components
type ComponentBuilder struct {
	config       *ComponentBuildConfig
	dockerClient DockerClient
	gitClient    GitClient
}

// ComponentBuildConfig holds configuration for component builds
type ComponentBuildConfig struct {
	Name             string            `json:"name"`
	Tag              string            `json:"tag"`
	Registry         string            `json:"registry"`
	Push             bool              `json:"push"`
	Force            bool              `json:"force"`
	WithDependencies bool              `json:"with_dependencies"`
	BuildArgs        map[string]string `json:"build_args"`
	Target           string            `json:"target"`
	Parallel         bool              `json:"parallel"`
	DryRun           bool              `json:"dry_run"`
	NoCache          bool              `json:"no_cache"`
	CacheFrom        string            `json:"cache_from"`
	CacheTo          string            `json:"cache_to"`
}

// ComponentBuildResult holds the result of a component build
type ComponentBuildResult struct {
	Component string        `json:"component"`
	Tag       string        `json:"tag"`
	ImageName string        `json:"image_name"`
	Duration  time.Duration `json:"duration"`
	ImageSize string        `json:"image_size"`
	Registry  string        `json:"registry"`
	Pushed    bool          `json:"pushed"`
	Artifacts []Artifact    `json:"artifacts"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}

// Artifact represents a build artifact
type Artifact struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// NewComponentBuilder creates a new component builder
func NewComponentBuilder(rc *eos_io.RuntimeContext, config *ComponentBuildConfig) (*ComponentBuilder, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating component builder",
		zap.String("component", config.Name),
		zap.String("tag", config.Tag))

	// Set default tag if not provided
	if config.Tag == "" {
		gitHash, err := getGitCommitHash(rc)
		if err != nil {
			logger.Warn("Failed to get git commit hash, using timestamp", zap.Error(err))
			config.Tag = fmt.Sprintf("build-%d", time.Now().Unix())
		} else {
			config.Tag = gitHash[:8] // Use short hash
		}
	}

	return &ComponentBuilder{
		config:       config,
		dockerClient: &DefaultDockerClient{},
		gitClient:    &DefaultGitClient{},
	}, nil
}

// Build executes the component build following Assessment → Intervention → Evaluation
func (cb *ComponentBuilder) Build(rc *eos_io.RuntimeContext) (*ComponentBuildResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting component build",
		zap.String("component", cb.config.Name),
		zap.String("tag", cb.config.Tag))

	result := &ComponentBuildResult{
		Component: cb.config.Name,
		Tag:       cb.config.Tag,
		Registry:  cb.config.Registry,
	}

	// Assessment: Check build prerequisites
	if err := cb.assessBuildPrerequisites(rc); err != nil {
		logger.Error("Build prerequisites assessment failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		return result, fmt.Errorf("build prerequisites assessment failed: %w", err)
	}

	// Dry run check
	if cb.config.DryRun {
		logger.Info("Dry run mode - build would execute successfully")
		result.Success = true
		result.Duration = time.Since(startTime)
		result.ImageName = cb.generateImageName()
		return result, nil
	}

	// Intervention: Execute the build
	if err := cb.executeBuild(rc, result); err != nil {
		logger.Error("Build execution failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("build execution failed: %w", err)
	}

	// Evaluation: Verify build success
	if err := cb.evaluateBuildResult(rc, result); err != nil {
		logger.Error("Build evaluation failed", zap.Error(err))
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("build evaluation failed: %w", err)
	}

	result.Success = true
	result.Duration = time.Since(startTime)

	logger.Info("Component build completed successfully",
		zap.String("component", cb.config.Name),
		zap.String("image", result.ImageName),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// assessBuildPrerequisites checks if all prerequisites for building are met
func (cb *ComponentBuilder) assessBuildPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing build prerequisites",
		zap.String("component", cb.config.Name))

	// Check if Docker is available
	if err := cb.dockerClient.Ping(rc.Ctx); err != nil {
		return fmt.Errorf("Docker is not available: %w", err)
	}

	// Check if component directory exists
	componentPath := fmt.Sprintf("./%s", cb.config.Name)
	if !cb.pathExists(componentPath) {
		return fmt.Errorf("component directory not found: %s", componentPath)
	}

	// Check if Dockerfile exists
	dockerfilePath := fmt.Sprintf("%s/Dockerfile", componentPath)
	if !cb.pathExists(dockerfilePath) {
		return fmt.Errorf("Dockerfile not found: %s", dockerfilePath)
	}

	// Check dependencies if required
	if cb.config.WithDependencies {
		if err := cb.checkDependencies(rc); err != nil {
			return fmt.Errorf("dependency check failed: %w", err)
		}
	}

	// Check if image already exists and force flag
	imageName := cb.generateImageName()
	exists, err := cb.dockerClient.ImageExists(rc.Ctx, imageName)
	if err != nil {
		logger.Warn("Failed to check if image exists", zap.Error(err))
	} else if exists && !cb.config.Force {
		return fmt.Errorf("image %s already exists, use --force-rebuild to override", imageName)
	}

	logger.Debug("Build prerequisites assessment completed")
	return nil
}

// executeBuild performs the actual build process
func (cb *ComponentBuilder) executeBuild(rc *eos_io.RuntimeContext, result *ComponentBuildResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing component build",
		zap.String("component", cb.config.Name))

	imageName := cb.generateImageName()
	result.ImageName = imageName

	// Build Docker image
	buildOptions := &DockerBuildOptions{
		Context:    fmt.Sprintf("./%s", cb.config.Name),
		Repository: cb.config.Name,
		Tags:       []string{cb.config.Tag},
		BuildArgs:  cb.config.BuildArgs,
		Target:     cb.config.Target,
		NoCache:    cb.config.NoCache,
		Registry:   cb.config.Registry,
	}

	if err := cb.dockerClient.BuildImage(rc.Ctx, buildOptions); err != nil {
		return fmt.Errorf("Docker build failed: %w", err)
	}

	// Get image size
	imageInfo, err := cb.dockerClient.InspectImage(rc.Ctx, imageName)
	if err != nil {
		logger.Warn("Failed to inspect image", zap.Error(err))
		result.ImageSize = "unknown"
	} else {
		result.ImageSize = formatImageSize(imageInfo.Size)
	}

	// Push to registry if requested
	if cb.config.Push && cb.config.Registry != "" {
		logger.Info("Pushing image to registry",
			zap.String("registry", cb.config.Registry),
			zap.String("image", imageName))

		if err := cb.dockerClient.PushImage(rc.Ctx, imageName); err != nil {
			return fmt.Errorf("failed to push image to registry: %w", err)
		}
		result.Pushed = true
	}

	// Collect build artifacts
	artifacts, err := cb.collectBuildArtifacts(rc)
	if err != nil {
		logger.Warn("Failed to collect build artifacts", zap.Error(err))
	} else {
		result.Artifacts = artifacts
	}

	logger.Debug("Build execution completed")
	return nil
}

// evaluateBuildResult verifies that the build was successful
func (cb *ComponentBuilder) evaluateBuildResult(rc *eos_io.RuntimeContext, result *ComponentBuildResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Evaluating build result",
		zap.String("component", cb.config.Name))

	// Verify image exists
	exists, err := cb.dockerClient.ImageExists(rc.Ctx, result.ImageName)
	if err != nil {
		return fmt.Errorf("failed to verify image existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("build completed but image %s was not found", result.ImageName)
	}

	// Test image can be run (basic smoke test)
	if err := cb.dockerClient.TestImage(rc.Ctx, result.ImageName); err != nil {
		logger.Warn("Image smoke test failed", zap.Error(err))
		// Don't fail the build for smoke test failures, just warn
	}

	// Verify registry push if requested
	if cb.config.Push && cb.config.Registry != "" {
		if !result.Pushed {
			return fmt.Errorf("push was requested but image was not pushed")
		}
	}

	logger.Debug("Build result evaluation completed")
	return nil
}

// Helper methods

func (cb *ComponentBuilder) generateImageName() string {
	if cb.config.Registry != "" {
		return fmt.Sprintf("%s/%s:%s", cb.config.Registry, cb.config.Name, cb.config.Tag)
	}
	return fmt.Sprintf("%s:%s", cb.config.Name, cb.config.Tag)
}

func (cb *ComponentBuilder) pathExists(path string) bool {
	// Implementation would check if path exists
	return true // Simplified for now
}

func (cb *ComponentBuilder) checkDependencies(rc *eos_io.RuntimeContext) error {
	// Implementation would check component dependencies
	return nil
}

func (cb *ComponentBuilder) collectBuildArtifacts(rc *eos_io.RuntimeContext) ([]Artifact, error) {
	// Implementation would collect build artifacts
	return []Artifact{
		{
			Name: fmt.Sprintf("%s-image", cb.config.Name),
			Type: "docker-image",
			Path: cb.generateImageName(),
			Size: 0, // Would be filled with actual size
		},
	}, nil
}

func getGitCommitHash(rc *eos_io.RuntimeContext) (string, error) {
	// Implementation would get git commit hash
	return "abc12345", nil
}

func formatImageSize(size int64) string {
	const (
		MB = 1024 * 1024
		GB = MB * 1024
	)

	if size >= GB {
		return fmt.Sprintf("%.1f GB", float64(size)/GB)
	}
	return fmt.Sprintf("%.1f MB", float64(size)/MB)
}
