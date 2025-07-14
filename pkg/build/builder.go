package build

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cicd"
	"github.com/google/uuid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewBuilder creates a new builder instance
func NewBuilder(workDir string) (*Builder, error) {
	// Verify required tools are available
	if err := checkCommandExists("hugo"); err != nil {
		return nil, &BuildError{
			Type:      "prerequisite",
			Stage:     "initialization",
			Message:   "hugo command not found in PATH",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	if err := checkCommandExists("docker"); err != nil {
		return nil, &BuildError{
			Type:      "prerequisite", 
			Stage:     "initialization",
			Message:   "docker command not found in PATH",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Ensure work directory exists
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, &BuildError{
			Type:      "initialization",
			Stage:     "setup",
			Message:   "failed to create work directory",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	return &Builder{
		workDir:    workDir,
		hugoPath:   "hugo",
		dockerPath: "docker",
	}, nil
}

// BuildHugo implements the BuildClient interface for Hugo site generation
func (b *Builder) BuildHugo(ctx context.Context, config cicd.HugoConfig) (*cicd.BuildResult, error) {
	logger := otelzap.Ctx(ctx)

	startTime := time.Now()
	buildID := uuid.New().String()

	logger.Info("Starting Hugo build",
		zap.String("build_id", buildID),
		zap.String("environment", config.Environment),
		zap.String("output_dir", config.OutputDir),
		zap.Bool("minify", config.Minify))

	result := &cicd.BuildResult{
		Artifacts: make([]cicd.ArtifactInfo, 0),
		Logs:      make([]cicd.LogEntry, 0),
		Metadata:  make(map[string]string),
	}

	// Add initial log entry
	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Starting Hugo static site build",
		Source:    "hugo-builder",
	})

	// Assessment: Verify Hugo environment
	if err := b.assessHugoBuild(ctx, config, result); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Intervention: Execute Hugo build
	if err := b.executeHugoBuild(ctx, config, result); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Evaluation: Verify build output
	if err := b.evaluateHugoBuild(ctx, config, result); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Calculate final metrics
	result.Duration = time.Since(startTime)
	result.Success = true
	result.Metadata["build_id"] = buildID
	result.Metadata["hugo_version"] = b.getHugoVersion()

	logger.Info("Hugo build completed successfully",
		zap.String("build_id", buildID),
		zap.Duration("duration", result.Duration),
		zap.Int("artifacts", len(result.Artifacts)))

	return result, nil
}

// assessHugoBuild performs assessment phase for Hugo build
func (b *Builder) assessHugoBuild(ctx context.Context, config cicd.HugoConfig, result *cicd.BuildResult) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing Hugo build prerequisites")

	// Check if Hugo config file exists
	if config.ConfigFile != "" {
		if _, err := os.Stat(config.ConfigFile); os.IsNotExist(err) {
			result.Logs = append(result.Logs, cicd.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   fmt.Sprintf("Hugo config file not found: %s", config.ConfigFile),
				Source:    "hugo-builder",
			})
			return &BuildError{
				Type:      "prerequisite",
				Stage:     "assessment",
				Message:   "Hugo config file not found",
				Metadata:  map[string]interface{}{"config_file": config.ConfigFile},
				Timestamp: time.Now(),
			}
		}
	}

	// Check for content directory
	if _, err := os.Stat("content"); os.IsNotExist(err) {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "warning",
			Message:   "No content directory found, Hugo build may produce empty site",
			Source:    "hugo-builder",
		})
	}

	// Verify Hugo binary works
	cmd := exec.CommandContext(ctx, b.hugoPath, "version")
	if err := cmd.Run(); err != nil {
		return &BuildError{
			Type:      "prerequisite",
			Stage:     "assessment",
			Message:   "Hugo binary check failed",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Hugo build prerequisites verified",
		Source:    "hugo-builder",
	})

	return nil
}

// executeHugoBuild performs the actual Hugo build
func (b *Builder) executeHugoBuild(ctx context.Context, config cicd.HugoConfig, result *cicd.BuildResult) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing Hugo build")

	// Prepare Hugo command
	args := []string{}

	// Set environment
	if config.Environment != "" {
		args = append(args, "--environment", config.Environment)
	}

	// Set destination directory
	if config.OutputDir != "" {
		// Ensure output directory is clean
		if err := os.RemoveAll(config.OutputDir); err != nil && !os.IsNotExist(err) {
			return &BuildError{
				Type:      "execution",
				Stage:     "cleanup",
				Message:   "failed to clean output directory",
				Cause:     err,
				Timestamp: time.Now(),
			}
		}
		args = append(args, "--destination", config.OutputDir)
	}

	// Enable minification
	if config.Minify {
		args = append(args, "--minify")
	}

	// Set base URL
	if config.BaseURL != "" {
		args = append(args, "--baseURL", config.BaseURL)
	}

	// Set config file
	if config.ConfigFile != "" {
		args = append(args, "--config", config.ConfigFile)
	}

	// Add garbage collection
	args = append(args, "--gc")

	// Execute Hugo build
	cmd := exec.CommandContext(ctx, b.hugoPath, args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("HUGO_ENV=%s", config.Environment))

	output, err := cmd.CombinedOutput()
	
	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Hugo command: %s %s", b.hugoPath, strings.Join(args, " ")),
		Source:    "hugo-builder",
	})

	if err != nil {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   fmt.Sprintf("Hugo build failed: %s", string(output)),
			Source:    "hugo",
		})
		return &BuildError{
			Type:      "execution",
			Stage:     "build",
			Message:   "Hugo build failed",
			Cause:     err,
			Metadata:  map[string]interface{}{"output": string(output)},
			Timestamp: time.Now(),
		}
	}

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Hugo build completed successfully",
		Source:    "hugo",
	})

	// Log Hugo output
	if len(output) > 0 {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   string(output),
			Source:    "hugo",
		})
	}

	return nil
}

// evaluateHugoBuild verifies the Hugo build output
func (b *Builder) evaluateHugoBuild(ctx context.Context, config cicd.HugoConfig, result *cicd.BuildResult) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating Hugo build output")

	outputDir := config.OutputDir
	if outputDir == "" {
		outputDir = "public"
	}

	// Check if output directory exists and has content
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return &BuildError{
			Type:      "evaluation",
			Stage:     "output_verification",
			Message:   "Hugo output directory does not exist",
			Metadata:  map[string]interface{}{"output_dir": outputDir},
			Timestamp: time.Now(),
		}
	}

	// Count files and calculate size
	fileCount := 0
	totalSize := int64(0)
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
			totalSize += info.Size()
		}
		return nil
	})

	if err != nil {
		return &BuildError{
			Type:      "evaluation",
			Stage:     "output_analysis",
			Message:   "failed to analyze build output",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Check for index.html
	indexPath := filepath.Join(outputDir, "index.html")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "warning",
			Message:   "No index.html found in output directory",
			Source:    "hugo-builder",
		})
	}

	// Create archive of static site
	archivePath := filepath.Join(b.workDir, fmt.Sprintf("hugo-site-%d.tar.gz", time.Now().Unix()))
	if err := b.createArchive(outputDir, archivePath); err != nil {
		logger.Warn("Failed to create site archive", zap.Error(err))
	} else {
		// Calculate checksum
		checksum, err := b.calculateChecksum(archivePath)
		if err != nil {
			logger.Warn("Failed to calculate archive checksum", zap.Error(err))
		}

		// Add artifact
		artifact := cicd.ArtifactInfo{
			Name:     "hugo-static-site",
			Type:     "archive",
			Location: archivePath,
			Size:     totalSize,
			Checksum: checksum,
			Metadata: map[string]string{
				"file_count":   fmt.Sprintf("%d", fileCount),
				"output_dir":   outputDir,
				"archive_type": "tar.gz",
			},
			CreatedAt: time.Now(),
		}

		result.Artifacts = append(result.Artifacts, artifact)
	}

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Hugo build evaluation completed: %d files, %d bytes", fileCount, totalSize),
		Source:    "hugo-builder",
	})

	return nil
}

// BuildDockerImage implements the BuildClient interface for Docker image building
func (b *Builder) BuildDockerImage(ctx context.Context, config cicd.BuildConfig) (*cicd.BuildResult, error) {
	logger := otelzap.Ctx(ctx)

	startTime := time.Now()
	buildID := uuid.New().String()

	logger.Info("Starting Docker image build",
		zap.String("build_id", buildID),
		zap.String("dockerfile", config.DockerFile),
		zap.String("context", config.Context),
		zap.Strings("tags", config.Tags))

	result := &cicd.BuildResult{
		Artifacts: make([]cicd.ArtifactInfo, 0),
		Logs:      make([]cicd.LogEntry, 0),
		Metadata:  make(map[string]string),
	}

	// Add initial log entry
	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Starting Docker image build",
		Source:    "docker-builder",
	})

	// Assessment: Verify Docker environment
	if err := b.assessDockerBuild(ctx, config, result); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Intervention: Execute Docker build
	if err := b.executeDockerBuild(ctx, config, result); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Evaluation: Verify Docker image
	if err := b.evaluateDockerBuild(ctx, config, result); err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	// Calculate final metrics
	result.Duration = time.Since(startTime)
	result.Success = true
	result.Metadata["build_id"] = buildID
	result.Metadata["docker_version"] = b.getDockerVersion()

	logger.Info("Docker build completed successfully",
		zap.String("build_id", buildID),
		zap.Duration("duration", result.Duration),
		zap.Int("artifacts", len(result.Artifacts)))

	return result, nil
}

// assessDockerBuild performs assessment phase for Docker build
func (b *Builder) assessDockerBuild(ctx context.Context, config cicd.BuildConfig, result *cicd.BuildResult) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing Docker build prerequisites")

	// Check if Dockerfile exists
	dockerfilePath := config.DockerFile
	if dockerfilePath == "" {
		dockerfilePath = "Dockerfile"
	}

	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   fmt.Sprintf("Dockerfile not found: %s", dockerfilePath),
			Source:    "docker-builder",
		})
		return &BuildError{
			Type:      "prerequisite",
			Stage:     "assessment",
			Message:   "Dockerfile not found",
			Metadata:  map[string]interface{}{"dockerfile": dockerfilePath},
			Timestamp: time.Now(),
		}
	}

	// Check if build context exists
	contextPath := config.Context
	if contextPath == "" {
		contextPath = "."
	}

	if _, err := os.Stat(contextPath); os.IsNotExist(err) {
		return &BuildError{
			Type:      "prerequisite",
			Stage:     "assessment",
			Message:   "Build context directory not found",
			Metadata:  map[string]interface{}{"context": contextPath},
			Timestamp: time.Now(),
		}
	}

	// Verify Docker daemon is running
	cmd := exec.CommandContext(ctx, b.dockerPath, "info")
	if err := cmd.Run(); err != nil {
		return &BuildError{
			Type:      "prerequisite",
			Stage:     "assessment",
			Message:   "Docker daemon not accessible",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Docker build prerequisites verified",
		Source:    "docker-builder",
	})

	return nil
}

// executeDockerBuild performs the actual Docker build
func (b *Builder) executeDockerBuild(ctx context.Context, config cicd.BuildConfig, result *cicd.BuildResult) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing Docker build")

	// Prepare Docker build command
	args := []string{"build"}

	// Add dockerfile
	if config.DockerFile != "" {
		args = append(args, "-f", config.DockerFile)
	}

	// Add build args
	for key, value := range config.Args {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}

	// Add tags
	for _, tag := range config.Tags {
		fullTag := tag
		if config.Registry != "" && config.Image != "" {
			fullTag = fmt.Sprintf("%s/%s:%s", config.Registry, config.Image, tag)
		}
		args = append(args, "-t", fullTag)
	}

	// Add build context
	buildContext := config.Context
	if buildContext == "" {
		buildContext = "."
	}
	args = append(args, buildContext)

	// Execute Docker build
	cmd := exec.CommandContext(ctx, b.dockerPath, args...)

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Docker command: %s %s", b.dockerPath, strings.Join(args, " ")),
		Source:    "docker-builder",
	})

	output, err := cmd.CombinedOutput()
	
	if err != nil {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "error",
			Message:   fmt.Sprintf("Docker build failed: %s", string(output)),
			Source:    "docker",
		})
		return &BuildError{
			Type:      "execution",
			Stage:     "build",
			Message:   "Docker build failed",
			Cause:     err,
			Metadata:  map[string]interface{}{"output": string(output)},
			Timestamp: time.Now(),
		}
	}

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "Docker build completed successfully",
		Source:    "docker",
	})

	// Log Docker output
	if len(output) > 0 {
		result.Logs = append(result.Logs, cicd.LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   string(output),
			Source:    "docker",
		})
	}

	return nil
}

// evaluateDockerBuild verifies the Docker build output
func (b *Builder) evaluateDockerBuild(ctx context.Context, config cicd.BuildConfig, result *cicd.BuildResult) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating Docker build output")

	// Verify images were created
	for _, tag := range config.Tags {
		fullTag := tag
		if config.Registry != "" && config.Image != "" {
			fullTag = fmt.Sprintf("%s/%s:%s", config.Registry, config.Image, tag)
		}

		// Check if image exists
		cmd := exec.CommandContext(ctx, b.dockerPath, "inspect", fullTag)
		if err := cmd.Run(); err != nil {
			return &BuildError{
				Type:      "evaluation",
				Stage:     "image_verification",
				Message:   fmt.Sprintf("Docker image not found: %s", fullTag),
				Cause:     err,
				Timestamp: time.Now(),
			}
		}

		// Get image information
		cmd = exec.CommandContext(ctx, b.dockerPath, "inspect", fullTag, "--format", "{{.Size}}")
		output, err := cmd.Output()
		if err != nil {
			logger.Warn("Failed to get image size", zap.String("image", fullTag), zap.Error(err))
		}

		size := strings.TrimSpace(string(output))

		// Create artifact
		artifact := cicd.ArtifactInfo{
			Name:     fmt.Sprintf("docker-image-%s", tag),
			Type:     "docker_image",
			Location: fullTag,
			Metadata: map[string]string{
				"tag":      fullTag,
				"size":     size,
				"registry": config.Registry,
			},
			CreatedAt: time.Now(),
		}

		result.Artifacts = append(result.Artifacts, artifact)
	}

	result.Logs = append(result.Logs, cicd.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Docker build evaluation completed: %d images created", len(config.Tags)),
		Source:    "docker-builder",
	})

	return nil
}

// PushDockerImage implements the BuildClient interface for pushing Docker images
func (b *Builder) PushDockerImage(ctx context.Context, image, registry string) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Pushing Docker image",
		zap.String("image", image),
		zap.String("registry", registry))

	// Execute docker push
	cmd := exec.CommandContext(ctx, b.dockerPath, "push", image)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Docker push failed",
			zap.String("image", image),
			zap.String("output", string(output)),
			zap.Error(err))
		return &BuildError{
			Type:      "execution",
			Stage:     "push",
			Message:   "Docker push failed",
			Cause:     err,
			Metadata:  map[string]interface{}{"output": string(output)},
			Timestamp: time.Now(),
		}
	}

	logger.Info("Docker image pushed successfully",
		zap.String("image", image))

	return nil
}

// Helper functions

// checkCommandExists verifies that a command is available in PATH
func checkCommandExists(command string) error {
	_, err := exec.LookPath(command)
	return err
}

// getHugoVersion returns the Hugo version
func (b *Builder) getHugoVersion() string {
	cmd := exec.Command(b.hugoPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// getDockerVersion returns the Docker version
func (b *Builder) getDockerVersion() string {
	cmd := exec.Command(b.dockerPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// createArchive creates a tar.gz archive of the given directory
func (b *Builder) createArchive(sourceDir, archivePath string) error {
	cmd := exec.Command("tar", "-czf", archivePath, "-C", sourceDir, ".")
	return cmd.Run()
}

// calculateChecksum calculates SHA256 checksum of a file
func (b *Builder) calculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}