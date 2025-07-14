package cicd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// MockBuildClient provides a mock implementation for testing
type MockBuildClient struct {
	logger *zap.Logger
}

// NewMockBuildClient creates a new mock build client
func NewMockBuildClient(logger *zap.Logger) *MockBuildClient {
	return &MockBuildClient{
		logger: logger,
	}
}

// BuildHugo simulates Hugo build process
func (c *MockBuildClient) BuildHugo(ctx context.Context, config HugoConfig) (*BuildResult, error) {
	c.logger.Info("Mock Hugo build started",
		zap.String("environment", config.Environment),
		zap.Bool("minify", config.Minify))

	start := time.Now()
	
	// Simulate build time
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("build cancelled: %w", ctx.Err())
	case <-time.After(2 * time.Second):
		// Continue with build
	}

	// Create mock artifacts
	artifacts := []ArtifactInfo{
		{
			Name:      "hugo-site",
			Type:      "archive",
			Location:  "/tmp/hugo-build.tar.gz",
			Size:      1024 * 1024,
			Checksum:  "mock-checksum-123",
			Metadata:  map[string]string{"pages": "42", "size": "1MB"},
			CreatedAt: time.Now(),
		},
	}

	// Create mock logs
	logs := []LogEntry{
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "Hugo build started",
			Source:    "hugo",
			Stage:     "build",
		},
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "Built 42 pages in 2s",
			Source:    "hugo",
			Stage:     "build",
		},
	}

	result := &BuildResult{
		Success:   true,
		Artifacts: artifacts,
		Logs:      logs,
		Duration:  time.Since(start),
		Metadata:  map[string]string{"pages": "42", "build_time": "2s"},
	}

	c.logger.Info("Mock Hugo build completed",
		zap.Duration("duration", result.Duration))

	return result, nil
}

// BuildDockerImage simulates Docker image build
func (c *MockBuildClient) BuildDockerImage(ctx context.Context, config BuildConfig) (*BuildResult, error) {
	c.logger.Info("Mock Docker build started",
		zap.String("image", config.Image),
		zap.String("dockerfile", config.DockerFile))

	start := time.Now()

	// Simulate build time
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("build cancelled: %w", ctx.Err())
	case <-time.After(5 * time.Second):
		// Continue with build
	}

	imageTag := fmt.Sprintf("%s/%s:latest", config.Registry, config.Image)
	
	artifacts := []ArtifactInfo{
		{
			Name:      "docker-image",
			Type:      "docker_image",
			Location:  imageTag,
			Size:      100 * 1024 * 1024, // 100MB
			Checksum:  "sha256:mock-image-hash",
			Metadata:  map[string]string{"tag": imageTag, "size": "100MB"},
			CreatedAt: time.Now(),
		},
	}

	logs := []LogEntry{
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   "Docker build started",
			Source:    "docker",
			Stage:     "build",
		},
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   fmt.Sprintf("Successfully built image %s", imageTag),
			Source:    "docker",
			Stage:     "build",
		},
	}

	result := &BuildResult{
		Success:   true,
		Artifacts: artifacts,
		Logs:      logs,
		Duration:  time.Since(start),
		Metadata:  map[string]string{"image": imageTag, "size": "100MB"},
	}

	return result, nil
}

// PushDockerImage simulates Docker image push
func (c *MockBuildClient) PushDockerImage(ctx context.Context, image, registry string) error {
	c.logger.Info("Mock Docker push started",
		zap.String("image", image),
		zap.String("registry", registry))

	// Simulate push time
	select {
	case <-ctx.Done():
		return fmt.Errorf("push cancelled: %w", ctx.Err())
	case <-time.After(3 * time.Second):
		// Continue with push
	}

	c.logger.Info("Mock Docker push completed",
		zap.String("image", image))

	return nil
}

// RunInfrastructureTests simulates infrastructure testing
func (c *MockBuildClient) RunInfrastructureTests(ctx context.Context, config *PipelineConfig) error {
	c.logger.Info("Mock infrastructure tests started",
		zap.String("pipeline", config.AppName))

	// Simulate test time
	select {
	case <-ctx.Done():
		return fmt.Errorf("tests cancelled: %w", ctx.Err())
	case <-time.After(10 * time.Second):
		// Continue with tests
	}

	c.logger.Info("Mock infrastructure tests completed",
		zap.String("pipeline", config.AppName))

	return nil
}

// MockNomadClient provides a mock Nomad client for testing
type MockNomadClient struct {
	logger *zap.Logger
	jobs   map[string]*NomadJobStatus
}

// NewMockNomadClient creates a new mock Nomad client
func NewMockNomadClient(logger *zap.Logger) *MockNomadClient {
	return &MockNomadClient{
		logger: logger,
		jobs:   make(map[string]*NomadJobStatus),
	}
}

// SubmitJob simulates submitting a job to Nomad
func (c *MockNomadClient) SubmitJob(ctx context.Context, jobSpec string) (*NomadJobStatus, error) {
	// Extract job name from spec (simplified)
	jobID := extractJobName(jobSpec)
	if jobID == "" {
		jobID = fmt.Sprintf("job-%d", time.Now().Unix())
	}

	c.logger.Info("Mock Nomad job submitted",
		zap.String("job_id", jobID))

	status := &NomadJobStatus{
		ID:      jobID,
		Status:  "pending",
		Running: 0,
		Desired: 1,
		Failed:  0,
		Allocations: []*NomadAllocation{},
	}

	c.jobs[jobID] = status

	// Simulate job startup
	go c.simulateJobLifecycle(jobID)

	return status, nil
}

// GetJobStatus returns the status of a Nomad job
func (c *MockNomadClient) GetJobStatus(ctx context.Context, jobID string) (*NomadJobStatus, error) {
	status, exists := c.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return status, nil
}

// StopJob simulates stopping a Nomad job
func (c *MockNomadClient) StopJob(ctx context.Context, jobID string, purge bool) error {
	c.logger.Info("Mock Nomad job stopped",
		zap.String("job_id", jobID),
		zap.Bool("purge", purge))

	if status, exists := c.jobs[jobID]; exists {
		status.Status = "dead"
		status.Running = 0
		if purge {
			delete(c.jobs, jobID)
		}
	}

	return nil
}

// GetAllocations returns allocations for a job
func (c *MockNomadClient) GetAllocations(ctx context.Context, jobID string) ([]*NomadAllocation, error) {
	status, exists := c.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return status.Allocations, nil
}

// simulateJobLifecycle simulates the lifecycle of a Nomad job
func (c *MockNomadClient) simulateJobLifecycle(jobID string) {
	// Wait a bit, then mark as running
	time.Sleep(2 * time.Second)
	
	if status, exists := c.jobs[jobID]; exists {
		status.Status = "running"
		status.Running = 1
		
		allocation := &NomadAllocation{
			ID:     fmt.Sprintf("alloc-%s", jobID),
			JobID:  jobID,
			Status: "running",
			NodeID: "node-1",
			Tasks:  map[string]string{"web": "running"},
		}
		status.Allocations = []*NomadAllocation{allocation}
		
		c.logger.Info("Mock job transitioned to running",
			zap.String("job_id", jobID))
	}
}

// MockConsulClient provides a mock Consul client
type MockConsulClient struct {
	logger   *zap.Logger
	kvStore  map[string]string
	services map[string]*ConsulService
}

// NewMockConsulClient creates a new mock Consul client
func NewMockConsulClient(logger *zap.Logger) *MockConsulClient {
	return &MockConsulClient{
		logger:   logger,
		kvStore:  make(map[string]string),
		services: make(map[string]*ConsulService),
	}
}

// GetKV gets a key-value pair from Consul
func (c *MockConsulClient) GetKV(ctx context.Context, key string) (string, error) {
	value, exists := c.kvStore[key]
	if !exists {
		return "", fmt.Errorf("key not found: %s", key)
	}
	return value, nil
}

// PutKV stores a key-value pair in Consul
func (c *MockConsulClient) PutKV(ctx context.Context, key, value string) error {
	c.kvStore[key] = value
	c.logger.Debug("Mock Consul KV stored",
		zap.String("key", key),
		zap.String("value", value))
	return nil
}

// DeleteKV deletes a key from Consul
func (c *MockConsulClient) DeleteKV(ctx context.Context, key string) error {
	delete(c.kvStore, key)
	c.logger.Debug("Mock Consul KV deleted",
		zap.String("key", key))
	return nil
}

// RegisterService registers a service with Consul
func (c *MockConsulClient) RegisterService(ctx context.Context, service *ConsulService) error {
	c.services[service.ID] = service
	c.logger.Info("Mock Consul service registered",
		zap.String("service_id", service.ID),
		zap.String("service_name", service.Name))
	return nil
}

// DeregisterService deregisters a service from Consul
func (c *MockConsulClient) DeregisterService(ctx context.Context, serviceID string) error {
	delete(c.services, serviceID)
	c.logger.Info("Mock Consul service deregistered",
		zap.String("service_id", serviceID))
	return nil
}

// extractJobName extracts job name from Nomad job specification
func extractJobName(jobSpec string) string {
	lines := strings.Split(jobSpec, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "job ") {
			// Extract job name between quotes
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[1]
				name = strings.Trim(name, `"`)
				return name
			}
		}
	}
	return ""
}

// RealBuildClient provides real implementations for production use
type RealBuildClient struct {
	logger *zap.Logger
}

// NewRealBuildClient creates a new real build client
func NewRealBuildClient(logger *zap.Logger) *RealBuildClient {
	return &RealBuildClient{
		logger: logger,
	}
}

// BuildHugo builds a Hugo site
func (c *RealBuildClient) BuildHugo(ctx context.Context, config HugoConfig) (*BuildResult, error) {
	start := time.Now()
	
	c.logger.Info("Starting Hugo build",
		zap.String("environment", config.Environment),
		zap.Bool("minify", config.Minify))

	// Build Hugo command
	args := []string{"--environment", config.Environment}
	if config.Minify {
		args = append(args, "--minify")
	}
	if config.OutputDir != "" {
		args = append(args, "--destination", config.OutputDir)
	}
	if config.ConfigFile != "" {
		args = append(args, "--config", config.ConfigFile)
	}
	if config.BaseURL != "" {
		args = append(args, "--baseURL", config.BaseURL)
	}

	cmd := exec.CommandContext(ctx, "hugo", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &BuildResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Hugo build failed: %v\nOutput: %s", err, string(output)),
		}, fmt.Errorf("hugo build failed: %w", err)
	}

	// Create build result
	artifacts := []ArtifactInfo{
		{
			Name:      "hugo-site",
			Type:      "file",
			Location:  config.OutputDir,
			CreatedAt: time.Now(),
		},
	}

	logs := []LogEntry{
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   string(output),
			Source:    "hugo",
			Stage:     "build",
		},
	}

	result := &BuildResult{
		Success:   true,
		Artifacts: artifacts,
		Logs:      logs,
		Duration:  time.Since(start),
		Metadata:  map[string]string{"environment": config.Environment},
	}

	c.logger.Info("Hugo build completed",
		zap.Duration("duration", result.Duration))

	return result, nil
}

// BuildDockerImage builds a Docker image
func (c *RealBuildClient) BuildDockerImage(ctx context.Context, config BuildConfig) (*BuildResult, error) {
	start := time.Now()

	imageTag := fmt.Sprintf("%s/%s:latest", config.Registry, config.Image)
	
	c.logger.Info("Starting Docker build",
		zap.String("image", imageTag),
		zap.String("dockerfile", config.DockerFile))

	// Build Docker command
	args := []string{"build", "-t", imageTag}
	if config.DockerFile != "" {
		args = append(args, "-f", config.DockerFile)
	}
	for key, value := range config.Args {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}
	args = append(args, config.Context)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &BuildResult{
			Success:  false,
			Duration: time.Since(start),
			Error:    fmt.Sprintf("Docker build failed: %v\nOutput: %s", err, string(output)),
		}, fmt.Errorf("docker build failed: %w", err)
	}

	artifacts := []ArtifactInfo{
		{
			Name:      "docker-image",
			Type:      "docker_image",
			Location:  imageTag,
			CreatedAt: time.Now(),
		},
	}

	logs := []LogEntry{
		{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   string(output),
			Source:    "docker",
			Stage:     "build",
		},
	}

	result := &BuildResult{
		Success:   true,
		Artifacts: artifacts,
		Logs:      logs,
		Duration:  time.Since(start),
		Metadata:  map[string]string{"image": imageTag},
	}

	return result, nil
}

// PushDockerImage pushes a Docker image to registry
func (c *RealBuildClient) PushDockerImage(ctx context.Context, image, registry string) error {
	c.logger.Info("Pushing Docker image",
		zap.String("image", image),
		zap.String("registry", registry))

	cmd := exec.CommandContext(ctx, "docker", "push", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.logger.Error("Docker push failed",
			zap.String("image", image),
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("docker push failed: %w", err)
	}

	c.logger.Info("Docker image pushed successfully",
		zap.String("image", image))

	return nil
}

// RunInfrastructureTests runs infrastructure tests
func (c *RealBuildClient) RunInfrastructureTests(ctx context.Context, config *PipelineConfig) error {
	c.logger.Info("Running infrastructure tests",
		zap.String("pipeline", config.AppName))

	// This would implement actual infrastructure testing
	// For now, just simulate success
	time.Sleep(2 * time.Second)

	c.logger.Info("Infrastructure tests completed",
		zap.String("pipeline", config.AppName))

	return nil
}