// pkg/docker/pull_progress.go
//
// Real Docker image pull progress tracking using Docker SDK
// Parses actual pull events and shows accurate progress

package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/progress"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PullProgress represents the progress of a Docker image pull
type PullProgress struct {
	ID             string `json:"id"`       // Layer ID
	Status         string `json:"status"`   // Status message
	Progress       string `json:"progress"` // Progress bar string
	ProgressDetail struct {
		Current int64 `json:"current"` // Bytes downloaded
		Total   int64 `json:"total"`   // Total bytes
	} `json:"progressDetail"`
}

// LayerProgress tracks progress of a single layer
type LayerProgress struct {
	ID       string
	Status   string
	Current  int64
	Total    int64
	Complete bool
}

// PullTracker tracks overall pull progress across multiple layers
type PullTracker struct {
	layers map[string]*LayerProgress
	visual *progress.VisualOperation
	logger otelzap.LoggerWithCtx
}

// NewPullTracker creates a pull progress tracker
func NewPullTracker(ctx context.Context, imageName string) *PullTracker {
	return &PullTracker{
		layers: make(map[string]*LayerProgress),
		visual: progress.NewVisual(ctx, fmt.Sprintf("Pulling %s", imageName), "varies by size"),
		logger: otelzap.Ctx(ctx),
	}
}

// Start begins tracking pull progress
func (pt *PullTracker) Start() {
	pt.visual.Start()
}

// Update processes a pull progress event
func (pt *PullTracker) Update(event *PullProgress) {
	if event.ID == "" {
		// Status messages without layer ID
		pt.visual.UpdateStage(event.Status)
		return
	}

	// Track layer progress
	layer, exists := pt.layers[event.ID]
	if !exists {
		layer = &LayerProgress{
			ID: event.ID,
		}
		pt.layers[event.ID] = layer
	}

	layer.Status = event.Status
	layer.Current = event.ProgressDetail.Current
	layer.Total = event.ProgressDetail.Total

	// Mark as complete for certain statuses
	if strings.Contains(event.Status, "Pull complete") ||
		strings.Contains(event.Status, "Already exists") {
		layer.Complete = true
	}

	// Update visual stage with summary
	summary := pt.getSummary()
	pt.visual.UpdateStage(summary)
}

// getSummary returns a human-readable summary of pull progress
func (pt *PullTracker) getSummary() string {
	totalLayers := len(pt.layers)
	completeLayers := 0
	var totalBytes int64
	var downloadedBytes int64

	for _, layer := range pt.layers {
		if layer.Complete {
			completeLayers++
		}
		totalBytes += layer.Total
		downloadedBytes += layer.Current
	}

	if totalLayers == 0 {
		return "starting pull"
	}

	// Calculate overall progress percentage
	var percent float64
	if totalBytes > 0 {
		percent = float64(downloadedBytes) / float64(totalBytes) * 100
	}

	return fmt.Sprintf("%d/%d layers (%.1f%% complete)", completeLayers, totalLayers, percent)
}

// Done marks pull as complete
func (pt *PullTracker) Done() {
	pt.visual.Done()
}

// Fail marks pull as failed
func (pt *PullTracker) Fail(err error) {
	pt.visual.Fail(err)
}

// PullImageWithProgress pulls a Docker image and shows real progress
func PullImageWithProgress(rc *eos_io.RuntimeContext, imageName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Connect to Docker
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer func() {
		if closeErr := cli.Close(); closeErr != nil {
			logger.Warn("Failed to close Docker client", zap.Error(closeErr))
		}
	}()

	// Start pull with progress tracking
	tracker := NewPullTracker(rc.Ctx, imageName)
	tracker.Start()

	// Pull image
	reader, err := cli.ImagePull(rc.Ctx, imageName, image.PullOptions{})
	if err != nil {
		tracker.Fail(err)
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()

	// Parse progress events
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var event PullProgress
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			logger.Warn("Failed to parse pull progress", zap.Error(err))
			continue
		}

		tracker.Update(&event)

		// Log errors from Docker
		if strings.Contains(strings.ToLower(event.Status), "error") {
			logger.Error("Docker pull error", zap.String("status", event.Status))
		}
	}

	if err := scanner.Err(); err != nil {
		tracker.Fail(err)
		return fmt.Errorf("error reading pull progress: %w", err)
	}

	tracker.Done()
	return nil
}

// PullComposeImagesWithProgress pulls all images from a docker-compose file
// Returns actual download progress by parsing Docker events
func PullComposeImagesWithProgress(rc *eos_io.RuntimeContext, composeFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Docker Compose image pull with real progress tracking",
		zap.String("compose_file", composeFile))

	// NOTE: For docker-compose, we need to run the shell command but capture output
	// The Docker SDK doesn't have native compose support yet
	// So we'll use a hybrid approach: shell command + output parsing

	return pullComposeWithOutputParsing(rc, composeFile)
}

// pullComposeWithOutputParsing extracts images from compose file and pulls each individually
func pullComposeWithOutputParsing(rc *eos_io.RuntimeContext, composeFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Step 1: Extract images from compose file
	images, err := getComposeImages(rc, composeFile)
	if err != nil {
		return fmt.Errorf("failed to get images from compose file: %w", err)
	}

	if len(images) == 0 {
		logger.Info("No images found in compose file")
		return nil
	}

	logger.Info("Will pull images from compose file",
		zap.Int("count", len(images)))

	// Step 2: Pull each image individually with real progress tracking
	for i, imageName := range images {
		logger.Info(fmt.Sprintf("Pulling image %d/%d", i+1, len(images)),
			zap.String("image", imageName))

		if err := PullImageWithProgress(rc, imageName); err != nil {
			// Don't fail completely - some images might already exist locally
			logger.Warn("Failed to pull image, continuing with next",
				zap.String("image", imageName),
				zap.Error(err))
			continue
		}
	}

	logger.Info("Completed pulling all compose images",
		zap.Int("total", len(images)))

	return nil
}

// getComposeImages extracts the list of images from a docker-compose file
func getComposeImages(rc *eos_io.RuntimeContext, composeFile string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Extracting images from compose file",
		zap.String("compose_file", composeFile))

	// Run docker compose config --images to get list of images
	cmd := exec.CommandContext(rc.Ctx, "docker", "compose", "-f", composeFile, "config", "--images")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from compose file: %w\nOutput: %s", err, string(output))
	}

	// Parse output - one image per line
	var images []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			images = append(images, line)
			logger.Debug("Found image in compose file", zap.String("image", line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing compose images: %w", err)
	}

	logger.Info("Extracted images from compose file",
		zap.Int("count", len(images)),
		zap.Strings("images", images))

	return images, nil
}
