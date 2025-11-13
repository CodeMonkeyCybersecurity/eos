package terraform

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// GenerateGraph provisions a new Terraform graph visualization
func GenerateGraph(rc *eos_io.RuntimeContext, config *GraphConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	span := trace.SpanFromContext(rc.Ctx)

	logger.Info("Starting Terraform graph generation",
		zap.String("working_dir", config.WorkingDir),
		zap.String("output_format", config.OutputFormat),
		zap.String("output_file", config.OutputFile))

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", zap.Error(err))
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create manager
	manager, err := NewGraphManager(config)
	if err != nil {
		logger.Error("Failed to create Terraform graph manager", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Start status monitoring
	go func() {
		for status := range manager.GetStatusChannel() {
			if status.Success {
				logger.Info(status.Message,
					zap.String("step", status.Step),
					zap.Any("details", status.Details))
			} else {
				logger.Error(status.Message,
					zap.String("step", status.Step),
					zap.Any("details", status.Details))
			}
		}
	}()

	// Execute graph generation
	if err := manager.GenerateGraph(rc.Ctx); err != nil {
		logger.Error("Terraform graph generation failed", zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("graph generation failed: %w", err)
	}

	logger.Info("Terraform graph generation completed successfully",
		zap.String("output_file", config.OutputFile),
		zap.String("format", config.OutputFormat),
		zap.String("namespace", config.Namespace))

	return nil
}

// ReadGraph retrieves information about an existing graph
func ReadGraph(rc *eos_io.RuntimeContext, namespace string, outputFile string) (*GraphInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Reading Terraform graph information",
		zap.String("namespace", namespace),
		zap.String("output_file", outputFile))

	// Create manager with config for reading
	config := DefaultGraphConfig()
	config.Namespace = namespace
	config.OutputFile = outputFile

	manager, err := NewGraphManager(config)
	if err != nil {
		logger.Error("Failed to create manager for read operation", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Get graph information
	info, err := manager.GetGraphInfo(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get graph information", zap.Error(err))
		return nil, fmt.Errorf("failed to get graph info: %w", err)
	}

	logger.Info("Terraform graph information retrieved",
		zap.String("format", info.Format),
		zap.Int("nodes_count", info.NodesCount),
		zap.Int("edges_count", info.EdgesCount),
		zap.Int64("file_size", info.FileSize))

	return info, nil
}
