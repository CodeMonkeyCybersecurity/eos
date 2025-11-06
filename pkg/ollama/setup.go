package ollama

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupConfig holds the configuration for Ollama setup
type SetupConfig struct {
	ContainerName string
	Port          int
	NoGPU         bool
}

// SetupOllama orchestrates the complete Ollama setup following Assess → Intervene → Evaluate pattern
func SetupOllama(rc *eos_io.RuntimeContext, config SetupConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Ollama setup requirements")

	// Validate port
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}

	// Create Ollama directory
	home := os.Getenv("HOME")
	if home == "" {
		return fmt.Errorf("HOME environment variable not set")
	}

	ollamaDir := fmt.Sprintf("%s/.ollama", home)

	// INTERVENE
	logger.Info("Setting up Ollama",
		zap.String("directory", ollamaDir),
		zap.String("container", config.ContainerName),
		zap.Int("port", config.Port))

	// Create config directory
	if err := os.MkdirAll(ollamaDir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	// Start Ollama serve process
	serveLog := fmt.Sprintf("%s/serve.log", ollamaDir)
	if err := StartServeProcess(rc, serveLog); err != nil {
		logger.Warn("Ollama serve may not be running", zap.Error(err))
	}

	// Remove any existing container
	if err := RemoveContainer(rc, config.ContainerName); err != nil {
		logger.Debug("Container removal failed (may not exist)", zap.Error(err))
	}

	// Run Web UI
	webUIConfig := WebUIConfig{
		Container: config.ContainerName,
		Port:      config.Port,
		Volume:    ollamaDir,
	}

	if err := RunWebUI(rc, webUIConfig); err != nil {
		return fmt.Errorf("failed to run Web UI: %w", err)
	}

	// Configure GPU support if requested
	if !config.NoGPU {
		if err := EnableGPUSupport(rc); err != nil {
			return fmt.Errorf("failed to enable GPU support: %w", err)
		}
	}

	// EVALUATE
	logger.Info("Evaluating Ollama setup")

	// Verify container is running
	if err := VerifyContainerRunning(rc, config.ContainerName); err != nil {
		return fmt.Errorf("container verification failed: %w", err)
	}

	logger.Info("Ollama setup completed successfully",
		zap.String("container", config.ContainerName),
		zap.Int("port", config.Port),
		zap.Bool("gpu_enabled", !config.NoGPU))

	return nil
}

// RemoveContainer removes an existing Docker container
func RemoveContainer(rc *eos_io.RuntimeContext, containerName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Debug("Checking for existing container", zap.String("container", containerName))

	// INTERVENE
	logger.Info("Removing container if exists", zap.String("container", containerName))
	err := execute.RunSimple(rc.Ctx, "docker", "rm", "-f", containerName)

	// EVALUATE
	if err != nil {
		// Container might not exist, which is fine
		logger.Debug("Container removal completed (container may not have existed)",
			zap.String("container", containerName),
			zap.Error(err))
		return nil
	}

	logger.Info("Container removed successfully", zap.String("container", containerName))
	return nil
}

// EnableGPUSupport configures GPU support for Ollama
func EnableGPUSupport(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing GPU support configuration")

	rcPath := platform.GetShellInitFile()
	if rcPath == "" {
		return fmt.Errorf("could not determine shell init file")
	}

	// INTERVENE
	logger.Info("Enabling GPU support", zap.String("config_file", rcPath))

	// Create file if it doesn't exist
	if _, err := os.Stat(rcPath); os.IsNotExist(err) {
		if err := os.WriteFile(rcPath, []byte{}, 0644); err != nil {
			return fmt.Errorf("failed to create shell config file: %w", err)
		}
	}

	// Add GPU export
	if err := parse.AppendIfMissing(rcPath, "export OLLAMA_USE_GPU=true"); err != nil {
		return fmt.Errorf("failed to write GPU config: %w", err)
	}

	// EVALUATE
	logger.Info("GPU support enabled successfully",
		zap.String("config_file", rcPath),
		zap.String("next_step", "Run 'source "+rcPath+"' to apply changes"))

	return nil
}

// VerifyContainerRunning checks if the Ollama container is running
func VerifyContainerRunning(rc *eos_io.RuntimeContext, containerName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Verifying container status", zap.String("container", containerName))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Status}}"},
	})
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}

	if output == "" {
		return fmt.Errorf("container %s is not running", containerName)
	}

	logger.Debug("Container is running",
		zap.String("container", containerName),
		zap.String("status", output))

	return nil
}
