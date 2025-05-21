// pkg/ollama/lifecycle.go

package ollama

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

func EnsureInstalled(log *zap.Logger) error {
	if !platform.IsCommandAvailable("ollama") {
		log.Info("📦 Installing Ollama via Homebrew")
		_, err := execute.RunShell("brew install ollama")
		if err != nil {
			return fmt.Errorf("failed to install Ollama: %w", err)
		}
		log.Info("✅ Ollama installed")
	}
	return nil
}

func StartServeProcess(log *zap.Logger, serveLog string) error {
	cmd := fmt.Sprintf("nohup ollama serve > %s 2>&1 &", serveLog)
	_, err := execute.RunShell(cmd)
	if err != nil {
		log.Warn("⚠️ Ollama serve may not have started", zap.Error(err))
	}
	log.Info("🔍 Ollama logs: " + serveLog)
	return nil
}

func RunWebUI(ctx context.Context, log *zap.Logger, cfg WebUIConfig) error {
	ctx, span := telemetry.StartSpan(ctx, "ollama.RunWebUI")
	defer span.End()

	const image = "ghcr.io/ollama-webui/ollama-webui:main"
	runArgs := []string{
		"run", "--rm", "--name", cfg.Container,
		"-p", fmt.Sprintf("%d:3000", cfg.Port),
		"-v", fmt.Sprintf("%s:/root/.ollama", cfg.Volume),
		image,
	}

	log = log.With(
		zap.String("container", cfg.Container),
		zap.Int("port", cfg.Port),
		zap.String("volume", cfg.Volume),
	)

	log.Info("📥 Inspecting local image cache", zap.String("image", image))
	_, err := execute.Run(execute.Options{
		Ctx:     ctx,
		Command: "docker",
		Args:    []string{"inspect", "--type=image", image},
	})
	if err != nil {
		log.Warn("📦 Image not found locally, pulling", zap.String("image", image))
		_, pullErr := execute.Run(execute.Options{
			Ctx:     ctx,
			Command: "docker",
			Args:    []string{"pull", "--disable-content-trust=1", image},
		})
		if pullErr != nil {
			span.RecordError(pullErr)
			log.Error("❌ Failed to pull Web UI image", zap.Error(pullErr))
			if cerr.HasType(pullErr, &exec.ExitError{}) && pullErr.Error() == "exit status 127" {
				return cerr.WithHint(pullErr, "Check if `docker-credential-desktop` is missing from your $PATH")
			}
			return cerr.WithHint(pullErr, "Unable to pull Web UI image")
		}
		log.Info("✅ Image pulled successfully")
	}

	// Step 2: Retry container launch
	maxRetries := 3
	for i := 1; i <= maxRetries; i++ {
		log.Info("🚀 Launching Web UI container", zap.Int("attempt", i))
		_, err := execute.Run(execute.Options{
			Ctx:     ctx,
			Command: "docker",
			Args:    runArgs,
		})
		if err == nil {
			log.Info("✅ Web UI started successfully")
			return nil
		}
		log.Warn("❌ Web UI launch failed", zap.Int("attempt", i), zap.Error(err))
		span.RecordError(err)
		time.Sleep(2 * time.Second)
	}

	return cerr.Newf("failed to start Web UI after %d attempts", maxRetries)
}
