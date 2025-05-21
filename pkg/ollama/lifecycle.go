// pkg/ollama/lifecycle.go

package ollama

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home dir: %w", err)
	}
	ollamaDir := filepath.Join(home, ".ollama")
	serveLogPath := filepath.Join(ollamaDir, "serve.log")

	if err := os.MkdirAll(ollamaDir, 0755); err != nil {
		return fmt.Errorf("failed to create ollama config dir: %w", err)
	}

	// Always ensure `ollama serve` is running
	if !platform.IsProcessRunning("ollama serve") {
		log.Info("🚀 Starting Ollama serve process")
		_ = StartServeProcess(log, serveLogPath)
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

	// Check if container is already running
	inspectRunning := []string{"inspect", "-f", "{{.State.Running}}", cfg.Container}
	output, err := execute.Run(execute.Options{
		Ctx:     ctx,
		Command: "docker",
		Args:    inspectRunning,
	})

	if isWebUIContainerRunningOnPort3000() {
		log.Info("✅ OpenWebUI is already active — skipping container start")
		return nil
	}

	if err == nil && strings.TrimSpace(output) == "true" {
		log.Info("🔁 Web UI container already running")
		return nil
	}

	const image = "ghcr.io/open-webui/open-webui:main"
	runArgs := []string{
		"run", "-d", "--name", cfg.Container,
		"-p", fmt.Sprintf("%d:8080", cfg.Port),
		"--add-host=host.docker.internal:host-gateway",
		"-v", "open-webui:/app/backend/data",
		"--restart", "always",
		image,
	}

	log = log.With(
		zap.String("container", cfg.Container),
		zap.Int("port", cfg.Port),
		zap.String("volume", "open-webui"),
	)

	log.Info("📥 Inspecting local image cache", zap.String("image", image))
	_, err = execute.Run(execute.Options{
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

	log.Info("🚀 Launching Web UI container")
	_, runErr := execute.Run(execute.Options{
		Ctx:     ctx,
		Command: "docker",
		Args:    runArgs,
	})
	if runErr != nil {
		span.RecordError(runErr)
		log.Error("❌ Web UI launch failed", zap.Error(runErr))
		return cerr.WithHint(runErr, "Docker container failed to start")
	}

	log.Info("✅ Web UI container started")

	if !waitForBackend(ctx, log, "http://host.docker.internal:11434", 15*time.Second) {
		return cerr.New("Ollama backend is not reachable — the Web UI may fail to connect")
	}
	return nil
}

func waitForBackend(ctx context.Context, log *zap.Logger, url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	triedServe := false

	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			log.Info("✅ Ollama backend reachable", zap.String("url", url))
			return true
		}

		if !triedServe {
			log.Warn("🔁 Backend not reachable — attempting to start `ollama serve`")
			home, err := os.UserHomeDir()
			if err == nil {
				logPath := filepath.Join(home, ".ollama", "serve.log")
				_ = StartServeProcess(log, logPath)
				triedServe = true
			} else {
				log.Warn("❌ Could not resolve user home directory to start serve", zap.Error(err))
			}
		}

		time.Sleep(2 * time.Second)
	}

	log.Warn("⚠️ Ollama backend did not become available in time", zap.String("url", url))
	return false
}
