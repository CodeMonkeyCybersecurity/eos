// pkg/ollama/lifecycle.go

package ollama

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

func EnsureInstalled(rc *eos_io.RuntimeContext) error {
	if !platform.IsCommandAvailable("ollama") {
		zap.L().Info(" Installing Ollama via Homebrew")
		_, err := execute.RunShell(rc.Ctx, "brew install ollama")
		if err != nil {
			return fmt.Errorf("failed to install Ollama: %w", err)
		}
		zap.L().Info(" Ollama installed")
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
		zap.L().Info(" Starting Ollama serve process")
		_ = StartServeProcess(rc, serveLogPath)
	}

	return nil
}

func StartServeProcess(rc *eos_io.RuntimeContext, serveLog string) error {
	cmd := fmt.Sprintf("nohup ollama serve > %s 2>&1 &", serveLog)
	_, err := execute.RunShell(rc.Ctx, cmd)
	if err != nil {
		zap.L().Warn("Ollama serve may not have started", zap.Error(err))
	}
	zap.L().Info("🔍 Ollama logs: " + serveLog)
	return nil
}

func RunWebUI(rc *eos_io.RuntimeContext, cfg WebUIConfig) error {

	// Check if container is already running
	inspectRunning := []string{"inspect", "-f", "{{.State.Running}}", cfg.Container}
	output, err := execute.Run(rc.Ctx, execute.Options{

		Command: "docker",
		Args:    inspectRunning,
	})

	if isWebUIContainerRunningOnPort3000(rc) {
		zap.L().Info(" OpenWebUI is already active — skipping container start")
		_ = platform.OpenBrowser("http://localhost:3000")
		return nil
	}

	if err == nil && strings.TrimSpace(output) == "true" {
		zap.L().Info("🔁 Web UI container already running")
		return nil
	}

	const image = "ghcr.io/open-webui/open-webui:main"
	runArgs := []string{
		"run", "-d", "--name", cfg.Container,
		"-p", fmt.Sprintf("%d:8080", cfg.Port),
		"--add-host=host.container.internal:host-gateway",
		"-v", "open-webui:/app/backend/data",
		"--restart", "always",
		image,
	}

	zap.L().With(
		zap.String("container", cfg.Container),
		zap.Int("port", cfg.Port),
		zap.String("volume", "open-webui"),
	)

	zap.L().Info("📥 Inspecting local image cache", zap.String("image", image))
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"inspect", "--type=image", image},
	})
	if err != nil {
		zap.L().Warn(" Image not found locally, pulling", zap.String("image", image))
		_, pullErr := execute.Run(rc.Ctx, execute.Options{

			Command: "docker",
			Args:    []string{"pull", "--disable-content-trust=1", image},
		})
		if pullErr != nil {
			zap.L().Error(" Failed to pull Web UI image", zap.Error(pullErr))
			if cerr.HasType(pullErr, &exec.ExitError{}) && pullErr.Error() == "exit status 127" {
				return cerr.WithHint(pullErr, "Check if `docker-credential-desktop` is missing from your $PATH")
			}
			return cerr.WithHint(pullErr, "Unable to pull Web UI image")
		}
		zap.L().Info(" Image pulled successfully")
	}

	zap.L().Info(" Launching Web UI container")
	_, runErr := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    runArgs,
	})
	if runErr != nil {
		zap.L().Error(" Web UI launch failed", zap.Error(runErr))
		return cerr.WithHint(runErr, "Docker container failed to start")
	}

	if !waitForBackend(rc, "http://host.container.internal:11434", 15*time.Second) {
		return cerr.New("Ollama backend is not reachable — the Web UI may fail to connect")
	}

	zap.L().Info(" Web UI container started")
	_ = platform.OpenBrowser("http://localhost:3000")

	return nil
}

func waitForBackend(rc *eos_io.RuntimeContext, url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	triedServe := false

	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(rc.Ctx, "GET", url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			zap.L().Info(" Ollama backend reachable", zap.String("url", url))
			return true
		}

		if !triedServe {
			zap.L().Warn("🔁 Backend not reachable — attempting to start `ollama serve`")
			home, err := os.UserHomeDir()
			if err == nil {
				logPath := filepath.Join(home, ".ollama", "serve.log")
				_ = StartServeProcess(rc, logPath)
				triedServe = true
			} else {
				zap.L().Warn(" Could not resolve user home directory to start serve", zap.Error(err))
			}
		}

		time.Sleep(2 * time.Second)
	}

	zap.L().Warn("Ollama backend did not become available in time", zap.String("url", url))
	return false
}
