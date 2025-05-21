// pkg/ollama/lifecycle.go

package ollama

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
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

func RunWebUI(log *zap.Logger, containerName string, port int, volume string) error {
	runCmd := fmt.Sprintf("docker run -d --name %s -p %d:3000 -v %s:/root/.ollama ghcr.io/ollama-webui/ollama-webui:main", containerName, port, volume)

	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := execute.RunShell(runCmd); err == nil {
			log.Info("🌐 Ollama Web UI running at http://localhost:" + fmt.Sprint(port))
			return nil
		} else if attempt == 3 {
			return fmt.Errorf("failed to start Web UI after 3 attempts: %w", err)
		}
		log.Warn("Retrying Web UI launch", zap.Int("attempt", attempt))
		time.Sleep(2 * time.Second)
	}
	return nil // unreachable
}
