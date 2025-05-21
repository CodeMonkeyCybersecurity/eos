// cmd/create/ollama.go
package create

import (
	"errors"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateOllamaCmd = &cobra.Command{
	Use:   "ollama",
	Short: "Install Ollama and Web UI on macOS with GPU support",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Logger()

		if !platform.IsMacOS() {
			return errors.New("❌ this command is only supported on macOS")
		}
		log.Info("🍏 macOS detected")

		// Install Ollama via Homebrew
		if !platform.IsCommandAvailable("ollama") {
			log.Info("📦 Installing Ollama via Homebrew")
			if _, err := execute.RunShell("brew install ollama"); err != nil {
				return fmt.Errorf("failed to install ollama: %w", err)
			}
		} else {
			log.Info("✅ Ollama already installed")
		}

		// Start Ollama (non-blocking or recommend manual)
		log.Info("🚀 Starting Ollama service (best effort)")
		_, err := execute.RunShell("ollama serve > /tmp/ollama.log 2>&1 &")
		if err != nil {
			log.Warn("⚠️ Could not start Ollama service", zap.Error(err))
		}

		// Clean up stale container if exists
		_, _ = execute.RunShell("docker rm -f ollama-webui || true")

		// Start Web UI
		log.Info("🌐 Starting Ollama Web UI in Docker")
		runCmd := fmt.Sprintf("docker run -d --name ollama-webui -p 3000:3000 -v %s/.ollama:/root/.ollama ghcr.io/ollama-webui/ollama-webui:main", os.Getenv("HOME"))
		if _, err := execute.RunShell(runCmd); err != nil {
			return fmt.Errorf("failed to launch Ollama Web UI: %w", err)
		}

		// GPU environment setup
		rcPath := platform.GetShellInitFile()
		line := "export OLLAMA_USE_GPU=true"
		log.Info("⚙️ Enabling GPU usage in: " + rcPath)

		if err := parse.AppendIfMissing(rcPath, line); err != nil {
			return fmt.Errorf("failed to write GPU export line: %w", err)
		}

		log.Info("✅ Ollama setup complete")
		log.Info("🔁 Visit http://localhost:3000 and run `source " + rcPath + "` to apply changes")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateOllamaCmd)
}
