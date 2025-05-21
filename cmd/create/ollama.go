// cmd/create/ollama.go
package create

import (
	"errors"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ollama"
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

		if _, err := execute.RunShell("docker info > /dev/null 2>&1"); err != nil {
			return fmt.Errorf("❌ Docker is not running. Start Docker Desktop and try again: %w", err)
		}

		if err := ollama.EnsureInstalled(log); err != nil {
			return err
		}

		home := os.Getenv("HOME")
		ollamaDir := fmt.Sprintf("%s/.ollama", home)
		if err := os.MkdirAll(ollamaDir, 0755); err != nil {
			return fmt.Errorf("failed to create config dir: %w", err)
		}

		serveLog := fmt.Sprintf("%s/serve.log", ollamaDir)
		if err := ollama.StartServeProcess(log, serveLog); err != nil {
			log.Warn("⚠️ Ollama serve may not be running", zap.Error(err))
		}

		containerName, _ := cmd.Flags().GetString("container-name")
		port, _ := cmd.Flags().GetInt("port")
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %d", port)
		}
		// Remove stale container
		out, err := execute.RunShell("docker rm -f " + containerName)
		if err != nil {
			log.Warn("⚠️ Failed to remove container", zap.Error(err), zap.String("output", out))
		}

		if err := ollama.RunWebUI(log, containerName, port, ollamaDir); err != nil {
			return err
		}

		// GPU Export
		noGPU, _ := cmd.Flags().GetBool("no-gpu")
		if !noGPU {
			rcPath := platform.GetShellInitFile()
			if _, err := os.Stat(rcPath); os.IsNotExist(err) {
				_ = os.WriteFile(rcPath, []byte{}, 0644)
			}
			if err := parse.AppendIfMissing(rcPath, "export OLLAMA_USE_GPU=true"); err != nil {
				return fmt.Errorf("failed to write GPU config: %w", err)
			}
			log.Info("✅ GPU support enabled in shell config")
			log.Info("🔁 Run `source " + rcPath + "` to apply changes")
		}

		return nil
	}),
}

func init() {
	CreateOllamaCmd.Flags().IntP("port", "p", 3000, "Local port to expose Ollama Web UI")
	CreateOllamaCmd.Flags().String("container-name", "ollama-webui", "Docker container name to use")
	CreateOllamaCmd.Flags().Bool("no-gpu", false, "Skip GPU environment setup")
	CreateCmd.AddCommand(CreateOllamaCmd)
}
