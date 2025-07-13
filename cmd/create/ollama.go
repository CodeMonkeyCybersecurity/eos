// cmd/create/ollama.go
package create

import (
	"errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ollama"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	cerr "github.com/cockroachdb/errors"
)

var CreateOllamaCmd = &cobra.Command{
	Use:   "ollama",
	Short: "Install Ollama and Web UI on macOS with GPU support",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		if !platform.IsMacOS() {
			return errors.New(" this command is only supported on macOS")
		}

		if err := container.CheckRunning(rc); err != nil {
			log.Warn("Docker not running", zap.Error(err))
			return cerr.WithHint(err, "Please start Docker Desktop before running this command")
		}

		// First ensure Ollama is installed
		if err := ollama.EnsureInstalled(rc); err != nil {
			return err
		}

		// Get configuration from flags
		containerName, _ := cmd.Flags().GetString("container-name")
		port, _ := cmd.Flags().GetInt("port")
		noGPU, _ := cmd.Flags().GetBool("no-gpu")

		// Setup Ollama with all the business logic encapsulated
		config := ollama.SetupConfig{
			ContainerName: containerName,
			Port:          port,
			NoGPU:         noGPU,
		}
		
		if err := ollama.SetupOllama(rc, config); err != nil {
			return err
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
