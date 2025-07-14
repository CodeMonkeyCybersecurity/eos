// cmd/read/ollama.go

package read

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var InspectOllamaCmd = &cobra.Command{
	Use:   "ollama",
	Short: "Inspect Ollama setup (container status, GPU usage, and logs)",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		if !platform.IsMacOS() {
			return fmt.Errorf(" Ollama inspection is only supported on macOS")
		}

		log.Info(" Inspecting Docker container for Ollama Web UI...")
		out, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"ps", "--filter", "name=ollama-webui"},
		})
		if err != nil {
			return fmt.Errorf("failed to inspect container: %w", err)
		}
		log.Info("terminal prompt: \n🧱 Ollama Web UI Container:\n" + out)

		log.Info("🧠 Checking OLLAMA_USE_GPU environment variable...")
		env := os.Getenv("OLLAMA_USE_GPU")
		if env == "true" {
			log.Info("terminal prompt:  GPU is ENABLED (OLLAMA_USE_GPU=true)")
		} else {
			log.Info("terminal prompt: GPU is DISABLED or not configured (OLLAMA_USE_GPU=" + env + ")")
		}

		logFile := "/tmp/ollama.log"
		log.Info("terminal prompt: \n Last 20 lines of Ollama log:")
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			log.Info("terminal prompt:  Ollama log not found at " + logFile)
		} else {
			logOut, _ := execute.Run(rc.Ctx, execute.Options{
				Command: "tail",
				Args:    []string{"-n", "20", logFile},
			})
			log.Info("terminal prompt: " + logOut)
		}

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectOllamaCmd)
}
