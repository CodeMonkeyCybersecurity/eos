// cmd/read/ollama.go

package read

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
)

var InspectOllamaCmd = &cobra.Command{
	Use:   "ollama",
	Short: "Inspect Ollama setup (container status, GPU usage, and logs)",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Logger()

		if !platform.IsMacOS() {
			return fmt.Errorf("❌ Ollama inspection is only supported on macOS")
		}

		log.Info("🔍 Inspecting Docker container for Ollama Web UI...")
		out, err := execute.RunShell("docker ps --filter name=ollama-webui")
		if err != nil {
			return fmt.Errorf("failed to inspect container: %w", err)
		}
		fmt.Println("\n🧱 Ollama Web UI Container:\n" + out)

		log.Info("🧠 Checking OLLAMA_USE_GPU environment variable...")
		env := os.Getenv("OLLAMA_USE_GPU")
		if env == "true" {
			fmt.Println("✅ GPU is ENABLED (OLLAMA_USE_GPU=true)")
		} else {
			fmt.Println("⚠️ GPU is DISABLED or not configured (OLLAMA_USE_GPU=" + env + ")")
		}

		logFile := "/tmp/ollama.log"
		fmt.Println("\n📜 Last 20 lines of Ollama log:")
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			fmt.Println("🚫 Ollama log not found at", logFile)
		} else {
			logOut, _ := execute.RunShell("tail -n 20 " + logFile)
			fmt.Println(logOut)
		}

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectOllamaCmd)
}
