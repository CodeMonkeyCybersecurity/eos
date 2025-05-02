// cmd/delphi/deploy/docker-listener.go
package deploy

import (
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// delphiListenerCmd represents the "github.com/CodeMonkeyCybersecurity/eos delphi install docker-listener" command
var DockerListenerCmd = &cobra.Command{
	Use:   "docker-listener",
	Short: "Installs and configures the Delphi DockerListener for Wazuh",
	Long:  `This command sets up a Python virtual environment and configures the Wazuh DockerListener to use it.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {

		log.Info("🚀 Setting up Delphi DockerListener...")

		// Step 1: Install required system packages
		log.Info("🔧 Installing Python virtual environment tools...")
		if err := execute.Execute("apt", "update"); err != nil {
			log.Fatal("❌ Failed to update package lists", zap.Error(err))
		}

		if err := execute.Execute("apt", "install", "-y", "python3-venv", "python3-pip"); err != nil {
			log.Fatal("❌ Failed to install required Python packages", zap.Error(err))
		}

		// Step 2: Create virtual environment
		log.Info("📂 Creating virtual environment")
		if err := execute.Execute("mkdir", "-p", shared.VenvPath); err != nil {
			log.Fatal("❌ Failed to create virtual environment directory", zap.Error(err))
		}

		if err := execute.Execute("python3", "-m", "venv", shared.VenvPath); err != nil {
			log.Fatal("❌ Failed to create virtual environment", zap.Error(err))
		}

		// Step 3: Install required Python packages
		log.Info("📦 Installing Python dependencies in virtual environment...")
		if err := execute.Execute(shared.VenvPath+"/bin/pip", "install", "docker==7.1.0", "urllib3==1.26.20", "requests==2.32.2"); err != nil {
			log.Fatal("❌ Failed to install Python dependencies", zap.Error(err))
		}

		// Step 4: Update Wazuh DockerListener script
		log.Info("✏️  Updating DockerListener shebang...")
		if _, err := os.Stat(shared.DockerListener); os.IsNotExist(err) {
			log.Warn("⚠️  Warning: DockerListener script not found", zap.Error(err))
		} else {
			// Backup the original script
			backupPath := shared.DockerListener + ".bak"
			if err := execute.Execute("cp", shared.DockerListener, backupPath); err != nil {
				log.Warn("Failed to backup DockerListener", zap.Error(err))
			}

			// Modify shebang
			shebang := "#!" + shared.VenvPath + "/bin/python3\n"
			content, _ := os.ReadFile(shared.DockerListener)
			newContent := shebang + strings.Join(strings.Split(string(content), "\n")[1:], "\n")

			// Write back the modified file
			if err := os.WriteFile(shared.DockerListener, []byte(newContent), shared.DirPermStandard); err != nil {
				log.Fatal("❌ Failed to update DockerListener script", zap.Error(err))
			}
			log.Info("✅ DockerListener script updated successfully")
		}

		// Step 5: Restart Wazuh Agent
		log.Info("🔄 Restarting Wazuh Agent...")
		if err := execute.Execute("systemctl", "restart", "wazuh-agent"); err != nil {
			log.Fatal("❌ Failed to restart Wazuh Agent", zap.Error(err))
		}
		return nil
	}),
}
