// cmd/delphi/deploy/docker-listener.go
package deploy

import (
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// delphiListenerCmd represents the "github.com/CodeMonkeyCybersecurity/eos delphi install docker-listener" command
var DockerListenerCmd = &cobra.Command{
	Use:   "docker-listener",
	Short: "Installs and configures the Delphi DockerListener for Wazuh",
	Long:  `This command sets up a Python virtual environment and configures the Wazuh DockerListener to use it.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger, _ := zap.NewProduction()
		defer logger.Sync()
		sugar := logger.Sugar()

		sugar.Infof("🚀 Setting up Delphi DockerListener...")

		// Step 1: Install required system packages
		sugar.Infof("🔧 Installing Python virtual environment tools...")
		if err := execute.Execute("sudo", "apt", "update"); err != nil {
			sugar.Fatalf("❌ Failed to update package lists: %v", err)
		}

		if err := execute.Execute("sudo", "apt", "install", "-y", "python3-venv", "python3-pip"); err != nil {
			sugar.Fatalf("❌ Failed to install required Python packages: %v", err)
		}

		// Step 2: Create virtual environment
		sugar.Infof("📂 Creating virtual environment at %s", types.VenvPath)
		if err := execute.Execute("sudo", "mkdir", "-p", types.VenvPath); err != nil {
			sugar.Fatalf("❌ Failed to create virtual environment directory: %v", err)
		}

		if err := execute.Execute("sudo", "python3", "-m", "venv", types.VenvPath); err != nil {
			sugar.Fatalf("❌ Failed to create virtual environment: %v", err)
		}

		// Step 3: Install required Python packages
		sugar.Infof("📦 Installing Python dependencies in virtual environment...")
		if err := execute.Execute(types.VenvPath+"/bin/pip", "install", "docker==7.1.0", "urllib3==1.26.20", "requests==2.32.2"); err != nil {
			sugar.Fatalf("❌ Failed to install Python dependencies: %v", err)
		}

		// Step 4: Update Wazuh DockerListener script
		sugar.Infof("✏️  Updating DockerListener shebang...")
		if _, err := os.Stat(types.DockerListener); os.IsNotExist(err) {
			sugar.Warn("⚠️  Warning: DockerListener script not found at %s", types.DockerListener)
		} else {
			// Backup the original script
			backupPath := types.DockerListener + ".bak"
			execute.Execute("sudo", "cp", types.DockerListener, backupPath)

			// Modify shebang
			shebang := "#!" + types.VenvPath + "/bin/python3\n"
			content, _ := os.ReadFile(types.DockerListener)
			newContent := shebang + strings.Join(strings.Split(string(content), "\n")[1:], "\n")

			// Write back the modified file
			if err := os.WriteFile(types.DockerListener, []byte(newContent), xdg.DirPermStandard); err != nil {
				sugar.Fatalf("❌ Failed to update DockerListener script: %v", err)
			}
			sugar.Infof("✅ DockerListener script updated successfully")
		}

		// Step 5: Restart Wazuh Agent
		sugar.Infof("🔄 Restarting Wazuh Agent...")
		if err := execute.Execute("sudo", "systemctl", "restart", "wazuh-agent"); err != nil {
			sugar.Fatalf("❌ Failed to restart Wazuh Agent: %v", err)
		}
		return nil
	}),
}
