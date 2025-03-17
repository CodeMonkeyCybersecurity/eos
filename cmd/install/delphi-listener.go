package install

import (
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// delphiListenerCmd represents the "eos install delphi-listener" command
var delphiListenerCmd = &cobra.Command{
	Use:   "delphi-listener",
	Short: "Installs and configures the Delphi DockerListener for Wazuh",
	Long:  `This command sets up a Python virtual environment and configures the Wazuh DockerListener to use it.`,
	Run: func(cmd *cobra.Command, args []string) {
		logger, _ := zap.NewProduction()
		defer logger.Sync()
		sugar := logger.Sugar()

		sugar.Info("🚀 Setting up Delphi DockerListener...")

		venvPath := "/opt/delphi_venv"
		dockerListener := "/var/ossec/wodles/docker/DockerListener"

		// Step 1: Install required system packages
		sugar.Info("🔧 Installing Python virtual environment tools...")
		if err := execute("sudo", "apt", "update"); err != nil {
			sugar.Fatal("❌ Failed to update package lists:", err)
		}

		if err := execute("sudo", "apt", "install", "-y", "python3-venv", "python3-pip"); err != nil {
			sugar.Fatal("❌ Failed to install required Python packages:", err)
		}

		// Step 2: Create virtual environment
		sugar.Info("📂 Creating virtual environment at", venvPath)
		if err := execute("sudo", "mkdir", "-p", venvPath); err != nil {
			sugar.Fatal("❌ Failed to create virtual environment directory:", err)
		}

		if err := execute("sudo", "python3", "-m", "venv", venvPath); err != nil {
			sugar.Fatal("❌ Failed to create virtual environment:", err)
		}

		// Step 3: Install required Python packages
		sugar.Info("📦 Installing Python dependencies in virtual environment...")
		if err := execute(venvPath+"/bin/pip", "install", "docker==7.1.0", "urllib3==1.26.20", "requests==2.32.2"); err != nil {
			sugar.Fatal("❌ Failed to install Python dependencies:", err)
		}

		// Step 4: Update Wazuh DockerListener script
		sugar.Info("✏️  Updating DockerListener shebang...")
		if _, err := os.Stat(dockerListener); os.IsNotExist(err) {
			sugar.Warn("⚠️  Warning: DockerListener script not found at", dockerListener)
		} else {
			// Backup the original script
			backupPath := dockerListener + ".bak"
			execute("sudo", "cp", dockerListener, backupPath)

			// Modify shebang
			shebang := "#!" + venvPath + "/bin/python3\n"
			content, _ := os.ReadFile(dockerListener)
			newContent := shebang + strings.Join(strings.Split(string(content), "\n")[1:], "\n")

			// Write back the modified file
			if err := os.WriteFile(dockerListener, []byte(newContent), 0755); err != nil {
				sugar.Fatal("❌ Failed to update DockerListener script:", err)
			}
			sugar.Info("✅ DockerListener script updated successfully")
		}

		// Step 5: Restart Wazuh Agent
		sugar.Info("🔄 Restarting Wazuh Agent...")
		if err := execute("sudo", "systemctl", "restart", "wazuh-agent"); err != nil {
			sugar.Fatal("❌ Failed to restart Wazuh Agent:", err)
		}

		// Step 6: Verify the installation
		sugar.Info("✅ Running verification...")
		if err := execute(venvPath+"/bin/python3", dockerListener, "--help"); err != nil {
			sugar.Fatal("❌ DockerListener verification failed:", err)
		}

		sugar.Info("🎉 Delphi DockerListener setup completed successfully!")
	},
}

// execute runs a command and returns an error if it fails
func execute(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

// Register the command inside the install package
func init() {
	InstallCmd.AddCommand(delphiListenerCmd)
}
