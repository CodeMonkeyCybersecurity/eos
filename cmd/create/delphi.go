// cmd/create/delphi.go
package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var CreateDelphiCmd = &cobra.Command{
	Use:     "delphi",
	Aliases: []string{"wazuh"},
	Short:   "Deploy Delphi (Wazuh all-in-one)",
	Long:    `Installs Wazuh server, dashboard, and indexer using the official Wazuh quickstart script.`,
	RunE:    runDelphiInstall,
}

func runDelphiInstall(cmd *cobra.Command, args []string) error {
	tmpDir := "/tmp"
	scriptURL := "https://packages.wazuh.com/4.11/wazuh-install.sh"
	scriptPath := filepath.Join(tmpDir, "wazuh-install.sh")

	log.Info("Downloading Wazuh installer", zap.String("url", scriptURL))
	if err := utils.DownloadFile(scriptPath, scriptURL); err != nil {
		return fmt.Errorf("failed to download installer: %w", err)
	}
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	log.Info("Running Wazuh installer")
	installCmd := exec.Command("bash", scriptPath, "-a")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	log.Info("Extracting admin credentials from wazuh-passwords.txt")
	extractCmd := exec.Command("tar", "-O", "-xvf", "wazuh-install-files.tar", "wazuh-install-files/wazuh-passwords.txt")
	extractCmd.Stdout = os.Stdout
	extractCmd.Stderr = os.Stderr
	if err := extractCmd.Run(); err != nil {
		return fmt.Errorf("failed to extract credentials: %w", err)
	}

	log.Info("Disabling Wazuh updates (repo disable)")

	if err := platform.RequireLinuxDistro([]string{"debian", "rhel"}); err != nil {
		log.Fatal("Unsupported Linux distro", zap.Error(err))
	}

	distro := platform.DetectLinuxDistro()
	switch distro {
	case "ubuntu", "debian":
		disableCmd := exec.Command("sed", "-i", "s/^deb /#deb /", "/etc/apt/sources.list.d/wazuh.list")
		disableCmd.Stdout = os.Stdout
		disableCmd.Stderr = os.Stderr
		if err := disableCmd.Run(); err != nil {
			log.Warn("Failed to comment out Wazuh APT repo", zap.Error(err))
		} else {
			log.Info("Commented out Wazuh APT repo successfully")
			exec.Command("apt", "update").Run()
		}
	default:
		disableCmd := exec.Command("sed", "-i", "s/^enabled=1/enabled=0/", "/etc/yum.repos.d/wazuh.repo")
		disableCmd.Stdout = os.Stdout
		disableCmd.Stderr = os.Stderr
		if err := disableCmd.Run(); err != nil {
			log.Warn("Could not disable Wazuh yum repo", zap.Error(err))
		} else {
			log.Info("Wazuh yum repo disabled")
		}

		log.Info("Delphi (Wazuh) installation completed")

		log.Info("To access the Wazuh Dashboard:")
		log.Info("👉 Run this on your **local machine** (not over SSH):")
		log.Info("    firefox https://$(hostname -I | awk '{print $1}')  # or use your preferred browser")

		log.Info("Alternatively, forward the port over SSH and access via localhost:")
		log.Info("    ssh -L 8443:localhost:443 user@your-server-ip")
		log.Info("Then open: https://localhost:8443 in your browser.")
		log.Info("To harden this installation, consider running the following commands: 'eos harden delphi'.")
		
	}
	return nil
}

func init() {
	CreateCmd.AddCommand(CreateDelphiCmd)
}
