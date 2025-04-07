// cmd/create/delphi.go
package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var log *zap.Logger

var CreateDelphiCmd = &cobra.Command{
	Use:     "delphi",
	Aliases: []string{"wazuh"},
	Short:   "Deploy Delphi (Wazuh all-in-one)",
	Long:    `Installs Wazuh server, dashboard, and indexer using the official Wazuh quickstart script.`,
	RunE:    runDelphiInstall,
}

// FindAndExtractWazuhPasswords attempts to locate wazuh-install-files.tar and extract wazuh-passwords.txt
func findAndExtractWazuhPasswords() error {

	searchPaths := []string{
		"/root",
		"/tmp",
		"/opt",
		"/var/tmp",
		".", // current working directory
	}

	found := false
	var tarPath string
	for _, dir := range searchPaths {
		candidate := filepath.Join(dir, "wazuh-install-files.tar")
		if utils.FileExists(candidate) {
			tarPath = candidate
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("could not locate wazuh-install-files.tar in common paths")
	}

	log.Info("Found Wazuh tar file", zap.String("path", tarPath))
	cmd := exec.Command("tar", "-O", "-xvf", tarPath, "wazuh-install-files/wazuh-passwords.txt")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract passwords: %w", err)
	}

	return nil
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
	log.Info("Wazuh installation completed successfully")
	log.Info("Extracting admin credentials from wazuh-passwords.txt")
	if err := findAndExtractWazuhPasswords(); err != nil {
		log.Warn("Could not extract Wazuh credentials", zap.Error(err))
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
	log = logger.L() // <-- INITIALIZE it
	CreateCmd.AddCommand(CreateDelphiCmd)
}
