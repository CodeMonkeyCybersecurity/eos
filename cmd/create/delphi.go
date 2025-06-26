package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var ignoreHardwareCheck bool
var overwriteInstall bool

func init() {
	CreateCmd.AddCommand(CreateDelphiCmd)
	CreateDelphiCmd.Flags().BoolVar(&ignoreHardwareCheck, "ignore", false, "Ignore Wazuh hardware requirements check")
	CreateDelphiCmd.Flags().BoolVar(&overwriteInstall, "overwrite", false, "Overwrite existing Wazuh installation")
}

var CreateDelphiCmd = &cobra.Command{
	Use:     "delphi",
	Aliases: []string{"wazuh"},
	Short:   "Deploy Delphi (Wazuh all-in-one) with optional hardware check override",
	Long: `Installs the full Wazuh stack (server, dashboard, and indexer) using the official quickstart script.
By default, this checks your system's hardware (4GB RAM, 2+ cores). Use --ignore to bypass this check.`,
	RunE: eos.Wrap(runDelphiInstall),
}

func runDelphiInstall(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)

	if err := platform.RequireLinuxDistro(rc, []string{"debian", "rhel"}); err != nil {
		log.Fatal("Unsupported Linux distro", zap.Error(err))
	}

	tmpDir := "/tmp"
	scriptURL := "https://packages.wazuh.com/4.11/wazuh-install.sh"
	scriptPath := filepath.Join(tmpDir, "wazuh-install.sh")

	log.Info(" Downloading Wazuh installer", zap.String("url", scriptURL))
	if err := utils.DownloadFile(scriptPath, scriptURL); err != nil {
		return fmt.Errorf("failed to download installer: %w", err)
	}
	if err := os.Chmod(scriptPath, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	args = []string{"-a"}
	if ignoreHardwareCheck {
		log.Info(" Ignoring hardware checks (passing -i)")
		args = append(args, "-i")
	}
	if overwriteInstall {
		log.Info(" Overwriting existing installation (passing -o)")
		args = append(args, "-o")
	}

	log.Info(" Running Wazuh installer script")
	cmdArgs := append([]string{scriptPath}, args...)
	installCmd := exec.Command("bash", cmdArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}
	log.Info(" Wazuh installation completed")

	log.Info(" Attempting to extract Wazuh admin credentials")
	if err := extractWazuhPasswords(rc); err != nil {
		log.Warn("Could not extract Wazuh credentials", zap.Error(err))
	}

	log.Info(" Disabling Wazuh repo updates")
	distro := platform.DetectLinuxDistro(rc)
	switch distro {
	case "debian", "ubuntu":
		cmd := exec.Command("sed", "-i", "s/^deb /#deb /", "/etc/apt/sources.list.d/wazuh.list")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Warn("Failed to comment out Wazuh APT repo", zap.Error(err))
		} else {
			log.Info(" Wazuh APT repo commented out")
			_ = exec.Command("apt", "update").Run()
		}
	default:
		cmd := exec.Command("sed", "-i", "s/^enabled=1/enabled=0/", "/etc/yum.repos.d/wazuh.repo")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Warn("Failed to disable Wazuh yum repo", zap.Error(err))
		} else {
			log.Info(" Wazuh yum repo disabled")
		}
	}

	log.Info(" Delphi (Wazuh) setup complete")
	log.Info("To access the Wazuh Dashboard:")
	log.Info(" Run this on your **local machine** (not over SSH):")
	log.Info("    firefox https://$(hostname -I | awk '{print $1}')")
	log.Info("Or forward port with:")
	log.Info("    ssh -L 8443:localhost:443 user@your-server")
	log.Info("Then browse: https://localhost:8443")
	log.Info(" To harden this install, run: `eos harden delphi`")

	return nil
}

func extractWazuhPasswords(rc *eos_io.RuntimeContext) error {
	searchPaths := []string{"/root", "/tmp", "/opt", "/var/tmp", "."}
	for _, dir := range searchPaths {
		tarPath := filepath.Join(dir, "wazuh-install-files.tar")
		if eos_unix.Exists(tarPath) {
			otelzap.Ctx(rc.Ctx).Info(" Found Wazuh tar file", zap.String("path", tarPath))
			cmd := exec.Command("tar", "-O", "-xvf", tarPath, "wazuh-install-files/wazuh-passwords.txt")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to extract passwords: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("wazuh-install-files.tar not found in expected paths")
}
