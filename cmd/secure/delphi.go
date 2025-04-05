// cmd/secure/delphi.go
package secure

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var SecureDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Harden Delphi (Wazuh) by rotating passwords and updating configs",
	Long:  `Downloads and runs the Wazuh password tool to rotate all credentials and restart relevant services.`,
	RunE:  runDelphiHardening,
}

func runDelphiHardening(cmd *cobra.Command, args []string) error {

	log.Info("Downloading Wazuh password management tool")
	if err := utils.DownloadFile(config.DelphiPasswdToolPath, config.DelphiPasswdToolURL); err != nil {
		return fmt.Errorf("failed to download password tool: %w", err)
	}
	if err := os.Chmod(config.DelphiPasswdToolURL, 0755); err != nil {
		return fmt.Errorf("failed to chmod tool: %w", err)
	}

	log.Info("Rotating all passwords with --change-all")
	cmd1 := exec.Command("bash", config.DelphiPasswdToolPath, "-a")
	cmd1.Stdout = os.Stdout
	cmd1.Stderr = os.Stderr
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("failed to rotate indexer passwords: %w", err)
	}

	log.Info("Rotating API passwords with admin user 'wazuh'")
	cmd2 := exec.Command("bash", config.DelphiPasswdToolURL, "-a", "-A", "-au", "wazuh", "-ap", "KTb+Md+rR74J2yHfoGGnFGHGm03Gadyu") // TODO: Replace this with dynamic secret loading
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	if err := cmd2.Run(); err != nil {
		return fmt.Errorf("failed to rotate API passwords: %w", err)
	}

	log.Info("Restarting Wazuh services to apply new credentials")

	services := []string{"filebeat", "wazuh-manager", "wazuh-dashboard"}
	for _, svc := range services {
		log.Info("Restarting", zap.String("service", svc))
		restart := exec.Command("systemctl", "restart", svc)
		restart.Stdout = os.Stdout
		restart.Stderr = os.Stderr
		if err := restart.Run(); err != nil {
			log.Warn("Failed to restart service", zap.String("service", svc), zap.Error(err))
		}
	}

	log.Info("Delphi hardening complete")
	return nil
}

func init() {
	SecureCmd.AddCommand(SecureDelphiCmd)
}
