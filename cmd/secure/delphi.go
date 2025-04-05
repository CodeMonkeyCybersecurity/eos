// cmd/secure/delphi.go
package secure

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
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
		log.Error("Failed to download Wazuh password management tool", zap.Error(err))
		return fmt.Errorf("failed to download password tool: %w", err)
	}
	if err := os.Chmod(config.DelphiPasswdToolPath, 0700); err != nil {
		log.Error("Failed to set permissions on Wazuh password management tool", zap.Error(err))
		return fmt.Errorf("failed to chmod tool: %w", err)

	}

	log.Info("Extracting current API admin password (user: wazuh)")
	apiPassword, err := delphi.ExtractWazuhUserPassword()
	log.Debug("Extracted password for user 'wazuh'", zap.String("password", apiPassword))
	if err != nil {
		log.Error("Failed to extract Wazuh API password", zap.Error(err))
		return fmt.Errorf("failed to extract wazuh API password: %w", err)
	}
	log.Info("Successfully extracted wazuh API password")

	log.Info("Rotating all passwords with --change-all")
	cmd1 := exec.Command("bash", config.DelphiPasswdToolPath, "-a", "-A", "-au", "wazuh", "-ap", apiPassword)
	cmd1.Stdout = os.Stdout
	cmd1.Stderr = os.Stderr
	if err := cmd1.Run(); err != nil {
		log.Error("Failed to rotate all Wazuh passwords", zap.Error(err))
		return fmt.Errorf("failed to rotate all Wazuh passwords: %w", err)
	}

	log.Info("Successfully rotated all passwords")

	log.Info("Restarting Wazuh services to apply new credentials")

	services := []string{"filebeat", "wazuh-manager", "wazuh-dashboard", "wazuh-indexer"}
	for _, svc := range services {
		log.Info("Restarting", zap.String("service", svc))
		restart := exec.Command("systemctl", "restart", svc)
		output, err := restart.CombinedOutput()
		if err != nil {
			log.Warn("Failed to restart service", zap.String("service", svc), zap.Error(err), zap.String("output", string(output)))
		}
		restart.Stdout = os.Stdout
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
