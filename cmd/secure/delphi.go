package secure

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// SecureDelphiCmd rotates credentials and updates configurations for Delphi.
var SecureDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Harden Delphi (Wazuh) by rotating passwords and updating configs",
	Long:  `Downloads and runs the Wazuh password tool to rotate all credentials and restart relevant services.`,
	RunE:  eos.Wrap(func(_ *cobra.Command, _ []string) error { return runDelphiHardening() }),
}

// downloadPasswordTool downloads the Wazuh password tool and sets executable permissions.
func downloadPasswordTool() error {
	log.Info("Downloading Wazuh password management tool")
	if err := utils.DownloadFile(delphi.DelphiPasswdToolPath, delphi.DelphiPasswdToolURL); err != nil {
		log.Error("Failed to download Wazuh password management tool", zap.Error(err))
		return fmt.Errorf("failed to download password tool: %w", err)
	}
	if err := os.Chmod(delphi.DelphiPasswdToolPath, 0700); err != nil {
		log.Error("Failed to set permissions on Wazuh password management tool", zap.Error(err))
		return fmt.Errorf("failed to chmod tool: %w", err)
	}
	return nil
}

// runPrimaryPasswordRotation attempts to rotate passwords using the provided API password.
func runPrimaryPasswordRotation(apiPassword string) (*bytes.Buffer, error) {
	log.Info("Rotating all passwords with --change-all")
	var stdout bytes.Buffer
	cmd := exec.Command("bash", delphi.DelphiPasswdToolPath,
		"-a", "-A",
		"-au", "wazuh",
		"-ap", apiPassword,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Warn("Primary password rotation failed", zap.Error(err))
		return nil, err
	}
	log.Info("Primary password rotation succeeded")
	return &stdout, nil
}

// runFallbackPasswordRotation performs fallback rotation using credentials extracted from wazuh.yml.
func runFallbackPasswordRotation() (string, error) {
	log.Info("Starting fallback password reset logic...")

	ymlPath := "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
	ymlContent, err := os.ReadFile(ymlPath)
	if err != nil {
		return "", fmt.Errorf("failed to read wazuh.yml: %w", err)
	}

	re := regexp.MustCompile(`password:\s*"(.*?)"`)
	match := re.FindStringSubmatch(string(ymlContent))
	if len(match) < 2 {
		return "", fmt.Errorf("could not extract wazuh-wui password from wazuh.yml")
	}
	extractedPass := match[1]
	log.Info("Extracted wazuh-wui password from wazuh.yml")

	cfg := delphi.DelphiConfig{
		Protocol:           "https",
		FQDN:               "127.0.0.1",
		Port:               "55000",
		VerifyCertificates: false,
	}

	token, err := delphi.AuthenticateUser(&cfg, "wazuh-wui", extractedPass)
	if err != nil {
		return "", fmt.Errorf("fallback: failed to authenticate with wazuh-wui: %w", err)
	}
	cfg.Token = token
	log.Info("Fallback: authenticated with wazuh-wui")

	userID, err := delphi.GetUserIDByUsername(&cfg, "wazuh")
	if err != nil {
		return "", fmt.Errorf("fallback: failed to get wazuh user ID: %w", err)
	}
	log.Info("Found wazuh user ID", zap.String("userID", userID))

	newWazuhPass, _ := utils.GeneratePassword(20)
	if err := delphi.UpdateUserPassword(&cfg, userID, newWazuhPass); err != nil {
		return "", fmt.Errorf("fallback: failed to update wazuh password: %w", err)
	}
	log.Info("Fallback: updated wazuh user password")

	retryCmd := exec.Command("bash", delphi.DelphiPasswdToolPath,
		"-a", "-A",
		"-au", "wazuh",
		"-ap", newWazuhPass,
	)
	retryCmd.Stdout = os.Stdout
	retryCmd.Stderr = os.Stderr
	if err := retryCmd.Run(); err != nil {
		return "", fmt.Errorf("fallback: password tool retry failed: %w", err)
	}

	log.Info("Fallback password rotation succeeded after fixing wazuh credentials")
	return newWazuhPass, nil
}

// parseSecrets scans output and extracts new password information.
func parseSecrets(stdout *bytes.Buffer) map[string]string {
	secrets := make(map[string]string)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "The password for user") {
			parts := strings.Split(line, " ")
			// Expected format: "The password for user wazuh is XYZ"
			if len(parts) >= 7 {
				user := strings.TrimSpace(parts[4])
				pass := strings.TrimSpace(parts[6])
				secrets[user] = pass
				fmt.Printf("🔐 Parsed secret for %s\n", user)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn("Error reading rotation output", zap.Error(err))
	}
	return secrets
}

// restartServices restarts system services and logs the outcome.
func restartServices(services []string) {
	for _, svc := range services {
		log.Info("Restarting service", zap.String("service", svc))
		cmd := exec.Command("systemctl", "restart", svc)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Warn("Failed to restart service", zap.String("service", svc), zap.Error(err), zap.String("output", string(output)))
		} else {
			log.Info("Service restarted successfully", zap.String("service", svc), zap.String("output", string(output)))
		}
	}
}

// runDelphiHardening coordinates the hardening steps for Delphi.
func runDelphiHardening() error {
	// Step 1: Download the password tool.
	if err := downloadPasswordTool(); err != nil {
		return err
	}

	// Step 2: Extract the current API admin password.
	log.Info("Extracting current API admin password (user: wazuh)")
	apiPassword, err := delphi.ExtractWazuhUserPassword()
	if err != nil {
		log.Error("Failed to extract Wazuh API password", zap.Error(err))
		return fmt.Errorf("failed to extract wazuh API password: %w", err)
	}
	log.Debug("Extracted password for user 'wazuh'", zap.String("password", apiPassword))
	log.Info("Successfully extracted wazuh API password")

	// Step 3: Attempt primary password rotation.
	stdout, err := runPrimaryPasswordRotation(apiPassword)
	if err != nil {
		log.Warn("Primary password rotation failed, attempting fallback", zap.Error(err))
		newPass, err := runFallbackPasswordRotation()
		if err != nil {
			return err
		}
		stdout = &bytes.Buffer{}
		fmt.Fprintf(stdout, "The password for user wazuh is %s\n", newPass)
	}

	// Step 4: Parse output for new secrets.
	log.Info("Parsing output for new passwords")
	secrets := parseSecrets(stdout)

	// Step 5: Restart required Wazuh services.
	services := []string{"filebeat", "wazuh-manager", "wazuh-dashboard", "wazuh-indexer"}
	log.Info("Restarting Wazuh services to apply new credentials")
	restartServices(services)

	// Step 6: Store updated secrets in the vault.
	log.Info("Storing secrets in vault")
	if err := vault.HandleFallbackOrStore("delphi", secrets); err != nil {
		log.Error("Failed to store secrets in vault", zap.Error(err))
		return err
	}

	log.Info("Delphi hardening complete")
	return nil
}

func init() {
	SecureCmd.AddCommand(SecureDelphiCmd)
}
