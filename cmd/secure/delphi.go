package secure

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SecureDelphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Harden Delphi (Wazuh) by rotating passwords and updating configs",
	Long:  `Downloads and runs the Wazuh password tool to rotate all credentials and restart relevant services.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, _ *cobra.Command, _ []string) error {
		return runDelphiHardening(ctx)
	}),
}

func downloadPasswordTool(ctx *eosio.RuntimeContext) error {
	ctx.Log.Info("📥 Downloading Wazuh password management tool")
	if err := utils.DownloadFile(delphi.DelphiPasswdToolPath, delphi.DelphiPasswdToolURL); err != nil {
		ctx.Log.Error("Failed to download password tool", zap.Error(err))
		return err
	}
	if err := os.Chmod(delphi.DelphiPasswdToolPath, 0700); err != nil {
		ctx.Log.Error("Failed to chmod password tool", zap.Error(err))
		return err
	}
	return nil
}

func runPrimaryPasswordRotation(ctx *eosio.RuntimeContext, apiPassword string) (*bytes.Buffer, error) {
	ctx.Log.Info("🔐 Attempting primary password rotation using Wazuh API password")
	var stdout bytes.Buffer

	cmd := exec.Command("sudo", "bash", delphi.DelphiPasswdToolPath, "-a", "-A", "-au", "wazuh", "-ap", apiPassword)
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		ctx.Log.Warn("Primary password rotation failed", zap.Error(err))
		return nil, err
	}
	ctx.Log.Info("✅ Primary password rotation succeeded")
	return &stdout, nil
}

func runFallbackPasswordRotation(ctx *eosio.RuntimeContext) (string, error) {
	ctx.Log.Info("🔁 Attempting fallback password rotation...")

	ymlPath := "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
	ymlContent, err := os.ReadFile(ymlPath)
	if err != nil {
		return "", fmt.Errorf("failed to read wazuh.yml: %w", err)
	}

	match := regexp.MustCompile(`password:\s*"(.*?)"`).FindStringSubmatch(string(ymlContent))
	if len(match) < 2 {
		return "", fmt.Errorf("could not extract wazuh-wui password")
	}
	extracted := match[1]
	ctx.Log.Info("🔓 Extracted wazuh-wui password")

	cfg := delphi.Config{
		Protocol:           "https",
		FQDN:               "127.0.0.1",
		Port:               "55000",
		VerifyCertificates: false,
	}

	token, err := delphi.AuthenticateUser(&cfg, "wazuh-wui", extracted)
	if err != nil {
		return "", fmt.Errorf("fallback: auth failed: %w", err)
	}
	cfg.Token = token
	ctx.Log.Info("✅ Authenticated with wazuh-wui")

	userID, err := delphi.GetUserIDByUsername(&cfg, "wazuh")
	if err != nil {
		return "", fmt.Errorf("fallback: could not get user ID: %w", err)
	}
	ctx.Log.Info("🔍 Found wazuh user ID", zap.String("userID", userID))

	newPass, _ := crypto.GeneratePassword(20)
	if err := delphi.UpdateUserPassword(&cfg, userID, newPass); err != nil {
		return "", fmt.Errorf("fallback: could not update user password: %w", err)
	}
	ctx.Log.Info("✅ Updated password for wazuh")

	retryCmd := exec.Command("sudo", "bash", delphi.DelphiPasswdToolPath, "-a", "-A", "-au", "wazuh", "-ap", newPass)
	retryCmd.Stdout = os.Stdout
	retryCmd.Stderr = os.Stderr
	if err := retryCmd.Run(); err != nil {
		return "", fmt.Errorf("fallback: password tool failed: %w", err)
	}

	ctx.Log.Info("✅ Fallback password rotation succeeded")
	return newPass, nil
}

func parseSecrets(ctx *eosio.RuntimeContext, stdout *bytes.Buffer) map[string]string {
	secrets := make(map[string]string)
	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "The password for user") {
			parts := strings.Split(line, " ")
			if len(parts) >= 7 {
				user := strings.TrimSpace(parts[4])
				pass := strings.TrimSpace(parts[6])
				secrets[user] = pass
				ctx.Log.Info("🔐 Parsed secret", zap.String("user", user))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		ctx.Log.Warn("Failed to scan secrets", zap.Error(err))
	}
	return secrets
}

func restartServices(ctx *eosio.RuntimeContext, services []string) {
	for _, svc := range services {
		ctx.Log.Info("🔄 Restarting service", zap.String("service", svc))
		cmd := exec.Command("sudo", "systemctl", "restart", svc)
		output, err := cmd.CombinedOutput()
		if err != nil {
			ctx.Log.Warn("Restart failed", zap.String("service", svc), zap.Error(err), zap.String("output", string(output)))
		} else {
			ctx.Log.Info("✅ Service restarted", zap.String("service", svc))
		}
	}
}

func runDelphiHardening(ctx *eosio.RuntimeContext) error {
	if err := downloadPasswordTool(ctx); err != nil {
		return err
	}

	ctx.Log.Info("🔍 Extracting current Wazuh API password")
	apiPass, err := delphi.ExtractWazuhUserPassword()
	if err != nil {
		ctx.Log.Error("Failed to extract API password", zap.Error(err))
		return err
	}
	ctx.Log.Debug("Extracted password", zap.String("user", "wazuh"), zap.String("password", apiPass))

	stdout, err := runPrimaryPasswordRotation(ctx, apiPass)
	if err != nil {
		ctx.Log.Warn("Primary rotation failed, running fallback")
		newPass, err := runFallbackPasswordRotation(ctx)
		if err != nil {
			return err
		}
		stdout = &bytes.Buffer{}
		fmt.Fprintf(stdout, "The password for user wazuh is %s\n", newPass)
	}

	ctx.Log.Info("🔎 Parsing new credentials from output")
	secrets := parseSecrets(ctx, stdout)

	ctx.Log.Info("🔁 Restarting affected services")
	restartServices(ctx, []string{
		"filebeat", "wazuh-manager", "wazuh-dashboard", "wazuh-indexer",
	})

	ctx.Log.Info("🔐 Storing secrets in Vault")
	if err := vault.HandleFallbackOrStore("delphi", secrets); err != nil {
		ctx.Log.Error("Failed to store secrets", zap.Error(err))
		return err
	}

	ctx.Log.Info("✅ Delphi hardening complete")
	return nil
}
