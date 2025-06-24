// pkg/delphi/secure.go

package delphi

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"

	cerr "github.com/cockroachdb/errors"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"go.uber.org/zap"
)

// RotateWithTool downloads and makes executable the Wazuh password tool.
func RotateWithTool(rc *eos_io.RuntimeContext) error {
	_, span := telemetry.Start(rc.Ctx, "delphi.rotate_tool")
	defer span.End()

	rc.Log.Info(" Downloading Wazuh password tool",
		zap.String("url", DelphiPasswdToolURL),
		zap.String("path", DelphiPasswdToolPath),
	)

	if err := utils.DownloadFile(DelphiPasswdToolPath, DelphiPasswdToolURL); err != nil {
		return cerr.Wrapf(err, "download tool")
	}
	if err := os.Chmod(DelphiPasswdToolPath, 0o700); err != nil {
		return cerr.Wrapf(err, "chmod tool")
	}
	return nil
}

// RunPrimary performs API-based rotation via the tool.
func RunPrimary(rc *eos_io.RuntimeContext, apiPass string) (*bytes.Buffer, error) {

	rc.Log.Info(" Running primary password rotation")

	buf := &bytes.Buffer{}
	cmd := exec.CommandContext(rc.Ctx,
		filepath.Base(DelphiPasswdToolPath),
		"-a", "-A", "-au", "wazuh", "-ap", apiPass,
	)
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, cerr.Wrap(err, "primary rotation failed")
	}
	rc.Log.Info(" Primary rotation succeeded")
	return buf, nil
}

// RunFallback extracts the UI password, rotates via API, then retries.
func RunFallback(rc *eos_io.RuntimeContext) (string, error) {

	rc.Log.Info(" Fallback: extracting WUI password")
	content, err := os.ReadFile("/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml")
	if err != nil {
		return "", cerr.Wrapf(err, "read wazuh.yml")
	}
	re := regexp.MustCompile(`password:\s*"(.*?)"`)
	match := re.FindStringSubmatch(string(content))
	if len(match) < 2 {
		return "", cerr.New("cannot parse WUI password")
	}
	wuiPass := match[1]

	// Authenticate & rotate
	cfg := Config{
		Protocol:           "https",
		FQDN:               "127.0.0.1",
		Port:               "55000",
		VerifyCertificates: false,
	}
	token, err := AuthenticateUser(rc, &cfg, "wazuh-wui", wuiPass)
	if err != nil {
		return "", cerr.Wrap(err, "fallback auth failed")
	}
	cfg.Token = token

	userID, err := GetUserIDByUsername(rc, &cfg, "wazuh")
	if err != nil {
		return "", cerr.Wrap(err, "fallback get user ID")
	}

	newPass, _ := crypto.GeneratePassword(20)
	if err := UpdateUserPassword(rc, &cfg, userID, newPass); err != nil {
		return "", cerr.Wrap(err, "fallback update password")
	}

	// Retry tool to sync everything
	rc.Log.Info(" Retrying with new password")
	retry := exec.CommandContext(rc.Ctx, filepath.Base(DelphiPasswdToolPath),
		"-a", "-A", "-au", "wazuh", "-ap", newPass,
	)
	retry.Stdout = os.Stdout
	retry.Stderr = os.Stderr
	if err := retry.Run(); err != nil {
		return "", cerr.Wrap(err, "fallback tool retry failed")
	}

	rc.Log.Info(" Fallback rotation succeeded")
	return newPass, nil
}

// ParseSecrets pulls “user X is Y” lines into a map.
func ParseSecrets(rc *eos_io.RuntimeContext, out *bytes.Buffer) map[string]string {
	_, span := telemetry.Start(rc.Ctx, "delphi.parse_secrets")
	defer span.End()

	secrets := make(map[string]string)
	scanner := bufio.NewScanner(out)
	re := regexp.MustCompile(`The password for user (\w+) is (\S+)`)

	for scanner.Scan() {
		if m := re.FindStringSubmatch(scanner.Text()); m != nil {
			user, pass := m[1], m[2]
			secrets[user] = pass
			rc.Log.Info(" Parsed secret", zap.String("user", user))
		}
	}
	if err := scanner.Err(); err != nil {
		rc.Log.Warn("scanner error", zap.Error(err))
	}
	return secrets
}

// RestartServices restarts the given services on each OS.
func RestartServices(rc *eos_io.RuntimeContext, services []string) error {

	for _, svc := range services {
		rc.Log.Info(" Restarting service", zap.String("service", svc))

		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			cmd = exec.CommandContext(rc.Ctx, "sc", "restart", svc)
		case "darwin":
			cmd = exec.CommandContext(rc.Ctx, "brew", "services", "restart", svc)
		default:
			cmd = exec.CommandContext(rc.Ctx, "systemctl", "restart", svc)
		}

		out, err := cmd.CombinedOutput()
		if err != nil {
			rc.Log.Warn("restart failed",
				zap.String("service", svc),
				zap.Error(err),
				zap.ByteString("output", out),
			)
		} else {
			rc.Log.Info(" Restarted", zap.String("service", svc))
		}
	}
	return nil
}
