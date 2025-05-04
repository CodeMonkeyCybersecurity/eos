package vault

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func PhaseEnsureVaultHealthy() error {
	zap.L().Info("🚀 [Phase 8] Ensuring Vault is ready")

	if isVaultProcessRunning() {
		zap.L().Info("✅ Vault process detected by lsof check")
	} else {
		zap.L().Warn("⚠️ Vault process NOT detected by lsof check")
	}

	if addr, err := EnsureVaultEnv(); err != nil {
		zap.L().Error("❌ Could not resolve VAULT_ADDR", zap.Error(err))
		return fmt.Errorf("could not resolve VAULT_ADDR: %w", err)
	} else {
		zap.L().Info("✅ VAULT_ADDR resolved", zap.String("address", addr))
	}

	client, err := GetPrivilegedVaultClient()
	if err != nil {
		zap.L().Error("❌ Failed to create privileged Vault client", zap.Error(err))
		return fmt.Errorf("could not create Vault client: %w", err)
	}
	zap.L().Info("✅ Privileged Vault client obtained")

	if err := probeVaultHealthUntilReady(client); err == nil {
		zap.L().Info("✅ Vault is healthy after probe")
		return nil
	}

	zap.L().Warn("⚠️ Vault did not become healthy after retries; escalate to phase 8")
	return err
}

func probeVaultHealthUntilReady(client *api.Client) error {
	for attempt := 1; attempt <= shared.VaultRetryCount; attempt++ {
		zap.L().Info("🔁 Vault health probe attempt", zap.Int("attempt", attempt))

		status, err := client.Sys().Health()
		if err != nil {
			zap.L().Warn("🛑 Vault health API error", zap.Int("attempt", attempt), zap.Error(err))
			time.Sleep(shared.VaultRetryDelay)
			continue
		}

		zap.L().Debug("📊 Vault health status",
			zap.Bool("initialized", status.Initialized),
			zap.Bool("sealed", status.Sealed),
			zap.Bool("standby", status.Standby),
		)

		if !status.Initialized {
			zap.L().Error("❌ Vault uninitialized; deferring to phase 8")
			return fmt.Errorf("vault uninitialized; defer to phase 8")
		}
		if status.Initialized && status.Sealed {
			zap.L().Error("❌ Vault sealed; deferring to phase 8")
			return fmt.Errorf("vault sealed; defer to phase 8")
		}

		if !status.Sealed && !status.Standby {
			zap.L().Info("✅ Vault is unsealed and active")
			return nil
		}
		if status.Standby {
			zap.L().Info("🟡 Vault is in standby — treating as healthy")
			return nil
		}

		zap.L().Warn("⚠️ Unexpected Vault health state", zap.Any("response", status))
		time.Sleep(shared.VaultRetryDelay)
	}
	zap.L().Error("❌ Vault not healthy after maximum retry attempts",
		zap.Int("retries", shared.VaultRetryCount))
	return fmt.Errorf("vault not healthy after %d attempts", shared.VaultRetryCount)
}

func CheckVaultHealth() (bool, error) {
	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		zap.L().Error("❌ VAULT_ADDR environment variable not set")
		return false, fmt.Errorf("VAULT_ADDR not set")
	}

	url := strings.TrimRight(addr, "/") + shared.VaultHealthPath
	zap.L().Debug("🌐 Performing raw Vault health check", zap.String("url", url))

	resp, err := http.Get(url)
	if err != nil {
		zap.L().Error("❌ Vault health endpoint not responding", zap.String("url", url), zap.Error(err))
		return false, fmt.Errorf("vault not responding: %w", err)
	}
	defer shared.SafeClose(resp.Body)

	zap.L().Debug("📨 Vault health HTTP response", zap.Int("statusCode", resp.StatusCode))

	switch resp.StatusCode {
	case 200, 429:
		zap.L().Info("✅ Vault is healthy or throttled", zap.Int("statusCode", resp.StatusCode))
		return true, nil
	case 501, 503:
		zap.L().Warn("⚠️ Vault is not initialized or unavailable", zap.Int("statusCode", resp.StatusCode))
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		zap.L().Error("❌ Unexpected Vault health response",
			zap.Int("statusCode", resp.StatusCode),
			zap.ByteString("body", body))
		return false, fmt.Errorf("unexpected vault health: %s", body)
	}
}

func isVaultProcessRunning() bool {
	zap.L().Debug("🔍 Checking Vault process using lsof")
	out, err := exec.Command("lsof", "-i", shared.VaultDefaultPort).Output()
	if err != nil {
		zap.L().Warn("⚠️ lsof command failed (process check skipped)", zap.Error(err))
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "vault") && strings.Contains(line, shared.EosID) {
			zap.L().Debug("✅ Vault process detected in lsof output", zap.String("line", line))
			return true
		}
	}
	zap.L().Warn("⚠️ Vault process not found in lsof output")
	return false
}

func ValidateAndCache(client *api.Client) {
	zap.L().Info("🔧 Validating and caching Vault client")
	report, checked := Check(client, nil, "")
	if checked != nil {
		zap.L().Info("✅ Caching validated Vault client")
		SetVaultClient(checked)
	}
	if report == nil {
		zap.L().Warn("⚠️ Vault check returned nil — skipping further setup")
		return
	}
	for _, note := range report.Notes {
		zap.L().Warn("⚠️ Vault diagnostic note", zap.String("note", note))
	}
}
