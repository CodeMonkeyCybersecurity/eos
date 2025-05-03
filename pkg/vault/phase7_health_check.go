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
	zap.L().Info("🚀 [Phase 7] Ensuring Vault is ready")

	if isVaultProcessRunning() {
		zap.L().Info("✅ Vault process running (lsof check)")
	}

	if _, err := EnsureVaultEnv(); err != nil {
		return fmt.Errorf("could not resolve VAULT_ADDR: %w", err)
	}

	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("could not create Vault client: %w", err)
	}

	if err := probeVaultHealthUntilReady(client); err == nil {
		zap.L().Info("✅ Vault healthy after probe")
		return nil
	}

	zap.L().Warn("⚠️ Vault did not become healthy after retries — attempting recovery")
	return recoverVaultHealth(client)
}

func probeVaultHealthUntilReady(client *api.Client) error {
	for attempt := 1; attempt <= shared.VaultRetryCount; attempt++ {
		zap.L().Info("🔁 Vault health probe", zap.Int("attempt", attempt))

		status, err := client.Sys().Health()
		if err != nil {
			zap.L().Warn("🛑 Vault health API error", zap.Error(err))
			time.Sleep(shared.VaultRetryDelay)
			continue
		}

		if !status.Initialized {
			zap.L().Info("ℹ️ Vault uninitialized — running init + unseal flow")
			_, err := UnsealVault()
			return err
		}
		if status.Initialized && status.Sealed {
			zap.L().Info("🔒 Vault sealed — attempting auto-unseal")
			if err := MustUnseal(client); err != nil {
				return fmt.Errorf("auto-unseal failed: %w", err)
			}
			return nil
		}
		if !status.Sealed && !status.Standby {
			return nil
		}
		if status.Standby {
			zap.L().Info("🟡 Vault is in standby — treating as healthy")
			return nil
		}

		zap.L().Warn("⚠️ Unexpected health state", zap.Any("response", status))
		time.Sleep(shared.VaultRetryDelay)
	}
	return fmt.Errorf("vault not healthy after %d attempts", shared.VaultRetryCount)
}

func CheckVaultHealth() (bool, error) {
	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		return false, fmt.Errorf("VAULT_ADDR not set")
	}

	resp, err := http.Get(strings.TrimRight(addr, "/") + shared.VaultHealthPath)
	if err != nil {
		return false, fmt.Errorf("vault not responding: %w", err)
	}
	defer shared.SafeClose(resp.Body)

	switch resp.StatusCode {
	case 200, 429:
		return true, nil
	case 501, 503:
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected vault health: %s", body)
	}
}

func recoverVaultHealth(client *api.Client) error {
	status, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health API call failed: %w", err)
	}

	switch {
	case !status.Initialized:
		zap.L().Info("💥 Vault uninitialized — running init + unseal flow")
		_, err := UnsealVault()
		return err
	case status.Sealed:
		zap.L().Info("🔒 Vault sealed — attempting fallback unseal")
		return MustUnseal(client)
	default:
		return fmt.Errorf("unexpected vault state: initialized=%v sealed=%v", status.Initialized, status.Sealed)
	}
}

func isVaultProcessRunning() bool {
	out, err := exec.Command("lsof", "-i", shared.VaultDefaultPort).Output()
	if err != nil {
		zap.L().Warn("⚠️ lsof command failed (process check skipped)", zap.Error(err))
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "vault") && strings.Contains(line, shared.EosUser) {
			return true
		}
	}
	return false
}
