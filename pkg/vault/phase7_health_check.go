// pkg/vault/phase7_health_check.go

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

//--------------------------------------------------------------------
// 7. Vault Health Check and Recovery
//--------------------------------------------------------------------

// PHASE 7 — PhaseEnsureVaultHealthy()
//          └── isVaultProcessRunning()
//          └── EnsureVaultEnv()
//          └── NewClient()
//          └── probeVaultHealthUntilReady()
//               └── CheckVaultHealth()
//          └── recoverVaultHealth()
//               └── initAndUnseal()
//               └── unsealFromStoredKeys()

// PhaseEnsureVaultHealthy ensures Vault is running, healthy, and ready for use.
func PhaseEnsureVaultHealthy() error {
	zap.L().Info("🚀 [Phase 7] Ensuring Vault is ready")

	if isVaultProcessRunning() {
		zap.L().Info("✅ Vault process running (lsof check)") // NOTE: Only TCP presence, not real health
	}

	if _, err := EnsureVaultEnv(); err != nil {
		return fmt.Errorf("could not resolve VAULT_ADDR: %w", err)
	}

	client, err := NewClient()
	if err != nil {
		return fmt.Errorf("could not create Vault client: %w", err)
	}

	if err := probeVaultHealthUntilReady(); err == nil {
		zap.L().Info("✅ Vault healthy after probe")
		return nil
	}

	zap.L().Warn("⚠️ Vault did not become healthy after retries — attempting recovery")
	return recoverVaultHealth(client)
}

// CheckVaultHealth probes Vault's /v1/sys/health and returns whether Vault is healthy.
func CheckVaultHealth() (bool, error) {
	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		zap.L().Error("❌ VAULT_ADDR not set")
		return false, fmt.Errorf("VAULT_ADDR not set")
	}

	healthURL := strings.TrimRight(addr, "/") + shared.VaultHealthPath
	client := http.Client{Timeout: shared.VaultHealthTimeout}

	resp, err := client.Get(healthURL)
	if err != nil {
		zap.L().Error("❌ Vault health check request failed", zap.String("url", healthURL), zap.Error(err))
		return false, fmt.Errorf("vault not responding at %s: %w", addr, err)
	}
	defer shared.SafeClose(resp.Body)

	switch resp.StatusCode {
	case 200:
		zap.L().Info("✅ Vault is healthy", zap.String(shared.VaultAddrEnv, addr))
		return true, nil
	case 429:
		zap.L().Warn("⚠️ Vault is overloaded (429)", zap.String(shared.VaultAddrEnv, addr))
		return true, nil // still usable
	case 501:
		zap.L().Warn("⚠️ Vault is uninitialized (501)", zap.String(shared.VaultAddrEnv, addr))
		return false, nil
	case 503:
		zap.L().Warn("⚠️ Vault is sealed or standby (503)", zap.String(shared.VaultAddrEnv, addr))
		return false, nil
	default:
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			zap.L().Warn("⚠️ Failed to read Vault health body", zap.Error(readErr))
		}
		zap.L().Error("🚨 Vault unhealthy", zap.Int("status_code", resp.StatusCode), zap.String("body", string(body)))
		return false, fmt.Errorf("vault unhealthy: %s", string(body))
	}
}

// probeVaultHealthUntilReady probes Vault health repeatedly until success or retries exhausted.
func probeVaultHealthUntilReady() error {
	for attempt := 1; attempt <= shared.VaultRetryCount; attempt++ {
		zap.L().Info("🔁 Vault health probe", zap.Int("attempt", attempt))

		healthy, err := CheckVaultHealth()
		if healthy && err == nil {
			return nil
		}
		if err != nil {
			zap.L().Warn("🛑 Vault health check failed", zap.Int("attempt", attempt), zap.Error(err))
		} else {
			zap.L().Warn("🛑 Vault unhealthy (no explicit error)", zap.Int("attempt", attempt))
		}

		time.Sleep(shared.VaultRetryDelay)
	}
	return fmt.Errorf("vault not healthy after %d attempts", shared.VaultRetryCount)
}

// recoverVaultHealth attempts initialization or unsealing based on Vault health status.
func recoverVaultHealth(client *api.Client) error {
	health, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health API call failed: %w", err)
	}

	switch {
	case !health.Initialized:
		zap.L().Info("💥 Vault uninitialized — running initialization")
		return initAndUnseal(client)

	case health.Sealed:
		zap.L().Info("🔒 Vault sealed — attempting unseal from fallback")
		return MustUnseal(client)

	default:
		zap.L().Warn("❓ Unexpected Vault health state after retries; manual intervention may be required")
		return fmt.Errorf("unexpected vault health state: initialized=%v sealed=%v", health.Initialized, health.Sealed)
	}
}

// isVaultProcessRunning checks if a Vault process is active and bound to the expected TCP port.
// Linux-only: relies on lsof syntax.
func isVaultProcessRunning() bool {
	out, err := exec.Command("sudo", "lsof", "-i", shared.VaultDefaultPort).Output()
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
