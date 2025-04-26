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
// 7. Final Vault Health Check and Recovery
//--------------------------------------------------------------------

// CheckVaultHealth probes Vault's /v1/sys/health and returns whether Vault is healthy.
func CheckVaultHealth(log *zap.Logger) (bool, error) {
	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		log.Error("❌ VAULT_ADDR not set")
		return false, fmt.Errorf("VAULT_ADDR not set")
	}

	healthURL := strings.TrimRight(addr, "/") + shared.VaultHealthPath
	client := http.Client{
		Timeout: shared.VaultHealthTimeout,
	}

	resp, err := client.Get(healthURL)
	if err != nil {
		log.Error("❌ Vault health check request failed", zap.String("url", healthURL), zap.Error(err))
		return false, fmt.Errorf("vault not responding at %s: %w", addr, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		log.Info("✅ Vault is healthy", zap.String("VAULT_ADDR", addr))
		return true, nil
	case 429:
		log.Warn("⚠️ Vault is overloaded (429)", zap.String("VAULT_ADDR", addr))
		return true, nil // still usable
	case 501:
		log.Warn("⚠️ Vault is uninitialized (501)", zap.String("VAULT_ADDR", addr))
		return false, nil
	case 503:
		log.Warn("⚠️ Vault is sealed or standby (503)", zap.String("VAULT_ADDR", addr))
		return false, nil
	default:
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Warn("⚠️ Failed to read Vault health body", zap.Error(readErr))
		}
		log.Error("🚨 Vault unhealthy", zap.Int("status_code", resp.StatusCode), zap.String("body", string(body)))
		return false, fmt.Errorf("vault unhealthy: %s", string(body))
	}
}

// PhaseEnsureVaultReady ensures Vault is running, healthy, and ready for use.
func PhaseEnsureVaultReady(log *zap.Logger) error {
	log.Info("🚀 [Phase] Ensuring Vault is ready")

	if isVaultProcessRunning(log) {
		log.Info("✅ Vault process already running (lsof check)")
		return nil
	}

	if _, err := EnsureVaultEnv(log); err != nil {
		return fmt.Errorf("could not resolve VAULT_ADDR: %w", err)
	}

	client, err := NewClient(log)
	if err != nil {
		return fmt.Errorf("could not create Vault client: %w", err)
	}

	if err := probeVaultHealthUntilReady(log); err == nil {
		log.Info("✅ Vault healthy after probe")
		return nil
	}

	log.Warn("⚠️ Vault did not become healthy after retries — attempting recovery")
	return recoverVaultHealth(client, log)
}

// probeVaultHealthUntilReady probes Vault health repeatedly until success or retries exhausted.
func probeVaultHealthUntilReady(log *zap.Logger) error {
	for attempt := 1; attempt <= shared.VaultRetryCount; attempt++ {
		log.Info("🔁 Vault health probe", zap.Int("attempt", attempt))

		healthy, err := CheckVaultHealth(log)
		if healthy && err == nil {
			return nil
		}
		if err != nil {
			log.Warn("🛑 Vault not healthy, retrying...", zap.Error(err))
		} else {
			log.Warn("🛑 Vault not healthy, retrying...")
		}

		log.Warn("🛑 Vault not healthy, retrying...", zap.Error(err))
		time.Sleep(shared.VaultRetryDelay)
	}
	return fmt.Errorf("vault not healthy after %d attempts", shared.VaultRetryCount)
}

// recoverVaultHealth attempts initialization or unsealing based on Vault health status.
func recoverVaultHealth(client *api.Client, log *zap.Logger) error {
	health, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health API call failed: %w", err)
	}

	switch {
	case !health.Initialized:
		log.Info("💥 Vault uninitialized — running initialization")
		return initAndUnseal(client, log)

	case health.Sealed:
		log.Info("🔒 Vault sealed — attempting unseal from fallback")
		return unsealFromStoredKeys(client, log)

	default:
		log.Warn("❓ Unexpected Vault health state after retries; manual intervention may be required")
		return fmt.Errorf("unexpected vault health state: initialized=%v sealed=%v", health.Initialized, health.Sealed)
	}
}

// isVaultProcessRunning checks if a Vault process is active and bound to the expected TCP port.
func isVaultProcessRunning(log *zap.Logger) bool {
	out, err := exec.Command("lsof", "-i", shared.VaultDefaultPort).Output()
	if err != nil {
		log.Warn("⚠️ lsof command failed", zap.Error(err))
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "vault") && strings.Contains(line, shared.EosUser) {
			return true
		}
	}
	return false
}
