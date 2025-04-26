// pkg/vault/vault_lifecycle.go

package vault

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 7.  Final Vault Health Check
//--------------------------------------------------------------------

// PHASE 7 — CheckVaultHealth()

// CheckVaultHealth probes the Vault server's /v1/sys/health endpoint.
// It returns the resolved VAULT_ADDR and an error if the server is unhealthy or unreachable.
func CheckVaultHealth(log *zap.Logger) (string, error) {

	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		log.Error("❌ VAULT_ADDR not set")
		return "", fmt.Errorf("VAULT_ADDR not set")
	}

	healthURL := strings.TrimRight(addr, "/") + shared.VaultHealthPath
	client := http.Client{
		Timeout: shared.VaultHealthTimeout,
	}

	resp, err := client.Get(healthURL)
	if err != nil {
		log.Error("❌ Vault health check request failed", zap.String("url", healthURL), zap.Error(err))
		return addr, fmt.Errorf("vault not responding at %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(resp.Body) // intentionally ignoring read error here
		log.Error("🚨 Vault unhealthy", zap.Int("status_code", resp.StatusCode), zap.String("body", string(body)))
		return addr, fmt.Errorf("vault unhealthy: %s", string(body))
	}

	log.Info("✅ Vault responded to health check", zap.String("VAULT_ADDR", addr))
	return addr, nil
}
