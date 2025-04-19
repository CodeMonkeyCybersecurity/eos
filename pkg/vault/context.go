/* pkg/vault/context.go */

package vault

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"go.uber.org/zap"
)

// EnsureVaultAddr sets VAULT_ADDR if missing.
//
//  1.  Prefer an existing listener on 127.0.0.1:<VaultDefaultPort>
//  2.  Fallback to http://<internal‑hostname>:<VaultDefaultPort>
//

func EnsureVaultAddr(log *zap.Logger) (string, error) {
	if cur := os.Getenv("VAULT_ADDR"); cur != "" {
		log.Debug("VAULT_ADDR already set", zap.String("VAULT_ADDR", cur))
		return cur, nil
	}

	candidates := []string{
		fmt.Sprintf("http://%s", ListenerAddr),                                        // 127.0.0.1:8179
		fmt.Sprintf("http://%s:%s", platform.GetInternalHostname(), VaultDefaultPort), // hostname:8179
	}

	for _, addr := range candidates {
		if tcpUp(addr, 500*time.Millisecond) {
			_ = os.Setenv("VAULT_ADDR", addr)
			log.Info("🔐 VAULT_ADDR auto‑detected", zap.String("VAULT_ADDR", addr))
			return addr, nil
		}
	}

	// No listener yet – set to hostname form so downstream code has *something*.
	fallback := candidates[1]
	_ = os.Setenv("VAULT_ADDR", fallback)
	log.Warn("⚠️ No Vault listener detected; using fallback VAULT_ADDR",
		zap.String("VAULT_ADDR", fallback))
	return fallback, nil
}

// ---------- helpers ----------

func tcpUp(raw string, d time.Duration) bool {
	u, _ := url.Parse(raw) // error impossible – we built the URLs
	conn, err := net.DialTimeout("tcp", u.Host, d)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}

// GetVaultAddr returns the canonical Vault address based on internal hostname
func getVaultAddr() string {
	host := platform.GetInternalHostname()
	return fmt.Sprintf(VaultDefaultAddr, host)
}
