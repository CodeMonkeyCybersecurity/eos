/* pkg/vault/context.go */

package vault

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"go.uber.org/zap"
)

const testTimeout = 500 * time.Millisecond // one‑shot probe timeout

// EnsureVaultAddr sets VAULT_ADDR if missing.
//
//  1. Prefer an existing HTTPS listener on 127.0.0.1:<VaultDefaultPort>
//  2. Else try https://<internal‑hostname>:<VaultDefaultPort>
//  3. Else fall back to the hostname form so callers have *something*
func EnsureVaultAddr(log *zap.Logger) (string, error) {
	if cur := os.Getenv("VAULT_ADDR"); cur != "" {
		log.Debug("VAULT_ADDR already set", zap.String("VAULT_ADDR", cur))
		return cur, nil
	}

	host := platform.GetInternalHostname()

	candidates := []string{
		fmt.Sprintf("https://127.0.0.1:%s", VaultDefaultPort),
		fmt.Sprintf(VaultDefaultAddr, host), // e.g. https://myhost:8179
	}

	for _, addr := range candidates {
		if canConnectTLS(addr, testTimeout) {
			_ = os.Setenv("VAULT_ADDR", addr)
			log.Info("🔐 VAULT_ADDR auto‑detected", zap.String("VAULT_ADDR", addr))
			return addr, nil
		}
	}

	// no live listener – just set to hostname form
	fallback := candidates[1]
	_ = os.Setenv("VAULT_ADDR", fallback)
	log.Warn("⚠️ No Vault listener detected; using fallback VAULT_ADDR",
		zap.String("VAULT_ADDR", fallback))
	return fallback, nil
}

// ---------- helpers ----------

// canConnectTLS opens a TLS socket (with InsecureSkipVerify=true **only for probe**).
func canConnectTLS(raw string, d time.Duration) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	dialer := &net.Dialer{Timeout: d}
	conn, err := tls.DialWithDialer(dialer, "tcp", u.Host, &tls.Config{
		InsecureSkipVerify: true, // probe only – we’re not sending secrets
	})
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}

// // tcpUp kept for completeness (currently unused by EnsureVaultAddr).
// func tcpUp(raw string, d time.Duration) bool {
// 	u, _ := url.Parse(raw)
// 	c, err := net.DialTimeout("tcp", u.Host, d)
// 	if err == nil {
// 		_ = c.Close()
// 		return true
// 	}
// 	return false
// }

// // GetVaultAddr returns the canonical HTTPS addr for internal hostname.
// func getVaultAddr() string {
// 	host := platform.GetInternalHostname()
// 	return fmt.Sprintf(VaultDefaultAddr, host) // VaultDefaultAddr is now "https://%s:8179"
// }
