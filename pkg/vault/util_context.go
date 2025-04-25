/* pkg/vault/context.go */

package vault

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

const testTimeout = 500 * time.Millisecond // one‑shot probe timeout

// EnsureVaultAddr sets VAULT_ADDR if missing.
//
//  1. Prefer an existing HTTPS listener on 127.0.0.1:<VaultDefaultPort>
//  2. Else try https://<internal‑hostname>:<VaultDefaultPort>
//  3. Else fall back to the hostname form so callers have *something*
func EnsureVaultEnv(log *zap.Logger) (string, error) {
	if cur := os.Getenv("VAULT_ADDR"); cur != "" {
		log.Debug("VAULT_ADDR already set", zap.String("VAULT_ADDR", cur))
		return cur, nil
	}

	host := system.GetInternalHostname()

	candidates := []string{
		fmt.Sprintf("https://127.0.0.1:%s", shared.VaultDefaultPort),
		fmt.Sprintf(shared.VaultDefaultAddr, host), // e.g. https://myhost:8179
	}

	for _, addr := range candidates {
		if canConnectTLS(addr, testTimeout) {
			_ = os.Setenv("VAULT_ADDR", addr)
			log.Info("🔐 VAULT_ADDR auto‑detected", zap.String("VAULT_ADDR", addr))
			return addr, nil
		}
	}

	// ensure CA
	if os.Getenv("VAULT_CACERT") == "" {
		log.Debug("🔧 Auto‑setting VAULT_CACERT", zap.String("path", shared.VaultAgentCACopyPath))
		os.Setenv("VAULT_CACERT", shared.VaultAgentCACopyPath)
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

/**/
func EnsureVaultDirs(log *zap.Logger) error {
	// Directories to create + who should own them
	dirs := []struct {
		path  string
		owner string // system.LookupUser key
		perm  os.FileMode
	}{
		{shared.SecretsDir, shared.EosUser, shared.FilePermOwnerRWX},                         // /var/lib/eos/secrets
		{shared.EosRunDir, shared.EosUser, shared.FilePermOwnerRWX},                          // /run/eos
		{shared.TLSDir, "vault", shared.FilePermOwnerRWX},                                    // where tls.key/.crt live
		{filepath.Dir(shared.VaultAgentCACopyPath), shared.EosUser, shared.FilePermOwnerRWX}, // parent of agent CA copy
	}

	// Resolve UIDs/GIDs
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Warn("⚠️ Could not resolve eos UID/GID, falling back to 1001:1001", zap.Error(err))
		eosUID, eosGID = 1001, 1001
	}
	vaultUID, vaultGID, err := system.LookupUser("vault")
	if err != nil {
		log.Warn("⚠️ Could not resolve vault UID/GID, vault‑owned files may be wrong", zap.Error(err))
		vaultUID, vaultGID = 0, 0
	}

	// 1) Create & fix ownership/perms on each directory
	for _, d := range dirs {
		log.Debug("🔧 Ensuring directory exists", zap.String("path", d.path))
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			log.Error("❌ Failed to create directory", zap.String("path", d.path), zap.Error(err))
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
		log.Info("✅ Directory created/exists", zap.String("path", d.path), zap.String("perm", fmt.Sprintf("%#o", d.perm)))

		info, err := os.Stat(d.path)
		if err != nil {
			log.Warn("⚠️ Could not stat directory after creation", zap.String("path", d.path), zap.Error(err))
			continue
		}
		st := info.Sys().(*syscall.Stat_t)

		// Decide which owner to apply
		var uid, gid int
		if d.owner == shared.EosUser {
			uid, gid = eosUID, eosGID
		} else {
			uid, gid = vaultUID, vaultGID
		}
		if int(st.Uid) != uid || int(st.Gid) != gid {
			if err := os.Chown(d.path, uid, gid); err != nil {
				log.Warn("⚠️ Could not chown directory", zap.String("path", d.path), zap.Int("uid", uid), zap.Int("gid", gid), zap.Error(err))
			} else {
				log.Info("🔐 Set directory ownership", zap.String("path", d.path), zap.Int("uid", uid), zap.Int("gid", gid))
			}
		}
	}

	// 2) Secure TLS files (key, cert) under TLSDir as vault:vault
	tlsFiles := []struct {
		path string
		perm os.FileMode
	}{
		{shared.TLSKey, shared.FilePermOwnerReadWrite},
		{shared.TLSCrt, shared.FilePermStandard},
	}
	for _, tf := range tlsFiles {
		log.Debug("🔧 Securing TLS file", zap.String("path", tf.path))
		if err := os.Chown(tf.path, vaultUID, vaultGID); err != nil {
			log.Warn("⚠️ Chown TLS file failed", zap.String("path", tf.path), zap.Error(err))
		} else {
			log.Info("✅ TLS file ownership set", zap.String("path", tf.path), zap.Int("uid", vaultUID), zap.Int("gid", vaultGID))
		}
		if err := os.Chmod(tf.path, tf.perm); err != nil {
			log.Warn("⚠️ Chmod TLS file failed", zap.String("path", tf.path), zap.Error(err))
		} else {
			log.Info("✅ TLS file permissions set", zap.String("path", tf.path), zap.String("perm", fmt.Sprintf("%#o", tf.perm)))
		}
	}

	// 3) Copy the public CA into eos’s trust store and secure it
	log.Info("🔧 Copying Vault CA into eos trust store",
		zap.String("src", shared.TLSCrt),
		zap.String("dst", shared.VaultAgentCACopyPath),
	)
	if err := system.CopyFile(shared.TLSCrt, shared.VaultAgentCACopyPath, 0, log); err != nil {
		log.Warn("❌ Failed to copy CA cert for Vault Agent", zap.Error(err))
		return err
	}
	if err := os.Chown(shared.VaultAgentCACopyPath, eosUID, eosGID); err != nil {
		log.Warn("⚠️ Could not chown CA cert for eos user", zap.String("path", shared.VaultAgentCACopyPath), zap.Error(err))
	} else {
		log.Info("✅ CA cert ownership set", zap.String("path", shared.VaultAgentCACopyPath), zap.Int("uid", eosUID), zap.Int("gid", eosGID))
	}

	return nil
}

/**/
