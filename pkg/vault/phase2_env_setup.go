// pkg/vault/vault_lifecycle.go

package vault

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 2.  Set Vault Environment and Ensure eos System User
//--------------------------------------------------------------------

// PHASE 2 — EnsureVaultEnv() + EnsureEosUser() + EnsureVaultDirs() + PrepareVaultAgentEnvironment()
// canConnectTLS

// EnsureVaultAddr sets VAULT_ADDR if missing.
//
//  1. Prefer an existing HTTPS listener on 127.0.0.1:<VaultDefaultPort>
//  2. Else try https://<internal‑hostname>:<VaultDefaultPort>
//  3. Else fall back to the hostname form so callers have *something*

// EnsureVaultEnv sets VAULT_ADDR and VAULT_CACERT if missing, using available network probes and fallbacks.

//--------------------------------------------------------------------
// Phase 2: Ensure Vault Environment and Directories
//--------------------------------------------------------------------

func EnsureVaultEnv(log *zap.Logger) (string, error) {
	const testTimeout = 500 * time.Millisecond

	if cur := os.Getenv(shared.VaultAddrEnv); cur != "" {
		log.Debug("VAULT_ADDR already set", zap.String(shared.VaultAddrEnv, cur))
		return cur, nil
	}

	host := system.GetInternalHostname()
	candidates := []string{
		fmt.Sprintf("https://127.0.0.1:%s", shared.VaultDefaultPort),
		fmt.Sprintf(shared.VaultDefaultAddr, host),
	}

	for _, addr := range candidates {
		if canConnectTLS(addr, testTimeout, log) {
			_ = os.Setenv(shared.VaultAddrEnv, addr)
			log.Info("🔐 VAULT_ADDR auto-detected", zap.String(shared.VaultAddrEnv, addr))
			return addr, nil
		}
	}

	log.Warn("⚠️ No Vault listener detected — falling back to internal hostname")

	_ = os.Setenv(shared.VaultAddrEnv, candidates[1])
	if os.Getenv(shared.VaultCA) == "" {
		_ = os.Setenv(shared.VaultCA, shared.VaultAgentCACopyPath)
		log.Debug("🔧 Auto-set VAULT_CACERT", zap.String("path", shared.VaultAgentCACopyPath))
	}

	return candidates[1], nil
}

func canConnectTLS(raw string, d time.Duration, log *zap.Logger) bool {
	u, err := url.Parse(raw)
	if err != nil {
		log.Debug("Invalid URL for TLS check", zap.String("raw", raw), zap.Error(err))
		return false
	}
	dialer := &net.Dialer{Timeout: d}
	conn, err := tls.DialWithDialer(dialer, "tcp", u.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Debug("TLS probe failed", zap.String("host", u.Host), zap.Error(err))
		return false
	}
	_ = conn.Close()
	return true
}

func EnsureVaultDirs(log *zap.Logger) error {
	log.Info("🔧 Ensuring Vault directories and ownerships")

	if err := ensureBaseDirs(log); err != nil {
		return err
	}
	if err := fixVaultTLSFiles(log); err != nil {
		return err
	}
	if err := fixVaultOwnership(log); err != nil {
		return err
	}

	return nil
}

// ensureBaseDirs creates core directories needed by eos and vault.
func ensureBaseDirs(log *zap.Logger) error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Warn("Could not resolve eos UID/GID, using fallback", zap.Error(err))
		eosUID, eosGID = 1001, 1001
	}

	dirs := []string{
		shared.SecretsDir,
		shared.EosRunDir,
		shared.TLSDir,
		filepath.Dir(shared.VaultAgentCACopyPath),
		shared.VaultDir,                      // <--- NEW
		filepath.Join(shared.VaultDir, "data"), // <--- NEW
	}

	for _, path := range dirs {
		log.Debug("🔧 Creating directory", zap.String("path", path))
		if err := os.MkdirAll(path, shared.FilePermOwnerRWX); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
		if err := os.Chown(path, eosUID, eosGID); err != nil {
			log.Warn("⚠️ Failed to chown directory", zap.String("path", path), zap.Error(err))
		}
	}
	return nil
}

// fixVaultTLSFiles ensures correct permissions on TLS key/cert files.
func fixVaultTLSFiles(log *zap.Logger) error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Warn("Could not resolve eos UID/GID for TLS files", zap.Error(err))
		eosUID, eosGID = 1001, 1001
	}

	tlsFiles := []struct {
		path string
		perm os.FileMode
	}{
		{shared.TLSKey, shared.FilePermOwnerReadWrite},
		{shared.TLSCrt, shared.FilePermStandard},
	}

	for _, tf := range tlsFiles {
		log.Debug("🔧 Securing TLS file", zap.String("path", tf.path))
		if err := os.Chown(tf.path, eosUID, eosGID); err != nil {
			log.Warn("Failed to chown TLS file", zap.String("path", tf.path), zap.Error(err))
		}
		if err := os.Chmod(tf.path, tf.perm); err != nil {
			log.Warn("Failed to chmod TLS file", zap.String("path", tf.path), zap.Error(err))
		}
	}
	return nil
}

// fixVaultOwnership ensures /opt/vault and its contents are eos:eos
func fixVaultOwnership(log *zap.Logger) error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Warn("Could not resolve eos UID/GID for vault directories", zap.Error(err))
		eosUID, eosGID = 1001, 1001
	}

	log.Info("🔧 Fixing Vault base directory ownership", zap.String("path", shared.VaultDir))
	if err := os.Chown(shared.VaultDir, eosUID, eosGID); err != nil {
		log.Warn("⚠️ Could not chown Vault base directory", zap.String("path", shared.VaultDir), zap.Error(err))
	}

	log.Info("🔧 Recursively fixing ownership inside Vault base directory", zap.String("path", shared.VaultDir))
	return system.ChownRecursive(shared.VaultDir, eosUID, eosGID, log)
}

func PrepareVaultAgentEnvironment(log *zap.Logger) error {
	if err := os.MkdirAll(shared.EosRunDir, shared.FilePermOwnerRWX); err != nil {
		log.Error("Failed to create runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return err
	}
	log.Info("Ensured runtime directory", zap.String("path", shared.EosRunDir))

	if err := os.MkdirAll(shared.SecretsDir, shared.FilePermOwnerRWX); err != nil {
		log.Error("Failed to create secrets directory", zap.String("path", shared.SecretsDir), zap.Error(err))
		return err
	}
	log.Info("Ensured secrets directory", zap.String("path", shared.SecretsDir))
	return nil
}
