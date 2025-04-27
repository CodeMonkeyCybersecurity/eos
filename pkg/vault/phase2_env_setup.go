// pkg/vault/phase2_env_setup.go

package vault

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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

	if err := createBaseDirs(log); err != nil {
		return err
	}
	if err := secureTLSFiles(log); err != nil {
		return err
	}
	if err := secureVaultDirOwnership(log); err != nil {
		return err
	}

	return nil
}

func createBaseDirs(log *zap.Logger) error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Error("❌ Critical error: eos system user not found. Vault environment cannot be safely prepared.", zap.Error(err))
		return fmt.Errorf("critical: eos system user not found: %w", err)
	}

	dirs := []struct {
		path string
		perm os.FileMode
	}{
		{path: shared.VaultDir, perm: shared.FilePermOwnerRWX},
		{path: filepath.Join(shared.VaultDir, "data"), perm: shared.FilePermOwnerRWX},
		{path: shared.TLSDir, perm: 0750},
		{path: shared.SecretsDir, perm: shared.FilePermOwnerRWX},
		{path: shared.EosRunDir, perm: shared.FilePermOwnerRWX},
		{path: filepath.Dir(shared.VaultAgentCACopyPath), perm: shared.FilePermOwnerRWX},
		{path: filepath.Join(shared.VaultDir, "logs"), perm: 0700},
	}

	for _, d := range dirs {
		log.Debug("🔧 Creating directory", zap.String("path", d.path))
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
		if err := os.Chown(d.path, eosUID, eosGID); err != nil {
			log.Warn("⚠️ Failed to chown directory", zap.String("path", d.path), zap.Error(err))
		}
	}
	return nil
}

func secureTLSFiles(log *zap.Logger) error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser) // 🔥 Change back to eos
	if err != nil {
		log.Warn("⚠️ Could not resolve eos UID/GID for TLS files", zap.Error(err))
		eosUID, eosGID = 1001, 1001
	}

	tlsFiles := []struct {
		path string
		perm os.FileMode
	}{
		{shared.TLSKey, 0600},
		{shared.TLSCrt, 0644},
	}

	for _, tf := range tlsFiles {
		log.Debug("🔧 Securing TLS file", zap.String("path", tf.path))
		if err := os.Chown(tf.path, eosUID, eosGID); err != nil {
			log.Error("❌ Failed to chown TLS file", zap.String("path", tf.path), zap.Error(err))
			return fmt.Errorf("failed to secure %s: %w", tf.path, err)
		}
		if err := os.Chmod(tf.path, tf.perm); err != nil {
			log.Error("❌ Failed to chmod TLS file", zap.String("path", tf.path), zap.Error(err))
			return fmt.Errorf("failed to secure %s: %w", tf.path, err)
		}
	}
	return nil
}

func secureVaultDirOwnership(log *zap.Logger) error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Warn("⚠️ Could not resolve eos UID/GID for Vault base", zap.Error(err))
		eosUID, eosGID = 1001, 1001
	}

	log.Info("🔧 Recursively fixing Vault directory ownership", zap.String("path", shared.VaultDir))
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

	// ✨ NEW: Validate runtime readiness
	if err := ValidateVaultAgentRuntimeEnvironment(log); err != nil {
		return err
	}

	return nil
}

func ValidateVaultAgentRuntimeEnvironment(log *zap.Logger) error {
	log.Info("🔍 Validating Vault Agent runtime environment")

	// 1. Check if /run/eos exists and is owned by eos
	info, err := os.Stat(shared.EosRunDir)
	if os.IsNotExist(err) {
		log.Error("❌ Missing runtime directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("missing runtime directory: %s", shared.EosRunDir)
	}
	if err != nil {
		log.Error("❌ Failed to stat runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return fmt.Errorf("failed to stat runtime directory: %w", err)
	}
	if !info.IsDir() {
		log.Error("❌ Runtime path is not a directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("runtime path is not a directory: %s", shared.EosRunDir)
	}
	stat := info.Sys()
	if stat == nil {
		log.Warn("⚠️ Unable to get ownership info of runtime directory")
	} else {
		if stat.(*syscall.Stat_t).Uid != 1001 { // 🔥 Assume eos UID 1001 or resolve dynamically
			log.Warn("⚠️ Runtime directory not owned by eos user", zap.String("path", shared.EosRunDir))
		}
	}

	// 2. Check if Vault binary exists
	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		log.Error("❌ Vault binary not found in PATH", zap.Error(err))
		return fmt.Errorf("vault binary not found in PATH: %w", err)
	}
	log.Info("✅ Vault binary found", zap.String("vault_path", vaultPath))

	return nil
}
