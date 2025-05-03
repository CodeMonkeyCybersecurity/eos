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

func PrepareEnvironment() error {
	if _, err := EnsureVaultEnv(); err != nil {
		return err
	}
	if err := system.EnsureEosUser(true, false); err != nil {
		return err
	}
	if err := EnsureVaultDirs(); err != nil {
		return err
	}
	if err := PrepareVaultAgentEnvironment(); err != nil {
		return err
	}
	return nil
}

func EnsureVaultEnv() (string, error) {
	const testTimeout = 500 * time.Millisecond

	if cur := os.Getenv(shared.VaultAddrEnv); cur != "" {
		zap.L().Debug("VAULT_ADDR already set", zap.String(shared.VaultAddrEnv, cur))
		return cur, nil
	}

	host := system.GetInternalHostname()
	candidates := []string{
		fmt.Sprintf("https://127.0.0.1:%s", shared.VaultDefaultPort),
		fmt.Sprintf(shared.VaultDefaultAddr, host),
	}

	for _, addr := range candidates {
		if canConnectTLS(addr, testTimeout) {
			_ = os.Setenv(shared.VaultAddrEnv, addr)
			zap.L().Info("🔐 VAULT_ADDR auto-detected", zap.String(shared.VaultAddrEnv, addr))
			return addr, nil
		}
	}

	zap.L().Warn("⚠️ No Vault listener detected — falling back to internal hostname")

	_ = os.Setenv(shared.VaultAddrEnv, candidates[1])
	if os.Getenv(shared.VaultCA) == "" {
		_ = os.Setenv(shared.VaultCA, shared.VaultAgentCACopyPath)
		zap.L().Debug("🔧 Auto-set VAULT_CACERT", zap.String("path", shared.VaultAgentCACopyPath))
	}

	return candidates[1], nil
}

func canConnectTLS(raw string, d time.Duration) bool {
	u, err := url.Parse(raw)
	if err != nil {
		zap.L().Debug("Invalid URL for TLS check", zap.String("raw", raw), zap.Error(err))
		return false
	}
	dialer := &net.Dialer{Timeout: d}
	conn, err := tls.DialWithDialer(dialer, "tcp", u.Host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		zap.L().Debug("TLS probe failed", zap.String("host", u.Host), zap.Error(err))
		return false
	}
	_ = conn.Close()
	return true
}

func EnsureVaultDirs() error {
	zap.L().Info("🔧 Ensuring Vault directories and ownerships")

	if err := createBaseDirs(); err != nil {
		return err
	}
	if err := secureVaultDirOwnership(); err != nil {
		return err
	}

	return nil
}

func createBaseDirs() error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		zap.L().Error("❌ Critical error: eos system user not found. Vault environment cannot be safely prepared.", zap.Error(err))
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
		zap.L().Debug("🔧 Creating directory", zap.String("path", d.path))
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
		if err := os.Chown(d.path, eosUID, eosGID); err != nil {
			zap.L().Warn("⚠️ Failed to chown directory", zap.String("path", d.path), zap.Error(err))
		}
	}
	return nil
}

func secureVaultDirOwnership() error {
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		zap.L().Error("❌ Failed to lookup eos user", zap.Error(err))
		return fmt.Errorf("failed to lookup eos user: %w", err)
	}

	zap.L().Info("🔧 Recursively fixing Vault directory ownership", zap.String("path", shared.VaultDir))
	return system.ChownRecursive(shared.VaultDir, eosUID, eosGID)
}

func PrepareVaultAgentEnvironment() error {
	if err := os.MkdirAll(shared.EosRunDir, shared.FilePermOwnerRWX); err != nil {
		zap.L().Error("Failed to create runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return err
	}
	zap.L().Info("Ensured runtime directory", zap.String("path", shared.EosRunDir))

	if err := os.MkdirAll(shared.SecretsDir, shared.FilePermOwnerRWX); err != nil {
		zap.L().Error("Failed to create secrets directory", zap.String("path", shared.SecretsDir), zap.Error(err))
		return err
	}
	zap.L().Info("Ensured secrets directory", zap.String("path", shared.SecretsDir))

	// ✨ NEW: Validate runtime readiness
	if err := ValidateVaultAgentRuntimeEnvironment(); err != nil {
		return err
	}

	return nil
}

func ValidateVaultAgentRuntimeEnvironment() error {
	zap.L().Info("🔍 Validating Vault Agent runtime environment")

	// Resolve eos user UID and GID safely
	eosUID, eosGID, err := system.LookupUser(shared.EosUser)
	if err != nil {
		zap.L().Error("❌ Failed to lookup eos user", zap.Error(err))
		return fmt.Errorf("failed to lookup eos user: %w", err)
	}

	// Check if /run/eos exists and is a directory
	info, err := os.Stat(shared.EosRunDir)
	if os.IsNotExist(err) {
		zap.L().Error("❌ Missing runtime directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("missing runtime directory: %s", shared.EosRunDir)
	}
	if err != nil {
		zap.L().Error("❌ Failed to stat runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return fmt.Errorf("failed to stat runtime directory: %w", err)
	}
	if !info.IsDir() {
		zap.L().Error("❌ Runtime path is not a directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("runtime path is not a directory: %s", shared.EosRunDir)
	}

	// Check ownership of the runtime directory
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		zap.L().Warn("⚠️ Unable to get ownership info of runtime directory")
	} else {
		currentUID := stat.Uid
		currentGID := stat.Gid
		if currentUID != uint32(eosUID) || currentGID != uint32(eosGID) {
			zap.L().Warn("⚠️ Runtime directory not owned by eos user",
				zap.String("path", shared.EosRunDir),
				zap.Uint32("current_uid", currentUID),
				zap.Uint32("current_gid", currentGID),
				zap.Int("expected_uid", eosUID),
				zap.Int("expected_gid", eosGID),
			)
		}
	}

	// Check if Vault binary exists in PATH
	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		zap.L().Error("❌ Vault binary not found in PATH", zap.Error(err))
		return fmt.Errorf("vault binary not found in PATH: %w", err)
	}
	zap.L().Info("✅ Vault binary found", zap.String("vault_path", vaultPath))

	return nil
}
