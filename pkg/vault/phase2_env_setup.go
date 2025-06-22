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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

func PrepareEnvironment(rc *eos_io.RuntimeContext) error {
	if _, err := EnsureVaultEnv(rc); err != nil {
		return err
	}
	if err := eos_unix.EnsureEosUser(rc.Ctx, true, false); err != nil {
		return err
	}
	if err := EnsureVaultDirs(rc); err != nil {
		return err
	}
	if err := PrepareVaultAgentEnvironment(rc); err != nil {
		return err
	}
	return nil
}

func EnsureVaultEnv(rc *eos_io.RuntimeContext) (string, error) {
	const testTimeout = 500 * time.Millisecond

	// 1. Return if already set
	if cur := os.Getenv(shared.VaultAddrEnv); cur != "" {
		otelzap.Ctx(rc.Ctx).Debug("VAULT_ADDR already set", zap.String(shared.VaultAddrEnv, cur))
		return cur, nil
	}

	// 2. Always use internal hostname as the Vault address
	host := eos_unix.GetInternalHostname()
	addr := fmt.Sprintf(shared.VaultDefaultAddr, host)

	// 3. Probe TLS before setting
	if canConnectTLS(rc, addr, testTimeout) {
		_ = os.Setenv(shared.VaultAddrEnv, addr)
		otelzap.Ctx(rc.Ctx).Info("🔐 VAULT_ADDR validated and set", zap.String(shared.VaultAddrEnv, addr))
	} else {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ VAULT_ADDR unreachable over TLS — setting anyway", zap.String("addr", addr))
		_ = os.Setenv(shared.VaultAddrEnv, addr)
	}

	// 4. Set CA cert path if missing
	if os.Getenv(shared.VaultCA) == "" {
		_ = os.Setenv(shared.VaultCA, shared.VaultAgentCACopyPath)
		otelzap.Ctx(rc.Ctx).Debug("🔧 Auto-set VAULT_CACERT", zap.String("path", shared.VaultAgentCACopyPath))
	}

	return addr, nil
}

func canConnectTLS(rc *eos_io.RuntimeContext, raw string, d time.Duration) bool {
	u, err := url.Parse(raw)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Debug("Invalid URL for TLS check", zap.String("raw", raw), zap.Error(err))
		return false
	}
	dialer := &net.Dialer{Timeout: d}
	
	// Use secure TLS configuration for production, allow insecure only for testing
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	
	// Only skip verification in development/testing environments
	if os.Getenv("EOS_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		tlsConfig.InsecureSkipVerify = true
		otelzap.Ctx(rc.Ctx).Debug("Using insecure TLS for development/testing", zap.String("host", u.Host))
	}
	
	conn, err := tls.DialWithDialer(dialer, "tcp", u.Host, tlsConfig)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Debug("TLS probe failed", zap.String("host", u.Host), zap.Error(err))
		return false
	}
	_ = conn.Close()
	return true
}

func EnsureVaultDirs(rc *eos_io.RuntimeContext) error {
	zap.S().Info("Ensuring Vault directories…")
	if err := createBaseDirs(rc); err != nil {
		return err
	}
	// ⚠️ now pass ctx
	if err := secureVaultDirOwnership(rc); err != nil {
		return err
	}
	return nil
}

func createBaseDirs(rc *eos_io.RuntimeContext) error {
	eosUID, eosGID, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Critical error: eos system user not found. Vault environment cannot be safely prepared.", zap.Error(err))
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
		otelzap.Ctx(rc.Ctx).Debug("🔧 Creating directory", zap.String("path", d.path))
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
		if err := os.Chown(d.path, eosUID, eosGID); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to chown directory", zap.String("path", d.path), zap.Error(err))
		}
	}
	return nil
}

// secureVaultDirOwnership chowns the entire Vault directory tree to eos.
// It starts a telemetry span, logs via Zap, and wraps errors with cerr.
func secureVaultDirOwnership(rc *eos_io.RuntimeContext) error {

	// find eos UID/GID
	eosUID, eosGID, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		zap.S().Errorw("lookup eos user failed",
			"user", shared.EosID, "error", err,
		)
		return cerr.Wrapf(err, "lookup user %q", shared.EosID)
	}

	// log intent
	zap.S().Infow("fixing Vault directory ownership",
		"path", shared.VaultDir,
		"uid", eosUID,
		"gid", eosGID,
	)

	// perform recursive chown
	if err := eos_unix.ChownR(rc.Ctx, shared.VaultDir, eosUID, eosGID); err != nil {
		zap.S().Errorw("chownR failed",
			"path", shared.VaultDir, "error", err,
		)
		return cerr.Wrapf(err, "chownR %s", shared.VaultDir)
	}

	zap.S().Infow("Vault directory ownership fixed", "path", shared.VaultDir)
	return nil
}

func PrepareVaultAgentEnvironment(rc *eos_io.RuntimeContext) error {
	if err := os.MkdirAll(shared.EosRunDir, shared.FilePermOwnerRWX); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info("Ensured runtime directory", zap.String("path", shared.EosRunDir))

	if err := os.MkdirAll(shared.SecretsDir, shared.FilePermOwnerRWX); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create secrets directory", zap.String("path", shared.SecretsDir), zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info("Ensured secrets directory", zap.String("path", shared.SecretsDir))

	// ✨ NEW: Validate runtime readiness
	if err := ValidateVaultAgentRuntimeEnvironment(rc); err != nil {
		return err
	}

	return nil
}

func ValidateVaultAgentRuntimeEnvironment(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info("🔍 Validating Vault Agent runtime environment")

	// Resolve eos user UID and GID safely
	eosUID, eosGID, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to lookup eos user", zap.Error(err))
		return fmt.Errorf("failed to lookup eos user: %w", err)
	}

	// Check if /run/eos exists and is a directory
	info, err := os.Stat(shared.EosRunDir)
	if os.IsNotExist(err) {
		otelzap.Ctx(rc.Ctx).Error("❌ Missing runtime directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("missing runtime directory: %s", shared.EosRunDir)
	}
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to stat runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return fmt.Errorf("failed to stat runtime directory: %w", err)
	}
	if !info.IsDir() {
		otelzap.Ctx(rc.Ctx).Error("❌ Runtime path is not a directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("runtime path is not a directory: %s", shared.EosRunDir)
	}

	// Check ownership of the runtime directory
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Unable to get ownership info of runtime directory")
	} else {
		currentUID := stat.Uid
		currentGID := stat.Gid
		
		// Safely convert int to uint32 with bounds checking
		if eosUID < 0 || eosGID < 0 {
			otelzap.Ctx(rc.Ctx).Error("❌ Invalid eos user UID/GID", 
				zap.Int("uid", eosUID), 
				zap.Int("gid", eosGID))
			return fmt.Errorf("invalid eos user UID/GID: %d/%d", eosUID, eosGID)
		}
		
		// #nosec G115 - Safe conversion after bounds checking above
		expectedUID := uint32(eosUID)
		// #nosec G115 - Safe conversion after bounds checking above  
		expectedGID := uint32(eosGID)
		
		if currentUID != expectedUID || currentGID != expectedGID {
			otelzap.Ctx(rc.Ctx).Warn("⚠️ Runtime directory not owned by eos user",
				zap.String("path", shared.EosRunDir),
				zap.Uint32("current_uid", currentUID),
				zap.Uint32("current_gid", currentGID),
				zap.Uint32("expected_uid", expectedUID),
				zap.Uint32("expected_gid", expectedGID),
			)
		}
	}

	// Check if Vault binary exists in PATH
	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Vault binary not found in PATH", zap.Error(err))
		return fmt.Errorf("vault binary not found in PATH: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info("✅ Vault binary found", zap.String("vault_path", vaultPath))

	return nil
}
