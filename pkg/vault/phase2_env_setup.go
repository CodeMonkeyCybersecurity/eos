// pkg/vault/phase2_env_setup.go

package vault

import (
	"crypto/tls"
	"crypto/x509"
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

// EnsureVaultEnv sets VAULT_ADDR if missing, using available network probes and fallbacks.
// Note: VAULT_CACERT is NOT set - we use VAULT_SKIP_VERIFY=1 for self-signed certificates instead.

//--------------------------------------------------------------------
// Phase 2: Ensure Vault Environment and Directories
//--------------------------------------------------------------------

func PrepareEnvironment(rc *eos_io.RuntimeContext) error {
	if _, err := EnsureVaultEnv(rc); err != nil {
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
		otelzap.Ctx(rc.Ctx).Info(" VAULT_ADDR validated and set", zap.String(shared.VaultAddrEnv, addr))
	} else {
		otelzap.Ctx(rc.Ctx).Warn("VAULT_ADDR unreachable over TLS — setting anyway", zap.String("addr", addr))
		_ = os.Setenv(shared.VaultAddrEnv, addr)
	}

	// Note: VAULT_CACERT not set here - we use VAULT_SKIP_VERIFY=1 for self-signed certs
	// The ca.crt file path was causing "Error loading CA File" failures because the file
	// doesn't exist at the expected location. For self-signed certificates, we skip
	// verification in CLI commands instead.
	otelzap.Ctx(rc.Ctx).Debug(" VAULT_CACERT not set - using VAULT_SKIP_VERIFY for self-signed certs")

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
	if os.Getenv("Eos_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		tlsConfig.InsecureSkipVerify = true
		otelzap.Ctx(rc.Ctx).Debug("Using insecure TLS for development/testing", zap.String("host", u.Host))
	} else {
		// SECURITY: Try to load custom CA certificate for self-signed Vault servers
		// This supports both system-trusted CAs and custom enterprise CAs
		caPaths := []string{
			"/etc/eos/ca.crt",              // Eos general CA
			"/etc/vault/tls/ca.crt",        // Vault standard location
			"/etc/ssl/certs/vault-ca.crt",  // Alternative location
		}

		for _, caPath := range caPaths {
			if _, err := os.Stat(caPath); os.IsNotExist(err) {
				continue
			}

			caCert, err := os.ReadFile(caPath)
			if err != nil {
				continue
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				continue
			}

			tlsConfig.RootCAs = caCertPool
			otelzap.Ctx(rc.Ctx).Debug("Loaded custom CA certificate for Vault TLS",
				zap.String("ca_path", caPath))
			break // Successfully loaded CA certificate
		}
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
	// now pass ctx
	if err := secureVaultDirOwnership(rc); err != nil {
		return err
	}
	return nil
}

func createBaseDirs(rc *eos_io.RuntimeContext) error {
	// Use vault user instead of deprecated eos user
	vaultUID, vaultGID, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		// If vault user doesn't exist, use current user
		vaultUID = os.Getuid()
		vaultGID = os.Getgid()
		otelzap.Ctx(rc.Ctx).Info("Vault user not found, using current user for directory ownership",
			zap.Int("uid", vaultUID),
			zap.Int("gid", vaultGID))
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
		otelzap.Ctx(rc.Ctx).Debug(" Creating directory", zap.String("path", d.path))
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
		if err := os.Chown(d.path, vaultUID, vaultGID); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to chown directory", zap.String("path", d.path), zap.Error(err))
		}
	}
	return nil
}

// secureVaultDirOwnership chowns the entire Vault directory tree to eos.
// It starts a telemetry span, logs via Zap, and wraps errors with cerr.
func secureVaultDirOwnership(rc *eos_io.RuntimeContext) error {

	// Use vault user instead of deprecated eos user
	vaultUID, vaultGID, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		// If vault user doesn't exist, use current user
		vaultUID = os.Getuid()
		vaultGID = os.Getgid()
		zap.S().Infow("vault user not found, using current user",
			"uid", vaultUID, "gid", vaultGID,
		)
	}

	// log intent
	zap.S().Infow("fixing Vault directory ownership",
		"path", shared.VaultDir,
		"uid", vaultUID,
		"gid", vaultGID,
	)

	// perform recursive chown
	if err := eos_unix.ChownR(rc.Ctx, shared.VaultDir, vaultUID, vaultGID); err != nil {
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

	//  NEW: Validate runtime readiness
	if err := ValidateVaultAgentRuntimeEnvironment(rc); err != nil {
		return err
	}

	return nil
}

func ValidateVaultAgentRuntimeEnvironment(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Validating Vault Agent runtime environment")

	// Use vault user instead of deprecated eos user
	vaultUID, vaultGID, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		// If vault user doesn't exist, skip ownership validation
		otelzap.Ctx(rc.Ctx).Info("Vault user not found, skipping ownership validation")
		return nil
	}

	// Check if /run/eos exists and is a directory
	info, err := os.Stat(shared.EosRunDir)
	if os.IsNotExist(err) {
		otelzap.Ctx(rc.Ctx).Error(" Missing runtime directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("missing runtime directory: %s", shared.EosRunDir)
	}
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to stat runtime directory", zap.String("path", shared.EosRunDir), zap.Error(err))
		return fmt.Errorf("failed to stat runtime directory: %w", err)
	}
	if !info.IsDir() {
		otelzap.Ctx(rc.Ctx).Error(" Runtime path is not a directory", zap.String("path", shared.EosRunDir))
		return fmt.Errorf("runtime path is not a directory: %s", shared.EosRunDir)
	}

	// Check ownership of the runtime directory
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		otelzap.Ctx(rc.Ctx).Warn("Unable to get ownership info of runtime directory")
	} else {
		currentUID := stat.Uid
		currentGID := stat.Gid

		// Safely convert int to uint32 with bounds checking
		if vaultUID < 0 || vaultGID < 0 {
			otelzap.Ctx(rc.Ctx).Error(" Invalid vault user UID/GID",
				zap.Int("uid", vaultUID),
				zap.Int("gid", vaultGID))
			return fmt.Errorf("invalid vault user UID/GID: %d/%d", vaultUID, vaultGID)
		}

		// #nosec G115 - Safe conversion after bounds checking above
		expectedUID := uint32(vaultUID)
		// #nosec G115 - Safe conversion after bounds checking above
		expectedGID := uint32(vaultGID)

		if currentUID != expectedUID || currentGID != expectedGID {
			otelzap.Ctx(rc.Ctx).Warn("Runtime directory not owned by vault user",
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
		otelzap.Ctx(rc.Ctx).Error(" Vault binary not found in PATH", zap.Error(err))
		return fmt.Errorf("vault binary not found in PATH: %w", err)
	}
	otelzap.Ctx(rc.Ctx).Info(" Vault binary found", zap.String("vault_path", vaultPath))

	return nil
}
