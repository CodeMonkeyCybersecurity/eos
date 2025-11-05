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
//  1. Prefer an existing HTTPS listener on shared.GetInternalHostname:<VaultDefaultPort>
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
	log := otelzap.Ctx(rc.Ctx)

	// 1. Return if already set
	if cur := os.Getenv(shared.VaultAddrEnv); cur != "" {
		log.Debug("VAULT_ADDR already set", zap.String(shared.VaultAddrEnv, cur))
		return cur, nil
	}

	// 2. Always use internal hostname as the Vault address
	host := shared.GetInternalHostname()
	addr := fmt.Sprintf(shared.VaultDefaultAddr, host)

	// SECURITY (P0-2 FIX): Attempt to use proper CA certificate validation
	// instead of unconditionally disabling TLS verification

	// 3. Try to locate and load CA certificate
	caPath, err := locateVaultCACertificate(rc)
	if err == nil {
		// CA certificate found - set VAULT_CACERT and test connection
		_ = os.Setenv("VAULT_CACERT", caPath)
		log.Info("✓ Vault CA certificate configured (TLS validation enabled)",
			zap.String("VAULT_CACERT", caPath))

		// Test connection with proper TLS validation
		if canConnectTLS(rc, addr, testTimeout) {
			_ = os.Setenv(shared.VaultAddrEnv, addr)
			log.Info("✓ VAULT_ADDR validated with TLS certificate verification",
				zap.String(shared.VaultAddrEnv, addr),
				zap.String("ca_cert", caPath))
			return addr, nil
		}

		log.Warn("TLS connection failed even with CA certificate - may indicate network or certificate issue",
			zap.String("addr", addr),
			zap.String("ca_path", caPath))
	} else {
		log.Warn("No Vault CA certificate found in standard locations",
			zap.Error(err),
			zap.Strings("searched", []string{
				"/etc/vault/tls/ca.crt",
				"/etc/eos/ca.crt",
				"/etc/ssl/certs/vault-ca.pem",
			}))
	}

	// 4. CA certificate not found or connection failed - handle TLS validation failure
	return handleTLSValidationFailure(rc, addr)
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
			"/etc/eos/ca.crt",             // Eos general CA
			"/etc/vault/tls/ca.crt",       // Vault standard location
			"/etc/ssl/certs/vault-ca.crt", // Alternative location
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

// locateVaultCACertificate attempts to find a Vault CA certificate in standard locations
//
// SECURITY (P0-2 FIX): Proper CA certificate discovery prevents MITM attacks
// RATIONALE: Using VAULT_CACERT enables certificate validation without skip_verify
// THREAT MODEL: Prevents attacker from intercepting Vault connections with fake certs
//
// Search order (highest priority first):
//  1. /etc/vault/tls/ca.crt - Vault standard location
//  2. /etc/eos/ca.crt - Eos general CA
//  3. /etc/ssl/certs/vault-ca.pem - Alternative location
//
// Returns:
//   - string: Path to valid CA certificate file
//   - error: If no valid CA certificate found in any location
//
// COMPLIANCE: NIST 800-53 SC-8, SC-13
func locateVaultCACertificate(rc *eos_io.RuntimeContext) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Try standard locations in priority order
	caPaths := []string{
		"/etc/vault/tls/ca.crt",       // Vault standard location (HIGHEST PRIORITY)
		"/etc/eos/ca.crt",             // Eos general CA
		"/etc/ssl/certs/vault-ca.pem", // Alternative location
	}

	for _, caPath := range caPaths {
		info, err := os.Stat(caPath)
		if err != nil {
			log.Debug("CA certificate not found",
				zap.String("path", caPath),
				zap.Error(err))
			continue // Try next path
		}

		// Verify it's a regular file and readable
		if !info.Mode().IsRegular() {
			log.Debug("CA certificate path is not a regular file",
				zap.String("path", caPath))
			continue
		}

		if info.Size() == 0 {
			log.Debug("CA certificate file is empty",
				zap.String("path", caPath))
			continue
		}

		// Verify it's actually a valid PEM certificate
		if err := validateCACertificate(caPath); err != nil {
			log.Warn("Found CA file but validation failed",
				zap.String("path", caPath),
				zap.Error(err))
			continue
		}

		log.Info("Found valid Vault CA certificate",
			zap.String("path", caPath),
			zap.Int64("size", info.Size()))
		return caPath, nil
	}

	return "", fmt.Errorf("no valid Vault CA certificate found in standard locations: %v", caPaths)
}

// validateCACertificate validates that a file contains a valid PEM-encoded certificate
//
// SECURITY: Ensures CA certificate is properly formatted before use
// RATIONALE: Prevents using corrupted or malformed certificates
//
// Parameters:
//   - caPath: Path to CA certificate file
//
// Returns:
//   - error: If certificate is invalid or cannot be read
func validateCACertificate(caPath string) error {
	certPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return fmt.Errorf("failed to parse PEM certificate")
	}

	// Successfully parsed - certificate is valid PEM format
	return nil
}

// handleTLSValidationFailure handles TLS validation failures with informed user consent
//
// SECURITY (P0-2 FIX): Implements informed consent before disabling TLS validation
// RATIONALE: User must explicitly accept risk of MITM attacks
// THREAT MODEL: Prevents accidental use of insecure connections
//
// This function is called when:
//   - No CA certificate found in standard locations, OR
//   - TLS connection failed even with CA certificate
//
// Behavior:
//   - Interactive mode (TTY): Prompts user with security warning, requires "yes"
//   - Non-interactive mode (CI/CD): Fails with clear remediation steps
//   - Development mode (Eos_ALLOW_INSECURE_VAULT=true): Allows with warning
//
// Parameters:
//   - rc: RuntimeContext for logging
//   - addr: Vault address that failed validation
//
// Returns:
//   - string: Vault address (if user consents or dev mode)
//   - error: If user declines or non-interactive mode
//
// COMPLIANCE: NIST 800-53 SC-8 (requires user acknowledgment of insecure connections)
func handleTLSValidationFailure(rc *eos_io.RuntimeContext, addr string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// Check for development mode override
	if os.Getenv("Eos_ALLOW_INSECURE_VAULT") == "true" {
		log.Warn("⚠️  VAULT_SKIP_VERIFY enabled via Eos_ALLOW_INSECURE_VAULT (INSECURE - DEV MODE)",
			zap.String("VAULT_SKIP_VERIFY", "1"),
			zap.String("reason", "dev_mode_environment_variable"),
			zap.String("env_var", "Eos_ALLOW_INSECURE_VAULT=true"))

		_ = os.Setenv("VAULT_SKIP_VERIFY", "1")
		_ = os.Setenv(shared.VaultAddrEnv, addr)
		return addr, nil
	}

	log.Warn("⚠️  Vault TLS certificate validation failed",
		zap.String("addr", addr),
		zap.String("reason", "CA certificate not found or connection failed"))

	// Check if we're in non-interactive mode
	if !isInteractiveTerminal() {
		return "", fmt.Errorf("TLS validation failed and cannot prompt in non-interactive mode\n\n"+
			"Remediation:\n"+
			"  1. RECOMMENDED: Install proper CA certificate to /etc/vault/tls/ca.crt\n"+
			"     Example: sudo cp /path/to/vault-ca.crt /etc/vault/tls/ca.crt\n"+
			"  2. OR set VAULT_CACERT=/path/to/ca.crt environment variable\n"+
			"  3. OR for development only: set Eos_ALLOW_INSECURE_VAULT=true (INSECURE)\n"+
			"\n"+
			"Verify CA certificate:\n"+
			"  openssl s_client -connect %s -CAfile /etc/vault/tls/ca.crt\n"+
			"\n"+
			"Security warning: Disabling TLS validation enables MITM attacks", addr)
	}

	// Interactive mode: Ask for informed consent
	fmt.Println("\n⚠️  SECURITY WARNING: Vault TLS Certificate Validation Failed")
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println("Cannot verify Vault server identity. This could indicate:")
	fmt.Println("  • Vault is using a self-signed certificate (expected during setup)")
	fmt.Println("  • CA certificate is not in the system trust store")
	fmt.Println("  • OR a man-in-the-middle attack is in progress")
	fmt.Println()
	fmt.Println("Proceeding WITHOUT certificate validation is INSECURE.")
	fmt.Println("An attacker could intercept your connection and steal secrets.")
	fmt.Println()
	fmt.Println("Recommended actions:")
	fmt.Println("  1. Install Vault's CA certificate to /etc/vault/tls/ca.crt")
	fmt.Println("  2. Verify with: openssl s_client -connect", addr, "-CAfile /etc/vault/tls/ca.crt")
	fmt.Println()
	fmt.Print("Do you want to proceed WITHOUT certificate validation? (yes/NO): ")

	var response string
	fmt.Scanln(&response)

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "yes" {
		log.Info("User declined to proceed without TLS validation (security-conscious choice)",
			zap.String("response", response))
		return "", fmt.Errorf("TLS validation failed and user declined to proceed insecurely")
	}

	// User explicitly consented - enable skip_verify with logging
	_ = os.Setenv("VAULT_SKIP_VERIFY", "1")
	_ = os.Setenv(shared.VaultAddrEnv, addr)

	log.Warn("⚠️  VAULT_SKIP_VERIFY enabled with user consent - INSECURE",
		zap.String("VAULT_SKIP_VERIFY", "1"),
		zap.String("reason", "user_consent_interactive"),
		zap.String("session_user", os.Getenv("USER")),
		zap.Time("consent_time", time.Now()),
		zap.String("vault_addr", addr))

	return addr, nil
}

// isInteractiveTerminal checks if stdin is connected to an interactive terminal
//
// Returns:
//   - true if running in interactive terminal (user can be prompted)
//   - false if running in CI/CD, script, or non-TTY environment
func isInteractiveTerminal() bool {
	// Check if stdin is a terminal
	fileInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	// Check if it's a character device (terminal)
	// On Unix systems, terminals are character devices
	mode := fileInfo.Mode()
	return (mode & os.ModeCharDevice) != 0
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
		{path: VaultBaseDir, perm: shared.FilePermOwnerRWX},
		{path: VaultDataDir, perm: shared.FilePermOwnerRWX},
		{path: shared.TLSDir, perm: 0750},
		{path: shared.SecretsDir, perm: shared.FilePermOwnerRWX},
		{path: shared.EosRunDir, perm: shared.FilePermOwnerRWX},
		{path: filepath.Dir(shared.VaultAgentCACopyPath), perm: shared.FilePermOwnerRWX},
		{path: VaultLogsDir, perm: 0700},
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
		"path", VaultBaseDir,
		"uid", vaultUID,
		"gid", vaultGID,
	)

	// perform recursive chown
	if err := eos_unix.ChownR(rc.Ctx, VaultBaseDir, vaultUID, vaultGID); err != nil {
		zap.S().Errorw("chownR failed",
			"path", VaultBaseDir, "error", err,
		)
		return cerr.Wrapf(err, "chownR %s", VaultBaseDir)
	}

	zap.S().Infow("Vault directory ownership fixed", "path", VaultBaseDir)
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
			otelzap.Ctx(rc.Ctx).Warn("Runtime directory not owned by vault user, fixing...",
				zap.String("path", shared.EosRunDir),
				zap.Uint32("current_uid", currentUID),
				zap.Uint32("current_gid", currentGID),
				zap.Uint32("expected_uid", expectedUID),
				zap.Uint32("expected_gid", expectedGID),
			)

			// FIX: Chown the directory to vault user
			// This is critical for Vault Agent to write the token file
			if err := os.Chown(shared.EosRunDir, vaultUID, vaultGID); err != nil {
				otelzap.Ctx(rc.Ctx).Error(" Failed to fix runtime directory ownership",
					zap.String("path", shared.EosRunDir),
					zap.Error(err))
				return fmt.Errorf("failed to chown runtime directory to vault user: %w", err)
			}

			otelzap.Ctx(rc.Ctx).Info(" Runtime directory ownership fixed",
				zap.String("path", shared.EosRunDir),
				zap.String("owner", "vault:vault"))
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
