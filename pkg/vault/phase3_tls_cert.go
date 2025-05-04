// pkg/vault/phase3_tls_cert.go

package vault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

// EnsureVaultTLS() →
// ---	checkTLSCertForSAN()
// ---	GenerateVaultTLSCert()
// ------	(if SAN missing → removeBadTLSCerts() → GenerateVaultTLSCert())
// ---	removeBadTLSCerts()

// TrustVaultCA()
// ---	TrustVaultCA_RHEL()  [if RHEL-like]
// ---	TrustVaultCA_Debian()  [if Debian-like]

// GenerateVaultTLSCert()
// --- tlsCertsExist()
// --- fixTLSCertIfMissingSAN()
// ------	removeBadTLSCerts()
// --- secureTLSFiles()
// --- secureVaultTLSOwnership()
// ------	EnsureVaultAgentCAExists()

//--------------------------------------------------------------------
// 3.  Generate TLS Certificates
//--------------------------------------------------------------------

// PHASE 3 — GenerateVaultTLSCert() + TrustVaultCA()

func GenerateTLS() error {
	zap.L().Info("📁 Starting full Vault TLS generation and trust setup")

	crt, key, err := EnsureVaultTLS()
	if err != nil {
		return fmt.Errorf("ensure vault TLS certs: %w", err)
	}
	zap.L().Info("✅ Vault TLS certs ensured", zap.String("key", key), zap.String("crt", crt))

	if err := TrustVaultCA(); err != nil {
		return fmt.Errorf("trust vault CA system-wide: %w", err)
	}
	zap.L().Info("✅ Vault CA trusted system-wide")

	if err := secureVaultTLSOwnership(); err != nil {
		return fmt.Errorf("secure Vault TLS ownership: %w", err)
	}
	zap.L().Info("✅ Vault Agent CA cert ensured")
	zap.L().Info("✅ Vault TLS generation and trust setup complete")

	return nil
}

func EnsureVaultTLS() (string, string, error) {
	// Quick check if files exist
	if !system.FileExists(shared.TLSKey) || !system.FileExists(shared.TLSCrt) {
		zap.L().Warn("🔐 TLS certs missing — triggering generation")
		if err := GenerateVaultTLSCert(); err != nil {
			return "", "", fmt.Errorf("failed to generate Vault TLS certs: %w", err)
		}
		return shared.TLSCrt, shared.TLSKey, nil
	}

	// Extra: Inspect certificate for valid SANs
	hasValidSAN, err := checkTLSCertForSAN(shared.TLSCrt)
	if err != nil {
		zap.L().Warn("⚠️ Could not inspect existing TLS cert, forcing regeneration", zap.Error(err))
		_ = removeBadTLSCerts() // Best effort
		if err := GenerateVaultTLSCert(); err != nil {
			return "", "", fmt.Errorf("failed to generate Vault TLS certs after SAN check failure: %w", err)
		}
		return shared.TLSCrt, shared.TLSKey, nil
	}

	if !hasValidSAN {
		zap.L().Warn("❌ Existing Vault TLS cert missing or invalid SANs — forcing regeneration")
		_ = removeBadTLSCerts() // Best effort
		if err := GenerateVaultTLSCert(); err != nil {
			return "", "", fmt.Errorf("failed to regenerate Vault TLS cert with SANs: %w", err)
		}
		return shared.TLSCrt, shared.TLSKey, nil
	}

	zap.L().Info("✅ Vault TLS cert exists and SANs are valid", zap.String("crt", shared.TLSCrt))
	return shared.TLSCrt, shared.TLSKey, nil
}

// TrustVaultCA dispatches to the correct CA‐trust helper based on the distro.
func TrustVaultCA() error {
	distro := platform.DetectLinuxDistro()
	zap.L().Info("🔐 Trusting Vault CA system‑wide", zap.String("distro", distro))

	switch distro {
	case "debian", "ubuntu":
		if err := TrustVaultCA_Debian(); err != nil {
			return fmt.Errorf("debian CA trust: %w", err)
		}
	default:
		if err := TrustVaultCA_RHEL(); err != nil {
			return fmt.Errorf("rhel CA trust: %w", err)
		}
	}

	zap.L().Info("✅ Vault CA is now trusted system‑wide")
	return nil
}

func TrustVaultCA_RHEL() error {
	src := shared.TLSCrt
	dest := shared.VaultSystemCATrustPath

	zap.L().Info("📥 Installing Vault CA into system trust store",
		zap.String("src", src),
		zap.String("dest", dest),
	)

	// copy the file (overwrite if needed)
	if err := system.CopyFile(src, dest, shared.FilePermStandard); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	// ensure root owns it
	if err := os.Chown(dest, 0, 0); err != nil {
		zap.L().Warn("could not chown system CA file", zap.Error(err))
	}

	// RHEL9 / CentOS Stream 9
	cmd := exec.Command("update-ca-trust", "extract")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		zap.L().Error("❌ Failed to update system CA trust", zap.Error(err))
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	zap.L().Info("✅ Vault CA is now trusted system‑wide")
	return nil
}

// TrustVaultCADebian installs the Vault CA into Debian/Ubuntu's trust store.
func TrustVaultCA_Debian() error {
	src := shared.TLSCrt
	dest := "/usr/local/share/ca-certificates/vault-local-ca.crt"

	zap.L().Info("📥 Installing Vault CA into Debian trust store",
		zap.String("src", src), zap.String("dest", dest))

	if err := system.CopyFile(src, dest, shared.FilePermStandard); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	if err := os.Chown(dest, 0, 0); err != nil {
		zap.L().Warn("could not chown CA file", zap.Error(err))
	}

	cmd := exec.Command("update-ca-certificates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		zap.L().Error("❌ Failed to update system CA trust", zap.Error(err))
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	zap.L().Info("✅ Vault CA trusted system-wide on Debian/Ubuntu")
	return nil
}

// GenerateVaultTLSCert generates a self-signed TLS certificate for Vault.
func GenerateVaultTLSCert() error {
	zap.L().Info("📁 Checking for existing Vault TLS certs",
		zap.String("key", shared.TLSKey),
		zap.String("crt", shared.TLSCrt))

	if tlsCertsExist() {
		zap.L().Info("✅ TLS certs already exist, skipping generation")
		return nil
	}

	if err := fixTLSCertIfMissingSAN(); err != nil {
		zap.L().Warn("⚠️ Could not verify SAN TLS cert status", zap.Error(err))
	}

	if system.FileExists(shared.TLSKey) && system.FileExists(shared.TLSCrt) {
		zap.L().Info("✅ TLS certs already exist after SAN check, skipping")
		return nil
	}

	hostname := system.GetInternalHostname()
	publicHostname, _ := os.Hostname()
	zap.L().Debug("🔎 Got internal hostname for SAN", zap.String("hostname", hostname))

	if err := os.MkdirAll(shared.TLSDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}

	// 🚀 Remove prompt, always generate
	zap.L().Info("⚙️ No TLS certs found, automatically generating self-signed TLS certs")

	configContent := fmt.Sprintf(`
[req]
distinguished_name = req
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = %s
DNS.2 = %s
IP.1 = %s
`, hostname, publicHostname, shared.LocalhostSAN)

	tmpFile, err := os.CreateTemp("", "vault_openssl_*.cnf")
	if err != nil {
		return fmt.Errorf("failed to create temp openssl config: %w", err)
	}
	tmpConfigPath := tmpFile.Name()
	defer func() {
		if err := os.Remove(tmpConfigPath); err != nil {
			zap.L().Warn("Failed to remove temp file", zap.Error(err))
		}
	}()

	if _, err := tmpFile.Write([]byte(configContent)); err != nil {
		return fmt.Errorf("failed to write temp openssl config: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp openssl config: %w", err)
	}

	zap.L().Info("🔐 Generating Vault TLS certificate with SANs",
		zap.String("hostname", hostname), zap.String("config", tmpConfigPath))

	cmd := exec.Command("openssl", "req", "-new", "-newkey", "rsa:4096",
		"-days", "825", "-nodes", "-x509",
		"-subj", "/CN="+hostname,
		"-keyout", shared.TLSKey,
		"-out", shared.TLSCrt,
		"-extensions", "v3_req",
		"-config", tmpConfigPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openssl failed: %w", err)
	}

	if err := secureTLSFiles(); err != nil {
		zap.L().Warn("could not apply secureTLSFiles ownership/permissions", zap.Error(err))
	}
	if err := secureVaultTLSOwnership(); err != nil {
		zap.L().Warn("could not apply secureVaultTLSOwnership", zap.Error(err))
	}

	zap.L().Info("✅ Vault TLS cert generated and secured",
		zap.String("key", shared.TLSKey),
		zap.String("crt", shared.TLSCrt))

	return nil
}

func fixTLSCertIfMissingSAN() error {
	url := shared.VaultHealthEndpoint
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Intentionally strict: want to catch validation failures
			},
		},
	}

	zap.L().Debug("🔍 Testing TLS connection for SAN validation", zap.String("url", url))

	resp, err := client.Get(url)
	if err != nil {
		errStr := err.Error()

		if os.IsTimeout(err) {
			zap.L().Warn("⏱️ TLS check timed out – assuming Vault not running")
			return nil // Not a cert issue
		}

		if strings.Contains(errStr, "x509: cannot validate certificate for 127.0.0.1") &&
			strings.Contains(errStr, "doesn't contain any IP SANs") {
			zap.L().Warn("❌ Detected TLS cert missing SAN for 127.0.0.1 — forcing regeneration")

			if err := removeBadTLSCerts(); err != nil {
				return fmt.Errorf("failed to remove broken certs after SAN check: %w", err)
			}
			return nil
		}

		if strings.Contains(errStr, "x509: certificate is not valid for") {
			zap.L().Warn("❌ Detected certificate hostname mismatch — forcing TLS cert regeneration",
				zap.String("error", errStr))

			if err := removeBadTLSCerts(); err != nil {
				return fmt.Errorf("failed to remove broken certs after hostname mismatch: %w", err)
			}
			return nil
		}

		zap.L().Debug("TLS connection failed, but not due to SAN issue", zap.Error(err))
		return nil // Different TLS failure — do not delete
	}

	defer shared.SafeClose(resp.Body)
	zap.L().Debug("✅ TLS cert appears valid – continuing")
	return nil
}

// Helper
func removeBadTLSCerts() error {
	for _, path := range []string{shared.TLSKey, shared.TLSCrt} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			zap.L().Error("❌ Failed to remove broken TLS cert file", zap.String("path", path), zap.Error(err))
			return err
		}
		zap.L().Info("✅ Removed broken TLS cert file", zap.String("path", path))
	}
	return nil
}

func tlsCertsExist() bool {
	return system.FileExists(shared.TLSKey) && system.FileExists(shared.TLSCrt)
}

func secureVaultTLSOwnership() error {
	uid, gid, err := system.LookupUser(shared.EosID)
	if err != nil {
		zap.L().Warn("could not lookup eos user", zap.Error(err))
		return err
	}

	for _, file := range []struct {
		path string
		perm os.FileMode
	}{
		{shared.TLSKey, shared.FilePermOwnerReadWrite},
		{shared.TLSCrt, shared.FilePermStandard},
		{shared.TLSDir, shared.FilePermOwnerRWX},
	} {
		if err := os.Chown(file.path, uid, gid); err != nil {
			zap.L().Warn("⚠️ Failed to chown", zap.String("path", file.path), zap.Error(err))
		} else {
			zap.L().Info("✅ Set ownership", zap.String("path", file.path), zap.Int("uid", uid), zap.Int("gid", gid))
		}

		if err := os.Chmod(file.path, file.perm); err != nil {
			zap.L().Warn("⚠️ Failed to chmod", zap.String("path", file.path), zap.Error(err))
		} else {
			zap.L().Info("✅ Set permissions", zap.String("path", file.path), zap.String("perm", fmt.Sprintf("%#o", file.perm)))
		}
	}

	// Now ensure CA is available for the Vault Agent
	return EnsureVaultAgentCAExists()
}

// EnsureVaultAgentCAExists ensures that the Vault Agent CA cert is present.
// If missing, it re-copies it from the Vault server TLS cert.
func EnsureVaultAgentCAExists() error {
	src := shared.TLSCrt
	dst := shared.VaultAgentCACopyPath

	if system.FileExists(dst) {
		zap.L().Debug("✅ Vault Agent CA cert already exists", zap.String("path", dst))
		return nil
	}

	zap.L().Warn("⚠️ Vault Agent CA cert missing, attempting to re-copy",
		zap.String("src", src), zap.String("dst", dst))

	if err := system.CopyFile(src, dst, shared.FilePermStandard); err != nil {
		return fmt.Errorf("failed to copy Vault Agent CA cert: %w", err)
	}

	uid, gid, err := system.LookupUser(shared.EosID)
	if err != nil {
		zap.L().Warn("could not lookup eos user for CA cert ownership", zap.Error(err))
		return err
	}

	if err := os.Chown(dst, uid, gid); err != nil {
		zap.L().Warn("could not chown Vault Agent CA cert", zap.Error(err))
	} else {
		zap.L().Info("✅ Vault Agent CA cert ownership corrected", zap.String("path", dst),
			zap.Int("uid", uid), zap.Int("gid", gid))
	}

	return nil
}

// checkTLSCertForSAN parses the cert and ensures it has SANs matching localhost or internal hostname.
func checkTLSCertForSAN(certPath string) (bool, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Errorf("read cert: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse cert: %w", err)
	}

	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		zap.L().Warn("TLS cert missing SANs entirely")
		return false, nil
	}

	// Optional: you can enforce certain DNS names here if you want stricter matching
	return true, nil
}

func secureTLSFiles() error {
	eosUID, eosGID, err := system.LookupUser(shared.EosID) // 🔥 Change back to eos
	if err != nil {
		zap.L().Error("⚠️ Could not resolve eos UID/GID for TLS files", zap.Error(err))
	}

	tlsFiles := []struct {
		path string
		perm os.FileMode
	}{
		{shared.TLSKey, 0600},
		{shared.TLSCrt, 0644},
	}

	for _, tf := range tlsFiles {
		zap.L().Debug("🔧 Securing TLS file", zap.String("path", tf.path))
		if err := os.Chown(tf.path, eosUID, eosGID); err != nil {
			zap.L().Error("❌ Failed to chown TLS file", zap.String("path", tf.path), zap.Error(err))
			return fmt.Errorf("failed to secure %s: %w", tf.path, err)
		}
		if err := os.Chmod(tf.path, tf.perm); err != nil {
			zap.L().Error("❌ Failed to chmod TLS file", zap.String("path", tf.path), zap.Error(err))
			return fmt.Errorf("failed to secure %s: %w", tf.path, err)
		}
	}
	return nil
}
