// pkg/vault/phase3_tls_cert.go
package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 3.  Generate TLS Certificates
//--------------------------------------------------------------------

// PHASE 3 — GenerateVaultTLSCert() + TrustVaultCA()

// TrustVaultCA dispatches to the correct CA‐trust helper based on the distro.
func TrustVaultCA(log *zap.Logger) error {
	distro := platform.DetectLinuxDistro(log)
	log.Info("🔐 Trusting Vault CA system‑wide", zap.String("distro", distro))

	switch distro {
	case "debian", "ubuntu":
		if err := TrustVaultCA_Debian(log); err != nil {
			return fmt.Errorf("debian CA trust: %w", err)
		}
	default:
		if err := TrustVaultCA_RHEL(log); err != nil {
			return fmt.Errorf("rhel CA trust: %w", err)
		}
	}

	log.Info("✅ Vault CA is now trusted system‑wide")
	return nil
}

func TrustVaultCA_RHEL(log *zap.Logger) error {
	src := shared.TLSCrt
	dest := shared.VaultSystemCATrustPath

	log.Info("📥 Installing Vault CA into system trust store",
		zap.String("src", src),
		zap.String("dest", dest),
	)

	// copy the file (overwrite if needed)
	if err := system.CopyFile(src, dest, shared.FilePermStandard, log); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	// ensure root owns it
	if err := os.Chown(dest, 0, 0); err != nil {
		log.Warn("could not chown system CA file", zap.Error(err))
	}

	// RHEL9 / CentOS Stream 9
	cmd := exec.Command("update-ca-trust", "extract")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("❌ Failed to update system CA trust", zap.Error(err))
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	log.Info("✅ Vault CA is now trusted system‑wide")
	return nil
}

// TrustVaultCADebian installs the Vault CA into Debian/Ubuntu's trust store.
func TrustVaultCA_Debian(log *zap.Logger) error {
	src := shared.TLSCrt
	dest := "/usr/local/share/ca-certificates/vault-local-ca.crt"

	log.Info("📥 Installing Vault CA into Debian trust store",
		zap.String("src", src), zap.String("dest", dest))

	if err := system.CopyFile(src, dest, shared.FilePermStandard, log); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	if err := os.Chown(dest, 0, 0); err != nil {
		log.Warn("could not chown CA file", zap.Error(err))
	}

	cmd := exec.Command("update-ca-certificates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("❌ Failed to update system CA trust", zap.Error(err))
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	log.Info("✅ Vault CA trusted system-wide on Debian/Ubuntu")
	return nil
}

// GenerateVaultTLSCert generates a self-signed TLS certificate for Vault,
// including SANs for internal hostname and 127.0.0.1, and stores them securely.
func GenerateVaultTLSCert(log *zap.Logger) error {
	log.Info("📁 Checking for existing Vault TLS certs",
		zap.String("key", shared.TLSKey),
		zap.String("crt", shared.TLSCrt))

	if tlsCertsExist() {
		log.Info("✅ TLS certs already exist, skipping generation")
		return nil
	}

	if err := fixTLSCertIfMissingSAN(log); err != nil {
		log.Warn("⚠️ Could not verify SAN TLS cert status", zap.Error(err))
	}

	if system.FileExists(shared.TLSKey) && system.FileExists(shared.TLSCrt) {
		log.Info("✅ TLS certs already exist after SAN check, skipping")
		return nil
	}

	hostname := system.GetInternalHostname()
	log.Debug("🔎 Got internal hostname for SAN", zap.String("hostname", hostname))

	// Create TLS directory
	if err := os.MkdirAll(shared.TLSDir, shared.DirPermStandard); err != nil {
		log.Error("❌ Failed to create TLS directory", zap.Error(err))
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}

	ok := interaction.PromptYesNo("No TLS certs found. Generate self-signed TLS certs now?", true, log)
	if !ok {
		return fmt.Errorf("user declined TLS certificate generation")
	}

	// Create temporary OpenSSL config with SANs
	configContent := fmt.Sprintf(`
[req]
distinguished_name = req
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = %s
IP.1 = %s
`, hostname, shared.LocalhostSAN)

	tmpFile, err := os.CreateTemp("", "vault_openssl_*.cnf")
	if err != nil {
		return fmt.Errorf("failed to create temp openssl config: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpConfigPath := tmpFile.Name()

	if _, err := tmpFile.Write([]byte(configContent)); err != nil {
		return fmt.Errorf("failed to write temp openssl config: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp openssl config: %w", err)
	}

	log.Info("🔐 Generating Vault TLS certificate with SANs",
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

	log.Info("🔐 Securing Vault TLS certs...")
	if err := secureVaultTLSOwnership(log); err != nil {
		log.Warn("could not apply correct ownership to TLS certs", zap.Error(err))
	}

	log.Info("✅ Vault TLS cert generated and secured",
		zap.String("key", shared.TLSKey),
		zap.String("crt", shared.TLSCrt))

	return nil
}

func fixTLSCertIfMissingSAN(log *zap.Logger) error {
	url := shared.VaultHealthEndpoint
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Intentionally strict: want to catch validation failures
			},
		},
	}

	log.Debug("🔍 Testing TLS connection for SAN validation", zap.String("url", url))

	resp, err := client.Get(url)
	if err != nil {
		errStr := err.Error()

		if os.IsTimeout(err) {
			log.Warn("⏱️ TLS check timed out – assuming Vault not running")
			return nil // Not a cert issue
		}

		if strings.Contains(errStr, "x509: cannot validate certificate for 127.0.0.1") &&
			strings.Contains(errStr, "doesn't contain any IP SANs") {
			log.Warn("❌ Detected TLS cert missing SAN for 127.0.0.1 — forcing regeneration")

			if err := removeBadTLSCerts(log); err != nil {
				return fmt.Errorf("failed to remove broken certs after SAN check: %w", err)
			}
			return nil
		}

		// 🔥 NEW: Catch other related SAN errors
		if strings.Contains(errStr, "x509: certificate is not valid for") {
			log.Warn("❌ Detected certificate hostname mismatch — forcing TLS cert regeneration",
				zap.String("error", errStr))

			if err := removeBadTLSCerts(log); err != nil {
				return fmt.Errorf("failed to remove broken certs after hostname mismatch: %w", err)
			}
			return nil
		}

		log.Debug("TLS connection failed, but not due to SAN issue", zap.Error(err))
		return nil // Different TLS failure — do not delete
	}

	defer resp.Body.Close()
	log.Debug("✅ TLS cert appears valid – continuing")
	return nil
}

// Helper
func removeBadTLSCerts(log *zap.Logger) error {
	for _, path := range []string{shared.TLSKey, shared.TLSCrt} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Error("❌ Failed to remove broken TLS cert file", zap.String("path", path), zap.Error(err))
			return err
		}
		log.Info("✅ Removed broken TLS cert file", zap.String("path", path))
	}
	return nil
}

func EnsureVaultTLS(log *zap.Logger) (string, string, error) {
	if system.FileExists(shared.TLSKey) && system.FileExists(shared.TLSCrt) {
		log.Info("✅ Vault TLS certs already exist, skipping generation",
			zap.String("key", shared.TLSKey), zap.String("crt", shared.TLSCrt))
		return shared.TLSCrt, shared.TLSKey, nil
	}

	log.Warn("🔐 No Vault TLS certs found — secure communication will fail unless generated")

	ok := interaction.PromptYesNo("No TLS certs found. Generate self-signed TLS certs now?", true, log)
	if !ok {
		return "", "", fmt.Errorf("user declined TLS cert generation")
	}

	if err := GenerateVaultTLSCert(log); err != nil {
		return "", "", fmt.Errorf("failed to generate Vault TLS cert: %w", err)
	}

	return shared.TLSCrt, shared.TLSKey, nil
}

func tlsCertsExist() bool {
	return system.FileExists(shared.TLSKey) && system.FileExists(shared.TLSCrt)
}

func secureVaultTLSOwnership(log *zap.Logger) error {
	uid, gid, err := system.LookupUser(shared.EosUser)
	if err != nil {
		log.Warn("could not lookup eos user", zap.Error(err))
		return err
	}

	// Chown and chmod each file with logging
	for _, file := range []struct {
		path string
		perm os.FileMode
	}{
		{shared.TLSKey, shared.FilePermOwnerReadWrite},
		{shared.TLSCrt, shared.FilePermStandard},
		{shared.TLSDir, shared.FilePermOwnerRWX},
	} {
		if err := os.Chown(file.path, uid, gid); err != nil {
			log.Warn("⚠️ Failed to chown", zap.String("path", file.path), zap.Error(err))
		} else {
			log.Info("✅ Set ownership", zap.String("path", file.path), zap.Int("uid", uid), zap.Int("gid", gid))
		}

		if err := os.Chmod(file.path, file.perm); err != nil {
			log.Warn("⚠️ Failed to chmod", zap.String("path", file.path), zap.Error(err))
		} else {
			log.Info("✅ Set permissions", zap.String("path", file.path), zap.String("perm", fmt.Sprintf("%#o", file.perm)))
		}
	}

	// Copy CA to eos trust path
	log.Info("🔧 Copying Vault CA into eos trust store",
		zap.String("src", shared.TLSCrt),
		zap.String("dst", shared.VaultAgentCACopyPath),
	)

	if err := system.CopyFile(shared.TLSCrt, shared.VaultAgentCACopyPath, shared.FilePermStandard, log); err != nil {
		log.Warn("❌ Failed to copy CA cert for Vault Agent", zap.Error(err))
		return err
	} else {
		log.Info("✅ CA cert copied", zap.String("dst", shared.VaultAgentCACopyPath))
	}

	if uid, gid, err := system.LookupUser(shared.EosUser); err != nil {
		log.Warn("could not lookup eos user for CA file ownership", zap.Error(err))
	} else if err := os.Chown(shared.VaultAgentCACopyPath, uid, gid); err != nil {
		log.Warn("could not chown CA cert for eos user", zap.Error(err))
	} else {
		log.Info("✅ CA cert ownership set", zap.String("path", shared.VaultAgentCACopyPath),
			zap.Int("uid", uid), zap.Int("gid", gid))
	}

	return nil
}
