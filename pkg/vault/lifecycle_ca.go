// pkg/vault/lifecycle_ca.go
package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

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
	src := TLSCrt
	dest := VaultSystemCATrustPath

	log.Info("📥 Installing Vault CA into system trust store",
		zap.String("src", src),
		zap.String("dest", dest),
	)

	// copy the file (overwrite if needed)
	if err := system.CopyFile(src, dest, xdg.FilePermStandard, log); err != nil {
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
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	log.Info("✅ Vault CA is now trusted system‑wide")
	return nil
}

// TrustVaultCADebian installs the Vault CA into Debian/Ubuntu's trust store.
func TrustVaultCA_Debian(log *zap.Logger) error {
	src := TLSCrt
	dest := "/usr/local/share/ca-certificates/vault-local-ca.crt"

	log.Info("📥 Installing Vault CA into Debian trust store",
		zap.String("src", src), zap.String("dest", dest))

	if err := system.CopyFile(src, dest, xdg.FilePermStandard, log); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	if err := os.Chown(dest, 0, 0); err != nil {
		log.Warn("could not chown CA file", zap.Error(err))
	}

	cmd := exec.Command("update-ca-certificates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update Debian CA trust: %w", err)
	}

	log.Info("✅ Vault CA trusted system-wide on Debian/Ubuntu")
	return nil
}

func GenerateVaultTLSCert(log *zap.Logger) error {
	log.Info("📁 Checking for existing Vault TLS certs",
		zap.String("key", TLSKey),
		zap.String("crt", TLSCrt))

	if err := fixTLSCertIfMissingSAN(log); err != nil {
		log.Warn("⚠️ Could not verify SAN TLS cert status", zap.Error(err))
	}

	if system.FileExists(TLSKey) && system.FileExists(TLSCrt) {
		log.Info("✅ Existing Vault TLS cert found, skipping generation")
		return nil
	}

	// Get hostname (FQDN)
	hostname := platform.GetInternalHostname()
	log.Debug("🔎 Got internal hostname for SAN", zap.String("hostname", hostname))

	// Create TLS directory
	log.Debug("📂 Ensuring TLS directory exists", zap.String("path", TLSDir))
	if err := os.MkdirAll(TLSDir, xdg.DirPermStandard); err != nil {
		log.Error("❌ Failed to create TLS directory", zap.Error(err))
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}
	// Skip if already present
	if system.FileExists(TLSKey) && system.FileExists(TLSCrt) {
		log.Info("✅ TLS certs already exist, skipping generation")
		return nil
	}

	log.Info("🔐 Generating Vault TLS certificate (simple mode)", zap.String("CN", hostname))

	cmd := exec.Command("openssl", "req", "-new", "-newkey", "rsa:4096",
		"-days", "825", "-nodes", "-x509",
		"-subj", "/CN="+hostname,
		"-addext", fmt.Sprintf("subjectAltName=DNS:%s,IP:127.0.0.1", hostname),
		"-keyout", TLSKey,
		"-out", TLSCrt,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("openssl failed: %w", err)
	}

	// Permissions and ownership
	log.Info("🔐 Securing Vault TLS certs...")

	if err := secureVaultTLSOwnership(log); err != nil {
		log.Warn("could not apply correct ownership to TLS certs", zap.Error(err))
	}

	// if err := ensureEosVaultProfile(log); err != nil {
	// 	log.Warn("could not install /etc/profile.d/eos_vault.sh", zap.Error(err))
	// }

	log.Info("✅ Vault TLS cert generated and secured", zap.String("key", TLSKey), zap.String("crt", TLSCrt))
	return nil
}

func fixTLSCertIfMissingSAN(log *zap.Logger) error {
	url := VaultHealthEndpoint
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // we want the error to happen
			},
		},
	}

	log.Debug("🔍 Testing TLS connection for SAN validation", zap.String("url", url))
	resp, err := client.Get(url)
	if err != nil {
		if os.IsTimeout(err) {
			log.Warn("⏱️ TLS check timed out – assuming Vault not running")
			return nil // not a cert issue
		}
		if strings.Contains(err.Error(), "x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs") {
			log.Warn("❌ TLS cert is missing SAN for 127.0.0.1 – forcing regeneration")

			// Delete cert + key
			if err := os.Remove(TLSKey); err != nil && !os.IsNotExist(err) {
				log.Error("failed to remove broken TLS key", zap.Error(err))
			}
			if err := os.Remove(TLSCrt); err != nil && !os.IsNotExist(err) {
				log.Error("failed to remove broken TLS cert", zap.Error(err))
			}

			return nil
		}

		log.Debug("TLS connection failed, but not due to SAN issue", zap.Error(err))
		return nil // different TLS failure — don't reset
	}

	resp.Body.Close()
	log.Debug("✅ TLS cert appears valid – continuing")
	return nil
}
