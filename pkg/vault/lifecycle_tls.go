// pkg/vault/lifecycle_tls.go

package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

func GenerateVaultTLSCert(log *zap.Logger) error {
	log.Info("📁 Checking for existing Vault TLS certs",
		zap.String("key", TLSKey),
		zap.String("crt", TLSCrt))

	if err := fixTLSCertIfMissingSAN(log); err != nil {
		log.Warn("⚠️ Could not verify SAN TLS cert status", zap.Error(err))
	}

	if fileExists(TLSKey) && fileExists(TLSCrt) {
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
	if fileExists(TLSKey) && fileExists(TLSCrt) {
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

	log.Info("✅ Vault TLS cert generated and secured", zap.String("key", TLSKey), zap.String("crt", TLSCrt))
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

func secureVaultTLSOwnership(log *zap.Logger) error {
	uid, gid, err := system.LookupUser("vault")
	if err != nil {
		log.Warn("could not lookup vault user", zap.Error(err))
		return err
	}

	// Set ownership
	if err := os.Chown(TLSKey, uid, gid); err != nil {
		log.Warn("failed to chown tls.key", zap.Error(err))
	}
	if err := os.Chown(TLSCrt, uid, gid); err != nil {
		log.Warn("failed to chown tls.crt", zap.Error(err))
	}
	if err := os.Chown(TLSDir, uid, gid); err != nil {
		log.Warn("failed to chown tls dir", zap.Error(err))
	}

	if err := os.Chmod(TLSKey, xdg.FilePermOwnerReadWrite); err != nil {
		log.Warn("could not chmod tls.key", zap.Error(err))
	}
	if err := os.Chmod(TLSCrt, xdg.FilePermPublicCert); err != nil {
		log.Warn("could not chmod tls.crt", zap.Error(err))
	}

	if err := os.Chmod(TLSDir, xdg.FilePermOwnerRWX); err != nil {
		log.Warn("could not chmod tls.key", zap.Error(err))
	}

	return nil
}
