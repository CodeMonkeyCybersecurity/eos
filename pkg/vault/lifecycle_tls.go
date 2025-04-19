// lifecycle_tls.go

package vault

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

func GenerateVaultTLSCert(log *zap.Logger) error {
	log.Info("📁 Checking for existing Vault TLS certs",
		zap.String("key", TLSKey),
		zap.String("crt", TLSCrt))

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

	if err := os.MkdirAll(TLSDir, xdg.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create TLS dir: %w", err)
	}

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
	if err := os.Chown(TLSKey, 990, 990); err != nil { // assuming vault:vault = 990:990
		log.Warn("could not chown tls.key", zap.Error(err))
	}
	if err := os.Chown(TLSCrt, 990, 990); err != nil {
		log.Warn("could not chown tls.crt", zap.Error(err))
	}
	if err := os.Chmod(TLSKey, xdg.FilePermOwnerReadWrite); err != nil {
		log.Warn("could not chmod tls.key", zap.Error(err))
	}
	if err := os.Chmod(TLSCrt, xdg.FilePermOwnerReadWrite); err != nil {
		log.Warn("could not chmod tls.crt", zap.Error(err))
	}

	log.Info("✅ Vault TLS cert generated and secured", zap.String("key", TLSKey), zap.String("crt", TLSCrt))
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
