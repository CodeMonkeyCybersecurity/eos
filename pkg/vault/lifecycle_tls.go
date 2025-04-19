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

	// Build openssl command
	cmd := exec.Command("openssl", "req", "-new", "-newkey", "rsa:4096", "-days", "825", "-nodes", "-x509",
		"-subj", "/CN="+hostname,
		"-addext", "subjectAltName=DNS:"+hostname+",IP:127.0.0.1",
		"-keyout", TLSKey,
		"-out", TLSCrt,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Info("🔐 Running openssl to generate Vault TLS cert...",
		zap.String("CN", hostname),
		zap.String("key_path", TLSKey),
		zap.String("crt_path", TLSCrt))

	if err := cmd.Run(); err != nil {
		log.Error("❌ OpenSSL failed to generate certificate", zap.Error(err))
		return fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	// Set strict file permissions
	log.Debug("🔒 Setting permissions on TLS cert and key")
	if err := os.Chmod(TLSKey, xdg.FilePermOwnerReadWrite); err != nil {
		log.Warn("⚠️ Could not set strict perms on TLS key", zap.Error(err))
	}
	if err := os.Chmod(TLSCrt, xdg.SystemdUnitFilePerms); err != nil {
		log.Warn("⚠️ Could not set perms on TLS cert", zap.Error(err))
	}

	log.Info("✅ Vault TLS cert generated successfully")
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
