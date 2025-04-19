// lifecycle_tls.go

package vault

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"go.uber.org/zap"
)

func GenerateVaultTLSCert(log *zap.Logger) error {

	// Skip if both cert + key already exist
	if fileExists(TLSKey) && fileExists(TLSCrt) {
		log.Info("✅ Existing Vault TLS cert found, skipping generation")
		return nil
	}

	hostnameCmd := exec.Command("hostname", "-f")
	hostnameOut, err := hostnameCmd.Output()
	if err != nil {
		return fmt.Errorf("could not get FQDN: %w", err)
	}
	hostname := string(hostnameOut)

	log.Info("🔐 Generating Vault TLS cert", zap.String("SAN", hostname))

	cmd := exec.Command("openssl", "req", "-new", "-newkey", "rsa:4096", "-days", "825", "-nodes", "-x509",
		"-subj", "/CN="+hostname,
		"-addext", "subjectAltName=DNS:"+hostname+",IP:127.0.0.1",
		"-keyout", TLSKey,
		"-out", TLSCrt,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := os.MkdirAll(TLSDir, xdg.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate TLS cert: %w", err)
	}

	if err := os.Chmod(TLSKey, xdg.FilePermOwnerReadWrite); err != nil {
		log.Warn("could not set strict perms on TLS key", zap.Error(err))
	}
	if err := os.Chmod(TLSCrt, xdg.SystemdUnitFilePerms); err != nil {
		log.Warn("could not set perms on TLS cert", zap.Error(err))
	}

	log.Info("✅ Vault TLS cert generated successfully")
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
