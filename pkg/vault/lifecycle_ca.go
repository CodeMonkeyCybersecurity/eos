// pkg/vault/lifecycle_ca.go
package vault

import (
	"fmt"
	"os"
	"os/exec"

	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

func TrustVaultCA(log *zap.Logger) error {
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
func TrustVaultCADebian(log *zap.Logger) error {
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
