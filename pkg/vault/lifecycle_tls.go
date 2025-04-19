// pkg/vault/lifecycle_tls.go

package vault

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

	if err := ensureEosVaultProfile(log); err != nil {
		log.Warn("could not install /etc/profile.d/eos_vault.sh", zap.Error(err))
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

	// Now copy the public cert into eos’s CA location so the agent can trust it:
	log.Info("🔧 Copying Vault CA into eos user trust store",
		zap.String("src", TLSCrt),
		zap.String("dst", VaultAgentCACopyPath),
		zap.String("perm", fmt.Sprintf("%#o", 0o644)),
	)
	if err := CopyFile(TLSCrt, VaultAgentCACopyPath, 0o644); err != nil {
		log.Warn("❌ Failed to copy CA cert for Vault Agent", zap.Error(err))
	} else {
		// make sure eos can read it
		if uid, gid, err := system.LookupUser(EosUser); err != nil {
			log.Warn("could not lookup eos user for CA file ownership", zap.Error(err))
		} else if err := os.Chown(VaultAgentCACopyPath, uid, gid); err != nil {
			log.Warn("could not chown CA cert for eos user", zap.Error(err))
		} else {
			log.Info("✅ Vault CA copied and ownership set", zap.String("path", VaultAgentCACopyPath))
		}
	}

	return nil
}

// CopyFile copies src → dst (creating parent dirs), setting dst to perm.
func CopyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s → %s: %w", src, dst, err)
	}
	return nil
}
