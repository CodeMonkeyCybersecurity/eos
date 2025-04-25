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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
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
		return fmt.Errorf("failed to update Debian CA trust: %w", err)
	}

	log.Info("✅ Vault CA trusted system-wide on Debian/Ubuntu")
	return nil
}

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
		log.Info("Skipping TLS cert generation", zap.Bool("keyExists", system.FileExists(shared.TLSKey)), zap.Bool("crtExists", system.FileExists(shared.TLSCrt)))
		return nil
	}

	// Get hostname (FQDN)
	hostname := system.GetInternalHostname()
	log.Debug("🔎 Got internal hostname for SAN", zap.String("hostname", hostname))

	// Create TLS directory
	log.Debug("📂 Ensuring TLS directory exists", zap.String("path", shared.TLSDir))
	if err := os.MkdirAll(shared.TLSDir, shared.DirPermStandard); err != nil {
		log.Error("❌ Failed to create TLS directory", zap.Error(err))
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}
	// Skip if already present
	if system.FileExists(shared.TLSKey) && system.FileExists(shared.TLSCrt) {
		log.Info("✅ TLS certs already exist, skipping generation")
		return nil
	}

	ok := interaction.PromptYesNo("No TLS certs found. Generate self-signed TLS certs now?", true, log)
	if !ok {
		return fmt.Errorf("user declined TLS certificate generation")
	}

	log.Info("🔐 Generating Vault TLS certificate (simple mode)", zap.String("CN", hostname))

	cmd := exec.Command("openssl", "req", "-new", "-newkey", "rsa:4096",
		"-days", "825", "-nodes", "-x509",
		"-subj", "/CN="+hostname,
		"-addext", fmt.Sprintf("subjectAltName=DNS:%s,IP:%s", hostname, shared.LocalhostSAN),
		"-keyout", shared.TLSKey,
		"-out", shared.TLSCrt,
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

	log.Info("✅ Vault TLS cert generated and secured", zap.String("key", shared.TLSKey), zap.String("crt", shared.TLSCrt))
	return nil
}

func fixTLSCertIfMissingSAN(log *zap.Logger) error {
	url := shared.VaultHealthEndpoint
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
			if err := os.Remove(shared.TLSKey); err != nil && !os.IsNotExist(err) {
				log.Error("failed to remove broken TLS key", zap.Error(err))
			}
			if err := os.Remove(shared.TLSCrt); err != nil && !os.IsNotExist(err) {
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

//
// ========================== LIFECYCLE_CA ==========================
//

/**/
// ## 3. Ensure TLS Certificates Exist
// 	- Prompt for self-signed cert confirmation
// 	- Generate cert with CN = internal hostname
// 	- Save to `/etc/vault.d/vault.crt` and `.key`
// 	- EOS will ensure required directories (e.g. `/etc/vault.d`, `/var/lib/eos/secrets`, `/opt/pandora/data`) exist with appropriate ownership and permissions before writing any files.
// 	- If any directory creation fails, EOS will abort and suggest running as root or fixing permissions.
// ### Decision: Self-Signed TLS with Interactive Prompting
// - Use self-signed certs by default to secure Vault listener.
// - Allow user override via `--cert` and `--key` flags.
// - If no flags are provided, prompt the user to confirm generating self-signed certs interactively.
// - Certificates will be written to:
//   - `/etc/vault.d/vault.crt`
//   - `/etc/vault.d/vault.key`
// - Designed to bootstrap secure vault health, unattended agent-to-host workflows, and future PKI.
// - Avoids brittle reliance on external ACME or CA automation in early stages.
// - Cert SANs must include both internal hostname and `127.0.0.1` to support local Vault Agent auth.
// - EOS will generate SANs by default, but warns if `--cert` is provided and lacks expected hostnames.
// - Self-signed certs are valid for 1 year and trusted only on localhost connections.
// - If users wish to use these certs across machines or in CI, EOS provides an option to export the root CA via `eos vault export-ca`.
// ---
/**/

/**/
// EnsureVaultTLS ensures that TLS certificates for Vault exist, generating self-signed ones if needed.
// It verifies SAN coverage and system trust, aborting if directory setup or permissions fail.
// EnsureVaultTLS ensures Vault TLS certs are present and valid.
// If no certs exist, it interactively prompts to generate a new self-signed cert.
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

//     - Prompt for self-signed cert confirmation
//     - Generate cert with CN = internal hostname
//     - Save to `/etc/vault.d/vault.crt` and `.key`
//     - EOS will ensure required directories (e.g. `/etc/vault.d`, `/var/lib/eos/secrets`, `/opt/pandora/data`) exist with appropriate ownership and permissions before writing any files.
//     - If any directory creation fails, EOS will abort and suggest running as root or fixing permissions.

// ### Decision: Self-Signed TLS with Interactive Prompting

// - Use self-signed certs by default to secure Vault listener.
// - Allow user override via `--cert` and `--key` flags.
// - If no flags are provided, prompt the user to confirm generating self-signed certs interactively.
// - Certificates will be written to:
//   - `/etc/vault.d/vault.crt`
//   - `/etc/vault.d/vault.key`
// - Designed to bootstrap secure vault health, unattended agent-to-host workflows, and future PKI.
// - Avoids brittle reliance on external ACME or CA automation in early stages.
// - Cert SANs must include both internal hostname and `127.0.0.1` to support local Vault Agent auth.
// - EOS will generate SANs by default, but warns if `--cert` is provided and lacks expected hostnames.
// - Self-signed certs are valid for 1 year and trusted only on localhost connections.
// - If users wish to use these certs across machines or in CI, EOS provides an option to export the root CA via `eos vault export-ca`.

// ---

/**/

/**/
func secureVaultTLSOwnership(log *zap.Logger) error {
	uid, gid, err := system.LookupUser("vault")
	if err != nil {
		log.Warn("could not lookup vault user", zap.Error(err))
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

/**/
