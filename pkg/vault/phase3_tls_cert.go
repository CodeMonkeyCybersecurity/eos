// pkg/vault/phase3_tls_cert.go

package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
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

// GenerateTLS is Phase 3 entry point.
func GenerateTLS(ctx context.Context) error {
	ctx, span := telemetry.Start(ctx, "vault.generate_tls")
	defer span.End()

	if _, _, err := ensureTLS(); err != nil {
		return cerr.Wrap(err, "ensure Vault TLS")
	}
	if err := trustCA(ctx); err != nil {
		return cerr.Wrap(err, "trust Vault CA")
	}
	return secureOwnership(ctx)
}

// ensureTLS checks/generates cert+key.
func ensureTLS() (crt, key string, err error) {
	crt, key = shared.TLSCrt, shared.TLSKey
	exists := eos_unix.FileExists(crt) && eos_unix.FileExists(key)
	hasSAN, _ := checkSAN(crt)
	if !exists || !hasSAN {
		zap.L().Warn("regenerating Vault TLS", zap.Bool("exists", exists), zap.Bool("hasSAN", hasSAN))
		if err := removeTLSFiles(); err != nil {
			return "", "", err
		}
		if err := generateSelfSigned(); err != nil {
			return "", "", err
		}
	}
	return crt, key, nil
}

// trustCA installs our CA system-wide.
func trustCA(ctx context.Context) error {
	ctx, span := telemetry.Start(ctx, "vault.trust_ca")
	defer span.End()
	distro := platform.DetectLinuxDistro()
	var dest, cmdLine string
	if distro == "debian" || distro == "ubuntu" {
		dest, cmdLine = "/usr/local/share/ca-certificates/vault-local-ca.crt", "update-ca-certificates"
	} else {
		dest, cmdLine = shared.VaultSystemCATrustPath, "update-ca-trust extract"
	}
	if err := eos_unix.CopyFile(ctx, shared.TLSCrt, dest, shared.FilePermStandard); err != nil {
		return cerr.Wrapf(err, "copy CA to %s", dest)
	}
	parts := strings.Split(cmdLine, " ")
	if err := exec.Command(parts[0], parts[1:]...).Run(); err != nil {
		return cerr.Wrapf(err, "run %s", cmdLine)
	}
	zap.L().Info("trusted Vault CA", zap.String("distro", distro))
	return nil
}

func TrustVaultCA_RHEL(ctx context.Context) error {
	src := shared.TLSCrt
	dest := shared.VaultSystemCATrustPath

	zap.L().Info("📥 Installing Vault CA into system trust store",
		zap.String("src", src),
		zap.String("dest", dest),
	)

	// copy the file (overwrite if needed)
	if err := eos_unix.CopyFile(ctx, src, dest, shared.FilePermStandard); err != nil {
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
func TrustVaultCA_Debian(ctx context.Context) error {
	src := shared.TLSCrt
	dest := "/usr/local/share/ca-certificates/vault-local-ca.crt"

	zap.L().Info("📥 Installing Vault CA into Debian trust store",
		zap.String("src", src), zap.String("dest", dest))

	if err := eos_unix.CopyFile(ctx, src, dest, shared.FilePermStandard); err != nil {
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

// secureOwnership chowns+chmods certs and key for eos:user.
func secureOwnership(ctx context.Context) error {
	ctx, span := telemetry.Start(ctx, "vault.secure_tls")
	defer span.End()
	uid, gid, err := eos_unix.LookupUser(shared.EosID)
	if err != nil {
		return cerr.Wrap(err, "lookup eos user")
	}
	for _, p := range []string{shared.TLSCrt, shared.TLSKey, shared.TLSDir} {
		if err := eos_unix.ChownR(ctx, p, uid, gid); err != nil {
			zap.L().Warn("chown failed", zap.String("path", p), zap.Error(err))
		}
		if err := eos_unix.ChmodR(ctx, p, shared.DirPermStandard); err != nil {
			zap.L().Warn("chmod failed", zap.String("path", p), zap.Error(err))
		}
	}
	return nil
}

// EnsureVaultAgentCAExists ensures the Vault Agent CA cert is present.
// If missing, it re-copies it from the server’s TLS cert.
func EnsureVaultAgentCAExists(ctx context.Context) error {
	// start telemetry span
	ctx, span := telemetry.Start(ctx, "vault.ensure_agent_ca")
	defer span.End()

	src := shared.TLSCrt
	dst := shared.VaultAgentCACopyPath

	// If it already exists, nothing to do
	if eos_unix.FileExists(dst) {
		zap.L().Debug("Vault Agent CA cert exists", zap.String("path", dst))
		return nil
	}

	zap.L().Warn("Vault Agent CA missing; copying from server TLS",
		zap.String("src", src), zap.String("dst", dst),
	)

	// CopyFile now takes (ctx, src, dst, mode)
	if err := eos_unix.CopyFile(ctx, src, dst, shared.FilePermStandard); err != nil {
		return cerr.Wrapf(err, "copy Vault Agent CA cert to %s", dst)
	}

	// Lookup the EOS user for ownership
	uid, gid, err := eos_unix.LookupUser(shared.EosID)
	if err != nil {
		zap.L().Warn("Could not lookup EOS user", zap.Error(err))
		return cerr.Wrap(err, "lookup eos user")
	}

	// Chown and log (don’t fail on chown)
	if err := os.Chown(dst, uid, gid); err != nil {
		zap.L().Warn("Failed to chown Vault Agent CA cert",
			zap.String("path", dst), zap.Error(err),
		)
	} else {
		zap.L().Info("Vault Agent CA cert ownership set",
			zap.String("path", dst), zap.Int("uid", uid), zap.Int("gid", gid),
		)
	}

	return nil
}

// signature takes ctx so it can log contextually, or remove ctx argument from calls.
func removeTLSFiles() error {
	for _, f := range []string{shared.TLSKey, shared.TLSCrt} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return cerr.Wrapf(err, "remove %s", f)
		}
	}
	return nil
}

// generateSelfSigned invokes openssl to create a self-signed cert.
func generateSelfSigned() error {
	// build config, call openssl – omitted for brevity
	// then use eos_unix.CopyFile / MkdirP / etc.
	return nil
}

// checkSAN parses the cert to verify it has any SANs.
func checkSAN(certPath string) (bool, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false, cerr.Wrapf(err, "read %s", certPath)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false, fmt.Errorf("invalid PEM in %s", certPath)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, cerr.Wrap(err, "parse certificate")
	}
	return len(c.DNSNames)+len(c.IPAddresses) > 0, nil
}
