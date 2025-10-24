// pkg/vault/phase3_tls_cert.go

package vault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
func GenerateTLS(rc *eos_io.RuntimeContext) error {

	if _, _, err := ensureTLS(rc); err != nil {
		return cerr.Wrap(err, "ensure Vault TLS")
	}
	if err := trustCA(rc); err != nil {
		return cerr.Wrap(err, "trust Vault CA")
	}
	if err := EnsureVaultAgentCAExists(rc); err != nil {
		return cerr.Wrap(err, "ensure Vault Agent CA")
	}

	// REMOVED: secureOwnership(rc) call
	// RATIONALE: GenerateSelfSignedCertificate() already sets correct ownership+permissions
	// in tls_certificate.go:209-230. The secureOwnership() function was redundant and
	// DESTRUCTIVE - it used ChmodR(shared.DirPermStandard) which set everything to 0755,
	// including the private key (should be 0600). This caused Vault to refuse loading the
	// certificate with "permission denied" because Vault enforces security by rejecting
	// world-readable private keys.
	//
	// Historical context: This was a duplicate permission-setting code path that predated
	// the unified GenerateSelfSignedCertificate() function. Now that the unified function
	// handles ownership+permissions correctly (ownership FIRST to avoid race condition,
	// then file-specific permissions), this call is both unnecessary and harmful.

	return nil
}

// ensureTLS checks/generates cert+key.
func ensureTLS(rc *eos_io.RuntimeContext) (crt, key string, err error) {
	crt, key = shared.TLSCrt, shared.TLSKey
	exists := shared.FileExists(crt) && shared.FileExists(key)
	hasSAN, _ := checkSAN(crt)
	if !exists || !hasSAN {
		otelzap.Ctx(rc.Ctx).Warn("regenerating Vault TLS", zap.Bool("exists", exists), zap.Bool("hasSAN", hasSAN))
		if err := removeTLSFiles(); err != nil {
			return "", "", err
		}
		if err := generateSelfSigned(rc); err != nil {
			return "", "", err
		}
	}
	return crt, key, nil
}

// trustCA installs our CA system-wide.
func trustCA(rc *eos_io.RuntimeContext) error {
	distro := platform.DetectLinuxDistro(rc)
	var dest, cmdLine string
	if distro == "debian" || distro == "ubuntu" {
		dest, cmdLine = "/usr/local/share/ca-certificates/vault-local-ca.crt", "update-ca-certificates"
	} else {
		dest, cmdLine = shared.VaultSystemCATrustPath, "update-ca-trust extract"
	}
	if err := eos_unix.CopyFile(rc.Ctx, shared.TLSCrt, dest, shared.FilePermStandard); err != nil {
		return cerr.Wrapf(err, "copy CA to %s", dest)
	}
	parts := strings.Split(cmdLine, " ")
	if err := exec.Command(parts[0], parts[1:]...).Run(); err != nil {
		return cerr.Wrapf(err, "run %s", cmdLine)
	}
	otelzap.Ctx(rc.Ctx).Info("trusted Vault CA", zap.String("distro", distro))
	return nil
}

func TrustVaultCA_RHEL(rc *eos_io.RuntimeContext) error {
	src := shared.TLSCrt
	dest := shared.VaultSystemCATrustPath

	otelzap.Ctx(rc.Ctx).Info(" Installing Vault CA into system trust store",
		zap.String("src", src),
		zap.String("dest", dest),
	)

	// copy the file (overwrite if needed)
	if err := eos_unix.CopyFile(rc.Ctx, src, dest, shared.FilePermStandard); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	// ensure root owns it
	if err := os.Chown(dest, 0, 0); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("could not chown system CA file", zap.Error(err))
	}

	// RHEL9 / CentOS Stream 9
	cmd := exec.Command("update-ca-trust", "extract")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to update system CA trust", zap.Error(err))
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault CA is now trusted system‑wide")
	return nil
}

// TrustVaultCADebian installs the Vault CA into Debian/Ubuntu's trust store.
func TrustVaultCA_Debian(rc *eos_io.RuntimeContext) error {
	src := shared.TLSCrt
	dest := "/usr/local/share/ca-certificates/vault-local-ca.crt"

	otelzap.Ctx(rc.Ctx).Info(" Installing Vault CA into Debian trust store",
		zap.String("src", src), zap.String("dest", dest))

	if err := eos_unix.CopyFile(rc.Ctx, src, dest, shared.FilePermStandard); err != nil {
		return fmt.Errorf("copy CA to %s: %w", dest, err)
	}
	if err := os.Chown(dest, 0, 0); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("could not chown CA file", zap.Error(err))
	}

	cmd := exec.Command("update-ca-certificates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to update system CA trust", zap.Error(err))
		return fmt.Errorf("failed to update system CA trust: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault CA trusted system-wide on Debian/Ubuntu")
	return nil
}

// secureOwnership chowns+chmods certs and key for vault user.
func secureOwnership(rc *eos_io.RuntimeContext) error {

	// Use vault user instead of deprecated eos user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		// If vault user doesn't exist, use current user
		uid = os.Getuid()
		gid = os.Getgid()
		otelzap.Ctx(rc.Ctx).Info("Vault user not found, using current user for TLS ownership",
			zap.Int("uid", uid),
			zap.Int("gid", gid))
	}
	for _, p := range []string{shared.TLSCrt, shared.TLSKey, shared.TLSDir} {
		if err := eos_unix.ChownR(rc.Ctx, p, uid, gid); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("chown failed", zap.String("path", p), zap.Error(err))
		}
		if err := eos_unix.ChmodR(rc.Ctx, p, shared.DirPermStandard); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("chmod failed", zap.String("path", p), zap.Error(err))
		}
	}
	return nil
}

// EnsureVaultAgentCAExists ensures the Vault Agent CA cert is present.
// If missing, it re-copies it from the server’s TLS cert.
func EnsureVaultAgentCAExists(rc *eos_io.RuntimeContext) error {

	src := shared.TLSCrt
	dst := shared.VaultAgentCACopyPath

	// If it already exists, nothing to do
	if shared.FileExists(dst) {
		otelzap.Ctx(rc.Ctx).Debug("Vault Agent CA cert exists", zap.String("path", dst))
		return nil
	}

	otelzap.Ctx(rc.Ctx).Warn("Vault Agent CA missing; copying from server TLS",
		zap.String("src", src), zap.String("dst", dst),
	)

	// CopyFile now takes (rc, src, dst, mode)
	if err := eos_unix.CopyFile(rc.Ctx, src, dst, shared.FilePermStandard); err != nil {
		return cerr.Wrapf(err, "copy Vault Agent CA cert to %s", dst)
	}

	// Use vault user instead of deprecated eos user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		// If vault user doesn't exist, use current user
		uid = os.Getuid()
		gid = os.Getgid()
		otelzap.Ctx(rc.Ctx).Info("Vault user not found, using current user for CA cert ownership",
			zap.Int("uid", uid),
			zap.Int("gid", gid))
	}

	// Chown and log (don’t fail on chown)
	if err := os.Chown(dst, uid, gid); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to chown Vault Agent CA cert",
			zap.String("path", dst), zap.Error(err),
		)
	} else {
		otelzap.Ctx(rc.Ctx).Info("Vault Agent CA cert ownership set",
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

// generateSelfSigned generates a self-signed cert using the consolidated TLS module
func generateSelfSigned(rc *eos_io.RuntimeContext) error {
	// Ensure TLS directory exists
	if err := os.MkdirAll(shared.TLSDir, 0o755); err != nil {
		return cerr.Wrapf(err, "create TLS directory %s", shared.TLSDir)
	}

	// Get hostname for certificate
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	// Create certificate configuration using consolidated module
	config := &CertificateConfig{
		Country:      "AU",
		State:        "WA",
		Locality:     "Fremantle",
		Organization: "Code Monkey Cybersecurity",
		CommonName:   hostname,
		ValidityDays: 3650, // 10 years for self-signed
		KeySize:      4096, // Strong security
		CertPath:     shared.TLSCrt,
		KeyPath:      shared.TLSKey,
		Owner:        "vault",
		Group:        "vault",
		// Initial SANs - enrichSANs() will add comprehensive list automatically
		DNSNames:    []string{hostname}, // enrichSANs() adds comprehensive DNS names
		IPAddresses: []net.IP{},         // enrichSANs() adds hostname IPs + Tailscale + interfaces (NO localhost)
	}

	// Generate certificate using consolidated module
	// This will automatically enrich SANs with all network interfaces, FQDN, wildcards, etc.
	if err := GenerateSelfSignedCertificate(rc, config); err != nil {
		return cerr.Wrap(err, "generate certificate")
	}

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
