// pkg/vault/tls_certificate.go
//
// Consolidated TLS certificate generation for Vault
// This module unifies the three previous implementations:
// - install.go generateSelfSignedCert()
// - phase3_tls_cert.go generateSelfSigned()
// - tls_raft.go GenerateRaftTLSCertificate()
//
// Reference: vault-complete-specification-v1.0-raft-integrated.md

package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CertificateConfig contains all configuration for TLS certificate generation
type CertificateConfig struct {
	// Certificate subject information
	Country            string
	State              string
	Locality           string
	Organization       string
	OrganizationalUnit string
	CommonName         string

	// Subject Alternative Names (SANs) - CRITICAL for proper TLS validation
	DNSNames    []string // DNS names (hostnames, FQDN, localhost, etc.)
	IPAddresses []net.IP // IP addresses (shared.GetInternalHostname, ::1, actual host IPs)

	// Certificate properties
	ValidityDays int  // Certificate validity period (default: 3650 for 10 years)
	KeySize      int  // RSA key size (default: 4096 for production)
	IsCA         bool // Whether this is a CA certificate

	// Output paths
	CertPath string // Path to write certificate (e.g., /etc/vault.d/tls/vault.crt)
	KeyPath  string // Path to write private key (e.g., /etc/vault.d/tls/vault.key)
	CAPath   string // Path to CA certificate if using internal CA

	// Ownership
	Owner string // User to own the certificate files (default: "vault")
	Group string // Group to own the certificate files (default: "vault")
}

// DefaultCertificateConfig returns default TLS certificate configuration
// This provides secure defaults following industry best practices
func DefaultCertificateConfig() *CertificateConfig {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "vault-server"
	}

	return &CertificateConfig{
		Country:      "AU",
		State:        "WA",
		Locality:     "Fremantle",
		Organization: "Code Monkey Cybersecurity",
		CommonName:   hostname,
		ValidityDays: 3650, // 10 years (recommended for self-signed)
		KeySize:      4096, // Strong security (4096-bit RSA)
		CertPath:     shared.TLSCrt,
		KeyPath:      shared.TLSKey,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("shared.GetInternalHostname")},
		Owner:        "vault",
		Group:        "vault",
	}
}

// GenerateSelfSignedCertificate generates a self-signed TLS certificate with comprehensive SANs
// This is the unified entry point for all Vault TLS certificate generation
func GenerateSelfSignedCertificate(rc *eos_io.RuntimeContext, config *CertificateConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Generating self-signed TLS certificate for Vault",
		zap.String("common_name", config.CommonName),
		zap.Int("dns_names", len(config.DNSNames)),
		zap.Int("ip_addresses", len(config.IPAddresses)),
		zap.Int("key_size", config.KeySize),
		zap.Int("validity_days", config.ValidityDays))

	// Validate configuration
	if err := validateCertificateConfig(config); err != nil {
		log.Error("Invalid certificate configuration", zap.Error(err))
		return fmt.Errorf("validate certificate config: %w", err)
	}

	// Ensure SANs include comprehensive list
	if err := enrichSANs(config); err != nil {
		log.Warn("Failed to enrich SANs with network information", zap.Error(err))
		// Continue anyway - we have at least the basic SANs
	}

	log.Info("Certificate will include SANs",
		zap.Strings("dns_names", config.DNSNames),
		zap.Int("ip_count", len(config.IPAddresses)))

	// Generate RSA private key
	log.Debug("Generating RSA private key", zap.Int("key_size", config.KeySize))
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		log.Error("Failed to generate private key", zap.Error(err))
		return fmt.Errorf("generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := generateSerialNumber()
	if err != nil {
		log.Error("Failed to generate serial number", zap.Error(err))
		return fmt.Errorf("generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(config.ValidityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{config.Country},
			Province:           []string{config.State},
			Locality:           []string{config.Locality},
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			CommonName:         config.CommonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		// Critical: Include both server and client auth for Raft cluster communication
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              config.DNSNames,
		IPAddresses:           config.IPAddresses,
	}

	// If this is a CA certificate, set CA flag
	if config.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		log.Info("Generating CA certificate")
	}

	log.Debug("Creating certificate",
		zap.Time("not_before", notBefore),
		zap.Time("not_after", notAfter),
		zap.Bool("is_ca", config.IsCA))

	// Create self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Error("Failed to create certificate", zap.Error(err))
		return fmt.Errorf("create certificate: %w", err)
	}

	// Ensure output directories exist
	certDir := filepath.Dir(config.CertPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Error("Failed to create certificate directory", zap.String("dir", certDir), zap.Error(err))
		return fmt.Errorf("create cert directory: %w", err)
	}

	// Write certificate to file
	log.Debug("Writing certificate", zap.String("path", config.CertPath))
	certFile, err := os.Create(config.CertPath)
	if err != nil {
		log.Error("Failed to create certificate file", zap.Error(err))
		return fmt.Errorf("create cert file: %w", err)
	}
	defer func() { _ = certFile.Close() }()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		log.Error("Failed to write certificate", zap.Error(err))
		return fmt.Errorf("write certificate: %w", err)
	}

	// Write private key to file
	log.Debug("Writing private key", zap.String("path", config.KeyPath))
	keyFile, err := os.Create(config.KeyPath)
	if err != nil {
		log.Error("Failed to create key file", zap.Error(err))
		return fmt.Errorf("create key file: %w", err)
	}
	defer func() { _ = keyFile.Close() }()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		log.Error("Failed to write private key", zap.Error(err))
		return fmt.Errorf("write private key: %w", err)
	}

	// CRITICAL: Set ownership BEFORE permissions to avoid race condition
	// If Vault service starts after files are created but before ownership is set,
	// it will fail with "permission denied" because files are owned by root:root.
	// By setting ownership first, the vault user can always read the files.
	if os.Geteuid() == 0 {
		if err := setFileOwnership(rc, config.CertPath, config.KeyPath, config.Owner, config.Group); err != nil {
			log.Error("CRITICAL: Failed to set vault ownership - Vault service will fail to start",
				zap.Error(err),
				zap.Int("euid", os.Geteuid()),
				zap.Int("uid", os.Getuid()))
			return fmt.Errorf("set file ownership: %w", err)
		}
	} else {
		log.Warn("Not running as root - TLS files will be owned by current user (Vault service may fail)",
			zap.Int("euid", os.Geteuid()),
			zap.Int("uid", os.Getuid()),
			zap.String("owner_requested", config.Owner))
	}

	// Now set permissions (after ownership is correct)
	// Certificate: world-readable for clients (0644)
	if err := os.Chmod(config.CertPath, 0644); err != nil {
		log.Warn("Failed to set certificate permissions", zap.Error(err))
	}

	// Private key: owner read-only for security (0600)
	if err := os.Chmod(config.KeyPath, 0600); err != nil {
		log.Error("Failed to set key permissions", zap.Error(err))
		return fmt.Errorf("set key permissions: %w", err)
	}

	log.Info("TLS certificate generated successfully",
		zap.String("cert", config.CertPath),
		zap.String("key", config.KeyPath),
		zap.Int("validity_days", config.ValidityDays),
		zap.Time("expires", notAfter))

	return nil
}

// enrichSANs adds comprehensive SANs to the certificate configuration
// This ensures the certificate works in all common scenarios
func enrichSANs(config *CertificateConfig) error {
	// Get hostname using intelligent resolution (hostname → Tailscale → interface IP → localhost)
	hostname := shared.GetInternalHostname()
	if hostname == "localhost" || hostname == "" {
		hostname = config.CommonName
	}

	// Build comprehensive DNS name list
	dnsNamesSet := make(map[string]bool)

	// Add existing DNS names
	for _, name := range config.DNSNames {
		dnsNamesSet[name] = true
	}

	// Always include these essential names
	essentialNames := []string{
		hostname,
		"localhost",
		"vault",
		"vault.service.consul", // Consul service DNS
		hostname + ".local",    // mDNS
		"*." + hostname,        // Wildcard for subdomains
		"*.localhost",          // Wildcard for localhost subdomains
	}

	for _, name := range essentialNames {
		dnsNamesSet[name] = true
	}

	// Try to get FQDN (may be different from hostname)
	if fqdnOutput, err := exec.Command("hostname", "-f").Output(); err == nil {
		fqdn := strings.TrimSpace(string(fqdnOutput))
		if fqdn != "" && fqdn != hostname {
			dnsNamesSet[fqdn] = true
		}
	}

	// Try to resolve hostname to get canonical name
	if addrs, err := net.LookupHost(hostname); err == nil && len(addrs) > 0 {
		// Get reverse DNS for first address
		if names, err := net.LookupAddr(addrs[0]); err == nil {
			for _, name := range names {
				canonicalName := strings.TrimSuffix(name, ".")
				if canonicalName != "" {
					dnsNamesSet[canonicalName] = true
				}
			}
		}
	}

	// Convert set to slice
	config.DNSNames = make([]string, 0, len(dnsNamesSet))
	for name := range dnsNamesSet {
		config.DNSNames = append(config.DNSNames, name)
	}

	// Build comprehensive IP address list
	ipSet := make(map[string]net.IP)

	// Add existing IPs
	for _, ip := range config.IPAddresses {
		ipSet[ip.String()] = ip
	}

	// NOTE: Loopback addresses (shared.GetInternalHostname, ::1) intentionally NOT included.
	// Rationale: Enforces proper service discovery via hostname/Consul DNS.
	// - Local access works via hostname: https://vhost1:8200
	// - Remote access via Tailscale or LAN hostname
	// - Service discovery via Consul: https://vault.service.consul:8200
	// - Prevents localhost bypass of service discovery and auditing
	// If shared.GetInternalHostname access is attempted, TLS validation will fail with clear error,
	// teaching users to use proper hostname-based addressing.

	// CRITICAL: Add actual host IP addresses from network interfaces
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			// Skip down interfaces and loopback
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				// Add non-loopback, non-link-local IPs
				if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
					ipSet[ip.String()] = ip
				}
			}
		}
	}

	// Convert set to slice
	config.IPAddresses = make([]net.IP, 0, len(ipSet))
	for _, ip := range ipSet {
		config.IPAddresses = append(config.IPAddresses, ip)
	}

	return nil
}

// validateCertificateConfig validates certificate configuration
func validateCertificateConfig(config *CertificateConfig) error {
	if config.CommonName == "" {
		return fmt.Errorf("common_name is required")
	}

	if config.ValidityDays <= 0 {
		return fmt.Errorf("validity_days must be positive")
	}

	if config.KeySize < 2048 {
		return fmt.Errorf("key_size must be at least 2048 bits (recommended: 4096)")
	}

	if len(config.DNSNames) == 0 && len(config.IPAddresses) == 0 {
		return fmt.Errorf("at least one DNS name or IP address is required for SANs")
	}

	if config.CertPath == "" {
		return fmt.Errorf("cert_path is required")
	}

	if config.KeyPath == "" {
		return fmt.Errorf("key_path is required")
	}

	return nil
}

// generateSerialNumber generates a cryptographically secure serial number
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// setFileOwnership sets ownership of certificate files to specified user:group
func setFileOwnership(rc *eos_io.RuntimeContext, certPath, keyPath, owner, _group string) error {
	log := otelzap.Ctx(rc.Ctx)

	uid, gid, err := eos_unix.LookupUser(rc.Ctx, owner)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", owner, err)
	}

	// CRITICAL: Set ownership on TLS directory FIRST
	// The directory is created by os.MkdirAll() as root:root, which would prevent
	// the vault user from accessing the certificate files inside it.
	certDir := filepath.Dir(certPath)
	if err := os.Chown(certDir, uid, gid); err != nil {
		return fmt.Errorf("chown directory %s: %w", certDir, err)
	}

	// Set ownership on certificate file
	if err := os.Chown(certPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", certPath, err)
	}

	// Set ownership on key file
	if err := os.Chown(keyPath, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", keyPath, err)
	}

	// Use Info instead of Debug so this appears in default logs (helps debugging)
	log.Info("Set certificate ownership successfully",
		zap.String("owner", owner),
		zap.Int("uid", uid),
		zap.Int("gid", gid),
		zap.String("directory", certDir),
		zap.String("cert", certPath),
		zap.String("key", keyPath))

	return nil
}

// VerifyCertificate verifies that a TLS certificate is valid and has proper SANs
func VerifyCertificate(rc *eos_io.RuntimeContext, certPath string, expectedSANs []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Verifying TLS certificate", zap.String("path", certPath))

	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (valid from: %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired (expired: %s)", cert.NotAfter)
	}

	// Log certificate details
	log.Info("Certificate details",
		zap.String("subject", cert.Subject.CommonName),
		zap.Time("not_before", cert.NotBefore),
		zap.Time("not_after", cert.NotAfter),
		zap.Strings("dns_names", cert.DNSNames),
		zap.Int("ip_addresses", len(cert.IPAddresses)))

	// Verify expected SANs are present
	if len(expectedSANs) > 0 {
		certSANs := make(map[string]bool)
		for _, dns := range cert.DNSNames {
			certSANs[dns] = true
		}
		for _, ip := range cert.IPAddresses {
			certSANs[ip.String()] = true
		}

		for _, expected := range expectedSANs {
			if !certSANs[expected] {
				return fmt.Errorf("certificate missing expected SAN: %s", expected)
			}
		}
	}

	log.Info("Certificate verification successful")
	return nil
}

// GetCertificateInfo returns information about a TLS certificate
func GetCertificateInfo(certPath string) (*CertificateInfo, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	ipStrings := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipStrings[i] = ip.String()
	}

	return &CertificateInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		IPAddresses:  ipStrings,
		IsCA:         cert.IsCA,
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// CertificateInfo contains information about a TLS certificate
type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	IPAddresses  []string
	IsCA         bool
	SerialNumber string
}
