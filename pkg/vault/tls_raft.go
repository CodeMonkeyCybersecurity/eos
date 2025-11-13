// pkg/vault/tls_raft.go

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
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TLSCertificateConfig contains configuration for TLS certificate generation
// Reference: vault-complete-specification-v1.0-raft-integrated.md - TLS Certificate Setup
type TLSCertificateConfig struct {
	// Certificate subject information
	Country            string
	State              string
	Locality           string
	Organization       string
	OrganizationalUnit string
	CommonName         string

	// Subject Alternative Names (SANs) - CRITICAL for Raft
	DNSNames    []string // All node hostnames and DNS names
	IPAddresses []net.IP // All node IP addresses

	// Certificate properties
	ValidityDays int  // Certificate validity period (default: 365)
	KeySize      int  // RSA key size (default: 4096)
	IsCA         bool // Whether this is a CA certificate

	// Output paths
	CertPath string // Path to write certificate (default: /opt/vault/tls/vault-cert.pem)
	KeyPath  string // Path to write private key (default: /opt/vault/tls/vault-key.pem)
	CAPath   string // Path to CA certificate if using internal CA
}

// DefaultTLSCertificateConfig returns default TLS certificate configuration
func DefaultTLSCertificateConfig() *TLSCertificateConfig {
	return &TLSCertificateConfig{
		Country:      "AU",
		State:        "WA",
		Locality:     "Fremantle",
		Organization: "Code Monkey Cybersecurity",
		CommonName:   "eos-vault-node1",
		ValidityDays: 365,
		KeySize:      4096,
		CertPath:     shared.TLSCrt,
		KeyPath:      shared.TLSKey,
		DNSNames:     []string{}, // enrichSANs() adds comprehensive DNS names
		IPAddresses:  []net.IP{}, // enrichSANs() adds hostname IPs + Tailscale + interfaces (NO localhost)
	}
}

// GenerateRaftTLSCertificate generates a self-signed TLS certificate with proper SANs for Raft
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Development Certificate (Self-Signed)
func GenerateRaftTLSCertificate(rc *eos_io.RuntimeContext, config *TLSCertificateConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Generating Raft TLS certificate",
		zap.String("common_name", config.CommonName),
		zap.Int("dns_names", len(config.DNSNames)),
		zap.Int("ip_addresses", len(config.IPAddresses)),
		zap.Int("validity_days", config.ValidityDays))

	// Validate configuration
	if err := validateRaftTLSConfig(config); err != nil {
		log.Error("Invalid TLS configuration", zap.Error(err))
		return fmt.Errorf("validate tls config: %w", err)
	}

	// Generate RSA private key
	log.Info("Generating RSA private key", zap.Int("key_size", config.KeySize))
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		log.Error("Failed to generate private key", zap.Error(err))
		return fmt.Errorf("generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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
	}

	log.Info("Creating certificate",
		zap.Time("not_before", notBefore),
		zap.Time("not_after", notAfter),
		zap.Strings("dns_names", config.DNSNames))

	// Create self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Error("Failed to create certificate", zap.Error(err))
		return fmt.Errorf("create certificate: %w", err)
	}

	// Ensure output directories exist
	certDir := filepath.Dir(config.CertPath)
	if err := os.MkdirAll(certDir, VaultBaseDirPerm); err != nil {
		log.Error("Failed to create certificate directory", zap.String("dir", certDir), zap.Error(err))
		return fmt.Errorf("create cert directory: %w", err)
	}

	// Write certificate to file
	log.Info("Writing certificate", zap.String("path", config.CertPath))
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

	// Set certificate file permissions (world-readable)
	if err := os.Chmod(config.CertPath, VaultTLSCertPerm); err != nil {
		log.Warn("Failed to set certificate permissions", zap.Error(err))
	}

	// Write private key to file
	log.Info("Writing private key", zap.String("path", config.KeyPath))
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

	// Set private key file permissions (owner read-only for security)
	if err := os.Chmod(config.KeyPath, VaultTLSKeyPerm); err != nil {
		log.Error("Failed to set key permissions", zap.Error(err))
		return fmt.Errorf("set key permissions: %w", err)
	}

	// Change ownership to vault:vault if running as root
	if os.Geteuid() == 0 {
		if err := setVaultOwnership(config.CertPath, config.KeyPath); err != nil {
			log.Warn("Failed to set vault ownership", zap.Error(err))
		}
	}

	log.Info("TLS certificate generated successfully",
		zap.String("cert", config.CertPath),
		zap.String("key", config.KeyPath),
		zap.Int("validity_days", config.ValidityDays))

	return nil
}

// GenerateMultiNodeRaftCertificate generates a TLS certificate for multi-node Raft cluster
// This certificate includes SANs for ALL nodes in the cluster
// Reference: vault-complete-specification-v1.0-raft-integrated.md - TLS Certificate Setup
func GenerateMultiNodeRaftCertificate(rc *eos_io.RuntimeContext, nodes []RaftNodeInfo) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Generating multi-node Raft TLS certificate", zap.Int("node_count", len(nodes)))

	if len(nodes) == 0 {
		return fmt.Errorf("no nodes provided for certificate generation")
	}

	// Build comprehensive SAN list from all nodes
	config := DefaultTLSCertificateConfig()
	config.CommonName = nodes[0].Hostname // Use first node as CN

	// Collect all DNS names and IP addresses
	dnsNames := make(map[string]bool)
	ipAddresses := make(map[string]net.IP)

	// NOTE: Localhost intentionally NOT included - enforces proper hostname-based addressing
	// enrichSANs() will add all required hostnames and IPs automatically

	for _, node := range nodes {
		// Add hostname
		if node.Hostname != "" {
			dnsNames[node.Hostname] = true
			dnsNames[node.Hostname+".local"] = true
		}

		// Add IP address
		if node.IPAddress != "" {
			if ip := net.ParseIP(node.IPAddress); ip != nil {
				ipAddresses[node.IPAddress] = ip
			}
		}

		// Add additional DNS names
		for _, dns := range node.AdditionalDNS {
			dnsNames[dns] = true
		}
	}

	// Convert maps to slices
	config.DNSNames = make([]string, 0, len(dnsNames))
	for dns := range dnsNames {
		config.DNSNames = append(config.DNSNames, dns)
	}

	config.IPAddresses = make([]net.IP, 0, len(ipAddresses))
	for _, ip := range ipAddresses {
		config.IPAddresses = append(config.IPAddresses, ip)
	}

	log.Info("Certificate will include SANs",
		zap.Int("dns_names", len(config.DNSNames)),
		zap.Int("ip_addresses", len(config.IPAddresses)),
		zap.Strings("dns_list", config.DNSNames))

	return GenerateRaftTLSCertificate(rc, config)
}

// RaftNodeInfo contains information about a Raft cluster node for certificate generation
type RaftNodeInfo struct {
	Hostname      string   // Node hostname (e.g., "eos-vault-node1")
	IPAddress     string   // Node IP address (e.g., "10.0.1.10")
	AdditionalDNS []string // Additional DNS names for this node
}

// validateRaftTLSConfig validates TLS certificate configuration for Raft
func validateRaftTLSConfig(config *TLSCertificateConfig) error {
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

// setVaultOwnership sets ownership of certificate files to vault:vault
func setVaultOwnership(_certPath, _keyPath string) error {
	// TODO: Implement proper ownership setting
	// This requires looking up vault user/group IDs and using os.Chown
	// For now, this is a placeholder
	return nil
}

// VerifyTLSCertificate verifies that a TLS certificate is valid and has proper SANs
// Reference: vault-complete-specification-v1.0-raft-integrated.md
func VerifyTLSCertificate(rc *eos_io.RuntimeContext, certPath string, expectedSANs []string) error {
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

// NOTE: GetCertificateInfo and CertificateInfo have been moved to tls_certificate.go
// This file (tls_raft.go) is deprecated in favor of the consolidated tls_certificate.go module
// See tls_certificate.go for the unified certificate generation implementation
