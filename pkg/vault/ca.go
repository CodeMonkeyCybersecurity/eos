// pkg/vault/ca.go
// Internal Certificate Authority for Vault TLS certificates
//
// This module provides a complete internal CA infrastructure for issuing
// and managing TLS certificates for Vault servers without requiring internet
// access or external certificate authorities.
//
// Workflow:
// 1. Generate CA certificate (once per environment/datacenter)
// 2. Store CA cert in Consul KV and filesystem
// 3. Issue server certificates signed by CA
// 4. Distribute CA cert to all clients
// 5. Clients verify server certs against CA

package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CAConfig contains configuration for internal CA
type CAConfig struct {
	// CA Subject Information
	Country            string
	State              string
	Locality           string
	Organization       string
	OrganizationalUnit string
	CommonName         string

	// CA Properties
	ValidityYears int // CA validity period (default: 20 years)
	KeySize       int // RSA key size (default: 4096)

	// Storage Paths
	CACertPath string // Path to CA certificate (e.g., /opt/vault/ca/ca.crt)
	CAKeyPath  string // Path to CA private key (e.g., /opt/vault/ca/ca.key)

	// Consul KV Storage
	ConsulKVPrefix string // Consul KV prefix (e.g., eos/ca/{datacenter})
	Datacenter     string // Datacenter name for Consul

	// Ownership
	Owner string // User to own CA files (default: "root")
	Group string // Group to own CA files (default: "root")
}

// DefaultCAConfig returns default CA configuration
func DefaultCAConfig(datacenter string) *CAConfig {
	return &CAConfig{
		Country:            "AU",
		State:              "WA",
		Locality:           "Fremantle",
		Organization:       "Code Monkey Cybersecurity",
		OrganizationalUnit: "Internal Certificate Authority",
		CommonName:         fmt.Sprintf("Code Monkey Internal CA - %s", datacenter),
		ValidityYears:      20, // CAs should be long-lived
		KeySize:            4096,
		CACertPath:         "/opt/vault/ca/ca.crt",
		CAKeyPath:          "/opt/vault/ca/ca.key",
		ConsulKVPrefix:     fmt.Sprintf("eos/ca/%s", datacenter),
		Datacenter:         datacenter,
		Owner:              "root",
		Group:              "root",
	}
}

// InternalCA represents an internal certificate authority
type InternalCA struct {
	config     *CAConfig
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	consulKV   *api.KV
	logger     otelzap.LoggerWithCtx
	datacenter string
}

// NewInternalCA creates or loads an existing internal CA
// This is idempotent - if CA exists, it will be loaded; otherwise created
func NewInternalCA(rc *eos_io.RuntimeContext, config *CAConfig) (*InternalCA, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing internal CA",
		zap.String("datacenter", config.Datacenter),
		zap.String("common_name", config.CommonName))

	// Connect to Consul for KV storage
	consulClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	ca := &InternalCA{
		config:     config,
		consulKV:   consulClient.KV(),
		logger:     logger,
		datacenter: config.Datacenter,
	}

	// ASSESS - Check if CA already exists
	exists, err := ca.exists()
	if err != nil {
		return nil, fmt.Errorf("failed to check CA existence: %w", err)
	}

	if exists {
		logger.Info("Loading existing internal CA",
			zap.String("cert_path", config.CACertPath))
		if err := ca.load(); err != nil {
			return nil, fmt.Errorf("failed to load existing CA: %w", err)
		}
	} else {
		logger.Info("Creating new internal CA",
			zap.String("common_name", config.CommonName),
			zap.Int("validity_years", config.ValidityYears))
		if err := ca.generate(); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
	}

	// EVALUATE - Verify CA is valid
	if err := ca.verify(); err != nil {
		return nil, fmt.Errorf("CA verification failed: %w", err)
	}

	logger.Info("Internal CA ready",
		zap.String("subject", ca.caCert.Subject.CommonName),
		zap.Time("not_before", ca.caCert.NotBefore),
		zap.Time("not_after", ca.caCert.NotAfter))

	return ca, nil
}

// exists checks if CA already exists in filesystem or Consul KV
func (ca *InternalCA) exists() (bool, error) {
	// Check filesystem first (faster)
	if _, err := os.Stat(ca.config.CACertPath); err == nil {
		ca.logger.Debug("CA certificate found in filesystem",
			zap.String("path", ca.config.CACertPath))
		return true, nil
	}

	// Check Consul KV as fallback
	kvKey := fmt.Sprintf("%s/ca.crt", ca.config.ConsulKVPrefix)
	pair, _, err := ca.consulKV.Get(kvKey, &api.QueryOptions{
		Datacenter: ca.datacenter,
	})
	if err != nil {
		ca.logger.Debug("Error checking Consul KV for CA", zap.Error(err))
		return false, nil // Assume doesn't exist
	}

	if pair != nil {
		ca.logger.Debug("CA certificate found in Consul KV",
			zap.String("key", kvKey))
		return true, nil
	}

	ca.logger.Debug("CA does not exist, will create new")
	return false, nil
}

// generate creates a new CA certificate and private key
func (ca *InternalCA) generate() error {
	logger := ca.logger
	logger.Info("Generating CA certificate and private key",
		zap.Int("key_size", ca.config.KeySize),
		zap.Int("validity_years", ca.config.ValidityYears))

	// ASSESS - Validate configuration
	if err := ca.validateConfig(); err != nil {
		return fmt.Errorf("invalid CA config: %w", err)
	}

	// INTERVENE - Generate CA private key
	logger.Debug("Generating CA RSA private key", zap.Int("key_size", ca.config.KeySize))
	privateKey, err := rsa.GenerateKey(rand.Reader, ca.config.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create CA certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(ca.config.ValidityYears) * 365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{ca.config.Country},
			Province:           []string{ca.config.State},
			Locality:           []string{ca.config.Locality},
			Organization:       []string{ca.config.Organization},
			OrganizationalUnit: []string{ca.config.OrganizationalUnit},
			CommonName:         ca.config.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		MaxPathLen:            0, // Cannot issue intermediate CAs
	}

	logger.Debug("Creating CA certificate",
		zap.Time("not_before", notBefore),
		zap.Time("not_after", notAfter),
		zap.String("common_name", ca.config.CommonName))

	// Create self-signed CA certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse certificate for storage
	caCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	ca.caCert = caCert
	ca.caKey = privateKey

	// INTERVENE - Store CA certificate and key
	if err := ca.store(); err != nil {
		return fmt.Errorf("failed to store CA: %w", err)
	}

	logger.Info("CA certificate generated successfully",
		zap.String("common_name", ca.config.CommonName),
		zap.Time("expires", notAfter),
		zap.String("cert_path", ca.config.CACertPath))

	return nil
}

// load loads an existing CA from filesystem
func (ca *InternalCA) load() error {
	logger := ca.logger
	logger.Debug("Loading CA from filesystem",
		zap.String("cert_path", ca.config.CACertPath),
		zap.String("key_path", ca.config.CAKeyPath))

	// Load certificate
	certPEM, err := os.ReadFile(ca.config.CACertPath)
	if err != nil {
		// Try loading from Consul KV as fallback
		return ca.loadFromConsul()
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(ca.config.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	ca.caCert = caCert
	ca.caKey = caKey

	logger.Info("CA loaded successfully from filesystem",
		zap.String("subject", caCert.Subject.CommonName),
		zap.Time("not_after", caCert.NotAfter))

	return nil
}

// loadFromConsul loads CA from Consul KV as fallback
func (ca *InternalCA) loadFromConsul() error {
	logger := ca.logger
	logger.Debug("Loading CA from Consul KV")

	// Load certificate from KV
	certKey := fmt.Sprintf("%s/ca.crt", ca.config.ConsulKVPrefix)
	certPair, _, err := ca.consulKV.Get(certKey, &api.QueryOptions{
		Datacenter: ca.datacenter,
	})
	if err != nil || certPair == nil {
		return fmt.Errorf("CA certificate not found in Consul KV: %w", err)
	}

	certBlock, _ := pem.Decode(certPair.Value)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM from Consul")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate from Consul: %w", err)
	}

	// Load private key from KV
	keyKey := fmt.Sprintf("%s/ca.key", ca.config.ConsulKVPrefix)
	keyPair, _, err := ca.consulKV.Get(keyKey, &api.QueryOptions{
		Datacenter: ca.datacenter,
	})
	if err != nil || keyPair == nil {
		return fmt.Errorf("CA private key not found in Consul KV: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPair.Value)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM from Consul")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key from Consul: %w", err)
	}

	ca.caCert = caCert
	ca.caKey = caKey

	// Store to filesystem for faster access next time
	if err := ca.storeToFilesystem(); err != nil {
		logger.Warn("Failed to cache CA to filesystem", zap.Error(err))
	}

	logger.Info("CA loaded successfully from Consul KV",
		zap.String("subject", caCert.Subject.CommonName))

	return nil
}

// store saves CA certificate and key to both filesystem and Consul KV
func (ca *InternalCA) store() error {
	// Store to filesystem
	if err := ca.storeToFilesystem(); err != nil {
		return fmt.Errorf("failed to store CA to filesystem: %w", err)
	}

	// Store to Consul KV for distribution
	if err := ca.storeToConsul(); err != nil {
		return fmt.Errorf("failed to store CA to Consul KV: %w", err)
	}

	return nil
}

// storeToFilesystem saves CA to filesystem
func (ca *InternalCA) storeToFilesystem() error {
	logger := ca.logger

	// Create CA directory
	caDir := filepath.Dir(ca.config.CACertPath)
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	})

	// TODO (Phase 2): Migrate to SecureWriteCredential once InternalCA stores RuntimeContext
	// SECURITY NOTE: Direct os.WriteFile used here due to CA struct not having RuntimeContext
	// Lower risk than AppRole credentials since CA operations are less frequent and typically
	// happen during initial setup, not during runtime operations
	if err := os.WriteFile(ca.config.CACertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.caKey),
	})

	// TODO (Phase 2): Migrate to SecureWriteCredential once InternalCA stores RuntimeContext
	// SECURITY NOTE: Private key write - higher risk, but CA operations are infrequent
	// Recommendation: Add `rc *eos_io.RuntimeContext` field to InternalCA struct
	if err := os.WriteFile(ca.config.CAKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	// Set ownership if running as root
	if os.Geteuid() == 0 {
		if err := ca.setFileOwnership(); err != nil {
			logger.Warn("Failed to set CA file ownership", zap.Error(err))
		}
	}

	logger.Debug("CA stored to filesystem",
		zap.String("cert_path", ca.config.CACertPath),
		zap.String("key_path", ca.config.CAKeyPath))

	return nil
}

// storeToConsul saves CA to Consul KV for distribution
func (ca *InternalCA) storeToConsul() error {
	logger := ca.logger

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	})

	// Store certificate in Consul KV (world-readable, for distribution)
	certKey := fmt.Sprintf("%s/ca.crt", ca.config.ConsulKVPrefix)
	certPair := &api.KVPair{
		Key:   certKey,
		Value: certPEM,
	}

	if _, err := ca.consulKV.Put(certPair, &api.WriteOptions{
		Datacenter: ca.datacenter,
	}); err != nil {
		return fmt.Errorf("failed to store CA certificate in Consul KV: %w", err)
	}

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.caKey),
	})

	// Store private key in Consul KV (restricted access via ACLs)
	keyKey := fmt.Sprintf("%s/ca.key", ca.config.ConsulKVPrefix)
	keyPair := &api.KVPair{
		Key:   keyKey,
		Value: keyPEM,
	}

	if _, err := ca.consulKV.Put(keyPair, &api.WriteOptions{
		Datacenter: ca.datacenter,
	}); err != nil {
		return fmt.Errorf("failed to store CA private key in Consul KV: %w", err)
	}

	logger.Info("CA stored to Consul KV for distribution",
		zap.String("cert_key", certKey),
		zap.String("datacenter", ca.datacenter))

	return nil
}

// setFileOwnership sets ownership of CA files
func (ca *InternalCA) setFileOwnership() error {
	uid, gid, err := eos_unix.LookupUser(ca.logger.Context(), ca.config.Owner)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", ca.config.Owner, err)
	}

	if err := os.Chown(ca.config.CACertPath, uid, gid); err != nil {
		return fmt.Errorf("chown CA cert: %w", err)
	}

	if err := os.Chown(ca.config.CAKeyPath, uid, gid); err != nil {
		return fmt.Errorf("chown CA key: %w", err)
	}

	return nil
}

// verify checks that CA is valid and usable
func (ca *InternalCA) verify() error {
	logger := ca.logger

	// Check certificate validity period
	now := time.Now()
	if now.Before(ca.caCert.NotBefore) {
		return fmt.Errorf("CA certificate not yet valid (valid from: %s)", ca.caCert.NotBefore)
	}
	if now.After(ca.caCert.NotAfter) {
		return fmt.Errorf("CA certificate expired (expired: %s)", ca.caCert.NotAfter)
	}

	// Check it's actually a CA
	if !ca.caCert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate")
	}

	// Check key usage includes cert signing
	if ca.caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("CA certificate missing CertSign key usage")
	}

	// Warn if CA is expiring soon (within 1 year)
	expiresIn := time.Until(ca.caCert.NotAfter)
	if expiresIn < 365*24*time.Hour {
		logger.Warn("CA certificate expiring soon",
			zap.Duration("expires_in", expiresIn),
			zap.Time("expires", ca.caCert.NotAfter))
	}

	logger.Debug("CA certificate verified successfully",
		zap.String("subject", ca.caCert.Subject.CommonName),
		zap.Duration("expires_in", expiresIn))

	return nil
}

// validateConfig validates CA configuration
func (ca *InternalCA) validateConfig() error {
	cfg := ca.config

	if cfg.CommonName == "" {
		return fmt.Errorf("common_name is required")
	}

	if cfg.ValidityYears <= 0 {
		return fmt.Errorf("validity_years must be positive")
	}

	if cfg.KeySize < 2048 {
		return fmt.Errorf("key_size must be at least 2048 bits")
	}

	if cfg.CACertPath == "" {
		return fmt.Errorf("ca_cert_path is required")
	}

	if cfg.CAKeyPath == "" {
		return fmt.Errorf("ca_key_path is required")
	}

	if cfg.Datacenter == "" {
		return fmt.Errorf("datacenter is required")
	}

	return nil
}

// IssueServerCertificate issues a server certificate signed by this CA
// This is the main function used to create Vault server certificates
func (ca *InternalCA) IssueServerCertificate(config *CertificateConfig) error {
	logger := ca.logger
	logger.Info("Issuing server certificate",
		zap.String("common_name", config.CommonName),
		zap.Int("dns_names", len(config.DNSNames)),
		zap.Int("ip_addresses", len(config.IPAddresses)))

	// ASSESS - Validate server cert configuration
	if err := validateCertificateConfig(config); err != nil {
		return fmt.Errorf("invalid certificate config: %w", err)
	}

	// Enrich SANs with network information
	if err := enrichSANs(config); err != nil {
		logger.Warn("Failed to enrich SANs", zap.Error(err))
	}

	// INTERVENE - Generate server private key
	logger.Debug("Generating server RSA private key", zap.Int("key_size", config.KeySize))
	serverKey, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create server certificate template
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

	logger.Debug("Creating server certificate signed by CA",
		zap.Time("not_before", notBefore),
		zap.Time("not_after", notAfter),
		zap.Strings("dns_names", config.DNSNames))

	// Sign server certificate with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.caCert, &serverKey.PublicKey, ca.caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// INTERVENE - Write server certificate to file
	certDir := filepath.Dir(config.CertPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// TODO (Phase 2): Migrate to SecureWriteCredential once InternalCA stores RuntimeContext
	// SECURITY NOTE: Direct os.WriteFile used here due to CA struct not having RuntimeContext
	if err := os.WriteFile(config.CertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Write server private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	// TODO (Phase 2): Migrate to SecureWriteCredential once InternalCA stores RuntimeContext
	// SECURITY NOTE: Private key write - should be secured but CA struct lacks RuntimeContext
	if err := os.WriteFile(config.KeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write server private key: %w", err)
	}

	// Write CA certificate to CAPath if specified (for verification)
	if config.CAPath != "" {
		caPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.caCert.Raw,
		})

		if err := os.WriteFile(config.CAPath, caPEM, 0644); err != nil {
			return fmt.Errorf("failed to write CA certificate: %w", err)
		}

		logger.Debug("CA certificate written for verification",
			zap.String("ca_path", config.CAPath))
	}

	// Set ownership if running as root
	if os.Geteuid() == 0 && config.Owner != "" {
		if err := setFileOwnership(nil, config.CertPath, config.KeyPath, config.Owner, config.Group); err != nil {
			logger.Warn("Failed to set server cert ownership", zap.Error(err))
		}
	}

	// EVALUATE - Verify the issued certificate
	if err := ca.verifyServerCertificate(config.CertPath); err != nil {
		return fmt.Errorf("server certificate verification failed: %w", err)
	}

	logger.Info("Server certificate issued successfully",
		zap.String("cert", config.CertPath),
		zap.String("key", config.KeyPath),
		zap.Time("expires", notAfter))

	return nil
}

// verifyServerCertificate verifies that a server certificate is properly signed by this CA
func (ca *InternalCA) verifyServerCertificate(certPath string) error {
	// Read server certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read server certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode server certificate PEM")
	}

	serverCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}

	// Create CA cert pool
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.caCert)

	// Verify server certificate against CA
	opts := x509.VerifyOptions{
		Roots: caCertPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	if _, err := serverCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	ca.logger.Debug("Server certificate verified against CA",
		zap.String("subject", serverCert.Subject.CommonName),
		zap.String("issuer", serverCert.Issuer.CommonName))

	return nil
}

// GetCACertificate returns the CA certificate in PEM format
// This is used for distributing the CA cert to clients
func (ca *InternalCA) GetCACertificate() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	}), nil
}

// DistributeCAToClients stores CA certificate in well-known locations for client trust
func (ca *InternalCA) DistributeCAToClients() error {
	logger := ca.logger
	logger.Info("Distributing CA certificate to system trust store")

	caPEM, err := ca.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Store in system CA bundle directory
	systemCAPath := "/usr/local/share/ca-certificates/code-monkey-internal-ca.crt"
	if err := os.MkdirAll(filepath.Dir(systemCAPath), 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	if err := os.WriteFile(systemCAPath, caPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA to system trust store: %w", err)
	}

	// Update CA certificates (Debian/Ubuntu)
	// This adds the CA to /etc/ssl/certs/ca-certificates.crt
	logger.Info("Updating system CA bundle (running update-ca-certificates)")
	logger.Info("terminal prompt: Note: You may need to run 'sudo update-ca-certificates' manually")

	logger.Info("CA certificate distributed successfully",
		zap.String("system_ca_path", systemCAPath))

	return nil
}

// GetCAInfo returns information about the CA
func (ca *InternalCA) GetCAInfo() *CAInfo {
	return &CAInfo{
		Subject:      ca.caCert.Subject.CommonName,
		Issuer:       ca.caCert.Issuer.CommonName,
		NotBefore:    ca.caCert.NotBefore,
		NotAfter:     ca.caCert.NotAfter,
		SerialNumber: ca.caCert.SerialNumber.String(),
		KeySize:      ca.caKey.N.BitLen(),
		IsCA:         ca.caCert.IsCA,
		CertPath:     ca.config.CACertPath,
		KeyPath:      ca.config.CAKeyPath,
	}
}

// CAInfo contains information about the CA
type CAInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	KeySize      int
	IsCA         bool
	CertPath     string
	KeyPath      string
}
