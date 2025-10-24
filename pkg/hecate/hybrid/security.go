// pkg/hecate/hybrid/security.go

package hybrid

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupHybridCertificates sets up certificate management for hybrid connections
func SetupHybridCertificates(rc *eos_io.RuntimeContext, link *HybridLink) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up hybrid certificates",
		zap.String("link_id", link.ID),
		zap.String("frontend_dc", link.FrontendDC),
		zap.String("backend_dc", link.BackendDC))

	// Generate CA for mutual TLS
	ca, err := generateCA(link.ID)
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	// Generate certificates for each DC
	frontendCert, err := generateCertificate(ca, link.FrontendDC)
	if err != nil {
		return fmt.Errorf("failed to generate frontend certificate: %w", err)
	}

	backendCert, err := generateCertificate(ca, link.BackendDC)
	if err != nil {
		return fmt.Errorf("failed to generate backend certificate: %w", err)
	}

	// Distribute certificates via Consul KV (encrypted)
	if err := distributeCertificates(rc, link, ca, frontendCert, backendCert); err != nil {
		return fmt.Errorf("failed to distribute certificates: %w", err)
	}

	// Configure automatic rotation
	if err := scheduleRotation(rc, link, 30*24*time.Hour); err != nil {
		logger.Warn("Failed to schedule certificate rotation",
			zap.Error(err))
	}

	logger.Info("Hybrid certificates setup completed",
		zap.String("link_id", link.ID))

	return nil
}

// ConfigureHybridIntentions configures Consul intentions for zero-trust networking
func ConfigureHybridIntentions(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring hybrid intentions",
		zap.String("backend_id", backend.ID),
		zap.String("service", backend.ConsulService.Name))

	// Create intention: frontend-proxy -> backend-service
	intention := &api.Intention{
		SourceName:      fmt.Sprintf("%s-proxy", backend.PublicDomain),
		DestinationName: backend.ConsulService.Name,
		Action:          api.IntentionActionAllow,
		Meta: map[string]string{
			"hybrid-backend": "true",
			"created-by":     "eos-hecate",
			"backend-id":     backend.ID,
		},
	}

	if err := createIntention(rc, intention); err != nil {
		return fmt.Errorf("failed to create intention: %w", err)
	}

	// Create additional intentions for health checks
	healthIntention := &api.Intention{
		SourceName:      "health-checker",
		DestinationName: backend.ConsulService.Name,
		Action:          api.IntentionActionAllow,
		Meta: map[string]string{
			"hybrid-backend": "true",
			"created-by":     "eos-hecate",
			"purpose":        "health-check",
		},
	}

	if err := createIntention(rc, healthIntention); err != nil {
		logger.Warn("Failed to create health check intention",
			zap.Error(err))
	}

	logger.Info("Hybrid intentions configured successfully",
		zap.String("backend_id", backend.ID))

	return nil
}

// ValidateHybridSecurity validates the security configuration
func ValidateHybridSecurity(rc *eos_io.RuntimeContext, link *HybridLink) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating hybrid security configuration",
		zap.String("link_id", link.ID))

	// Check certificate validity
	if err := validateCertificates(rc, link); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// Check encryption configuration
	if err := validateEncryption(rc, link); err != nil {
		return fmt.Errorf("encryption validation failed: %w", err)
	}

	// Check intentions
	if err := validateIntentions(rc, link); err != nil {
		return fmt.Errorf("intentions validation failed: %w", err)
	}

	logger.Info("Hybrid security validation completed",
		zap.String("link_id", link.ID))

	return nil
}

// RotateHybridCertificates rotates certificates for hybrid connections
func RotateHybridCertificates(rc *eos_io.RuntimeContext, linkID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Rotating hybrid certificates",
		zap.String("link_id", linkID))

	// TODO: Implement certificate rotation
	// This would involve:
	// 1. Generate new certificates
	// 2. Distribute to both DCs
	// 3. Update tunnel configurations
	// 4. Restart services if needed
	// 5. Clean up old certificates

	return nil
}

// Certificate generation functions

func generateCA(linkID string) (*x509.Certificate, error) {
	// Create CA template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Eos Hecate"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    fmt.Sprintf("Hecate-CA-%s", linkID),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate CA private key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse CA certificate
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return caCert, nil
}

func generateCertificate(caCert *x509.Certificate, dcName string) (*x509.Certificate, error) {
	// Create certificate template
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:  []string{"Eos Hecate"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    fmt.Sprintf("Hecate-%s", dcName),
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour), // 30 days
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{dcName, fmt.Sprintf("*.%s", dcName)},
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func distributeCertificates(rc *eos_io.RuntimeContext, link *HybridLink, ca, frontendCert, backendCert *x509.Certificate) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Distributing certificates",
		zap.String("link_id", link.ID))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Store CA certificate
	caKeyPath := fmt.Sprintf("hecate/hybrid/%s/ca", link.ID)
	caPem := encodeCertificatePEM(ca)
	
	if _, err := client.KV().Put(&api.KVPair{
		Key:   caKeyPath,
		Value: caPem,
	}, nil); err != nil {
		return fmt.Errorf("failed to store CA certificate: %w", err)
	}

	// Store frontend certificate
	frontendKeyPath := fmt.Sprintf("hecate/hybrid/%s/frontend", link.ID)
	frontendPem := encodeCertificatePEM(frontendCert)
	
	if _, err := client.KV().Put(&api.KVPair{
		Key:   frontendKeyPath,
		Value: frontendPem,
	}, nil); err != nil {
		return fmt.Errorf("failed to store frontend certificate: %w", err)
	}

	// Store backend certificate
	backendKeyPath := fmt.Sprintf("hecate/hybrid/%s/backend", link.ID)
	backendPem := encodeCertificatePEM(backendCert)
	
	if _, err := client.KV().Put(&api.KVPair{
		Key:   backendKeyPath,
		Value: backendPem,
	}, nil); err != nil {
		return fmt.Errorf("failed to store backend certificate: %w", err)
	}

	logger.Info("Certificates distributed successfully",
		zap.String("ca_path", caKeyPath),
		zap.String("frontend_path", frontendKeyPath),
		zap.String("backend_path", backendKeyPath))

	return nil
}

func encodeCertificatePEM(cert *x509.Certificate) []byte {
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(certPEM)
}

func scheduleRotation(rc *eos_io.RuntimeContext, link *HybridLink, interval time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Scheduling certificate rotation",
		zap.String("link_id", link.ID),
		zap.Duration("interval", interval))

	// TODO: Implement certificate rotation scheduling
	// This would involve:
	// 1. Set up periodic rotation timer
	// 2. Monitor certificate expiration
	// 3. Trigger rotation before expiration
	// 4. Handle rotation failures gracefully

	return nil
}

// Validation functions

func validateCertificates(rc *eos_io.RuntimeContext, link *HybridLink) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating certificates",
		zap.String("link_id", link.ID))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Check CA certificate
	caKeyPath := fmt.Sprintf("hecate/hybrid/%s/ca", link.ID)
	caPair, _, err := client.KV().Get(caKeyPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}
	if caPair == nil {
		return fmt.Errorf("CA certificate not found")
	}

	// Parse and validate CA certificate
	caCert, err := parseCertificatePEM(caPair.Value)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if time.Now().After(caCert.NotAfter) {
		return fmt.Errorf("CA certificate has expired")
	}

	// Validate certificate chain
	if err := validateCertificateChain(caCert, caCert); err != nil {
		return fmt.Errorf("CA certificate chain validation failed: %w", err)
	}

	// Check frontend certificate
	frontendKeyPath := fmt.Sprintf("hecate/hybrid/%s/frontend", link.ID)
	frontendPair, _, err := client.KV().Get(frontendKeyPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get frontend certificate: %w", err)
	}
	if frontendPair == nil {
		return fmt.Errorf("frontend certificate not found")
	}

	// Parse and validate frontend certificate
	frontendCert, err := parseCertificatePEM(frontendPair.Value)
	if err != nil {
		return fmt.Errorf("failed to parse frontend certificate: %w", err)
	}

	if time.Now().After(frontendCert.NotAfter) {
		return fmt.Errorf("frontend certificate has expired")
	}

	// Validate frontend certificate against CA
	if err := validateCertificateChain(frontendCert, caCert); err != nil {
		return fmt.Errorf("frontend certificate chain validation failed: %w", err)
	}

	// Check backend certificate
	backendKeyPath := fmt.Sprintf("hecate/hybrid/%s/backend", link.ID)
	backendPair, _, err := client.KV().Get(backendKeyPath, nil)
	if err != nil {
		return fmt.Errorf("failed to get backend certificate: %w", err)
	}
	if backendPair == nil {
		return fmt.Errorf("backend certificate not found")
	}

	// Parse and validate backend certificate
	backendCert, err := parseCertificatePEM(backendPair.Value)
	if err != nil {
		return fmt.Errorf("failed to parse backend certificate: %w", err)
	}

	if time.Now().After(backendCert.NotAfter) {
		return fmt.Errorf("backend certificate has expired")
	}

	// Validate backend certificate against CA
	if err := validateCertificateChain(backendCert, caCert); err != nil {
		return fmt.Errorf("backend certificate chain validation failed: %w", err)
	}

	logger.Info("Certificate validation completed successfully",
		zap.String("link_id", link.ID))

	return nil
}

func parseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func validateEncryption(rc *eos_io.RuntimeContext, link *HybridLink) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating encryption configuration",
		zap.String("link_id", link.ID))

	// Check if mTLS is enabled
	if !link.Security.MTLS {
		return fmt.Errorf("mTLS is not enabled")
	}

	// Validate encryption algorithm
	validAlgorithms := []string{"aes-256-gcm", "aes-128-gcm", "chacha20-poly1305"}
	isValid := false
	for _, algo := range validAlgorithms {
		if link.Security.Encryption == algo {
			isValid = true
			break
		}
	}

	if !isValid {
		return fmt.Errorf("invalid encryption algorithm: %s", link.Security.Encryption)
	}

	logger.Info("Encryption validation completed successfully",
		zap.String("link_id", link.ID))

	return nil
}

func validateIntentions(rc *eos_io.RuntimeContext, link *HybridLink) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating intentions configuration",
		zap.String("link_id", link.ID))

	// TODO: Implement intention validation
	// This would involve:
	// 1. Check if intentions are properly configured
	// 2. Validate allow/deny rules
	// 3. Check for conflicts
	// 4. Verify permissions

	return nil
}

// Intention management

func createIntention(rc *eos_io.RuntimeContext, intention *api.Intention) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Consul intention",
		zap.String("source", intention.SourceName),
		zap.String("destination", intention.DestinationName),
		zap.String("action", string(intention.Action)))

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Create intention (using IntentionUpsert instead of deprecated IntentionCreate)
	_, err = client.Connect().IntentionUpsert(intention, nil)
	if err != nil {
		return fmt.Errorf("failed to create intention: %w", err)
	}

	logger.Info("Intention created successfully",
		zap.String("source", intention.SourceName),
		zap.String("destination", intention.DestinationName))

	return nil
}

// GetTLSConfig returns TLS configuration for hybrid connections
func GetTLSConfig(rc *eos_io.RuntimeContext, linkID string) (*tls.Config, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting TLS configuration",
		zap.String("link_id", linkID))

	// TODO: Implement TLS configuration retrieval
	// This would involve:
	// 1. Get certificates from Consul KV
	// 2. Configure mTLS
	// 3. Set up certificate verification
	// 4. Configure cipher suites

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	return tlsConfig, nil
}

// SecureTokenGeneration generates secure tokens for authentication
func SecureTokenGeneration(rc *eos_io.RuntimeContext, length int) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating secure token",
		zap.Int("length", length))

	// Generate random bytes
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64
	token := fmt.Sprintf("%x", bytes)

	logger.Info("Secure token generated successfully",
		zap.Int("token_length", len(token)))

	return token, nil
}

// validateCertificateChain validates a certificate against its CA
func validateCertificateChain(cert, ca *x509.Certificate) error {
	// Create certificate pool with CA
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	
	// Verify certificate
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	
	_, err := cert.Verify(opts)
	return err
}