package lifecycle

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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	consulTLSDir      = "/etc/consul.d/tls"
	consulCACertFile  = "consul-agent-ca.pem"
	consulCAKeyFile   = "consul-agent-ca-key.pem"
	consulCertFile    = "server.pem"
	consulKeyFile     = "server-key.pem"
	certValidityYears = 2
	caValidityYears   = 10
)

func ensureTLSCertificates(logger otelzap.LoggerWithCtx, bindAddr, datacenter string) (*config.TLSConfig, error) {
	if err := os.MkdirAll(consulTLSDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create TLS directory: %w", err)
	}
	if err := chownConsul(consulTLSDir); err != nil {
		logger.Warn("Failed to set TLS directory ownership",
			zap.String("path", consulTLSDir),
			zap.Error(err))
	}

	caCertPath := filepath.Join(consulTLSDir, consulCACertFile)
	caKeyPath := filepath.Join(consulTLSDir, consulCAKeyFile)
	serverCertPath := filepath.Join(consulTLSDir, consulCertFile)
	serverKeyPath := filepath.Join(consulTLSDir, consulKeyFile)

	caCert, caKey, err := loadOrCreateCA(logger, caCertPath, caKeyPath)
	if err != nil {
		return nil, err
	}

	if certValid(serverCertPath) && fileExists(serverKeyPath) {
		if err := ensureTLSOwnership(serverCertPath, serverKeyPath); err != nil {
			logger.Warn("Failed to ensure TLS file ownership", zap.Error(err))
		}
		return &config.TLSConfig{
			Enabled:              true,
			CAFile:               caCertPath,
			CertFile:             serverCertPath,
			KeyFile:              serverKeyPath,
			VerifyIncoming:       true,
			VerifyOutgoing:       true,
			VerifyServerHostname: true,
		}, nil
	}

	if err := generateServerCertificate(logger, serverCertPath, serverKeyPath, caCert, caKey, bindAddr, datacenter); err != nil {
		return nil, err
	}

	if err := ensureTLSOwnership(serverCertPath, serverKeyPath); err != nil {
		logger.Warn("Failed to set TLS file ownership", zap.Error(err))
	}

	return &config.TLSConfig{
		Enabled:              true,
		CAFile:               caCertPath,
		CertFile:             serverCertPath,
		KeyFile:              serverKeyPath,
		VerifyIncoming:       true,
		VerifyOutgoing:       true,
		VerifyServerHostname: true,
	}, nil
}

func loadOrCreateCA(logger otelzap.LoggerWithCtx, certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if cert, key, err := loadCA(certPath, keyPath); err == nil {
		if cert.NotAfter.After(time.Now().Add(365 * 24 * time.Hour)) {
			logger.Info("Reusing existing Consul agent CA",
				zap.String("path", certPath),
				zap.Time("expires", cert.NotAfter))
			return cert, key, nil
		}
		logger.Warn("Existing Consul CA is expiring soon, generating new CA",
			zap.Time("expires", cert.NotAfter))
	}

	logger.Info("Generating new Consul agent CA",
		zap.String("cert_path", certPath))

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Eos Consul"},
			CommonName:   "Consul Agent CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(caValidityYears, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER, 0o644); err != nil {
		return nil, nil, err
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv), 0o600); err != nil {
		return nil, nil, err
	}

	return tmpl, priv, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return cert, key, nil
}

func generateServerCertificate(logger otelzap.LoggerWithCtx, certPath, keyPath string, caCert *x509.Certificate, caKey *rsa.PrivateKey, bindAddr, datacenter string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("failed to generate server serial number: %w", err)
	}

	hostname := shared.GetInternalHostname()
	nodeName := fmt.Sprintf("%s-consul", hostname)

	dnsNames := []string{
		"localhost",
		hostname,
		nodeName,
		fmt.Sprintf("%s.%s.consul", nodeName, datacenter),
		fmt.Sprintf("server.%s.consul", datacenter),
	}

	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(bindAddr); ip != nil {
		ipAddresses = append(ipAddresses, ip)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Eos Consul"},
			CommonName:   fmt.Sprintf("%s.%s.consul", nodeName, datacenter),
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(certValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER, 0o644); err != nil {
		return err
	}
	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv), 0o600); err != nil {
		return err
	}

	logger.Info("Generated new Consul TLS certificate",
		zap.String("cert_path", certPath),
		zap.Time("expires", tmpl.NotAfter))

	return nil
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", path, err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func ensureTLSOwnership(certPath, keyPath string) error {
	if err := os.Chmod(certPath, 0o644); err != nil {
		return err
	}
	if err := chownConsul(certPath); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return err
	}
	if err := chownConsul(keyPath); err != nil {
		return err
	}
	return nil
}

func certValid(path string) bool {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.NotAfter.After(time.Now().Add(24 * time.Hour))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
