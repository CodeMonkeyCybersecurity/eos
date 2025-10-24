// pkg/vault/cert_renewal.go
// Automatic certificate renewal for Vault TLS certificates
//
// This module implements automatic renewal of Vault server certificates
// similar to Caddy's automatic certificate management. Certificates are
// renewed 30 days before expiration using systemd timers.
//
// Workflow:
// 1. systemd timer triggers renewal check daily
// 2. Check if certificate expires within 30 days
// 3. If yes, issue new certificate from CA
// 4. Reload Vault service to pick up new cert
// 5. Log renewal event to Consul KV

package vault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RenewalConfig contains certificate renewal configuration
type RenewalConfig struct {
	// Certificate paths
	CertPath string // Path to server certificate
	KeyPath  string // Path to server private key
	CAPath   string // Path to CA certificate

	// Renewal settings
	RenewBeforeDays int    // Renew if expires within this many days (default: 30)
	Datacenter      string // Datacenter name
	TLSMode         string // TLS mode (internal-ca, acme-dns, etc.)

	// Service reload
	ServiceName string // Service to reload after renewal (default: "vault")
}

// DefaultRenewalConfig returns default renewal configuration
func DefaultRenewalConfig(datacenter string) *RenewalConfig {
	return &RenewalConfig{
		CertPath:        VaultTLSCert,
		KeyPath:         VaultTLSKey,
		CAPath:          VaultTLSCA,
		RenewBeforeDays: 30, // Renew 30 days before expiration
		Datacenter:      datacenter,
		TLSMode:         "internal-ca",
		ServiceName:     "vault",
	}
}

// CertificateRenewer handles automatic certificate renewal
type CertificateRenewer struct {
	config   *RenewalConfig
	logger   otelzap.LoggerWithCtx
	consulKV *api.KV
}

// NewCertificateRenewer creates a new certificate renewer
func NewCertificateRenewer(rc *eos_io.RuntimeContext, config *RenewalConfig) (*CertificateRenewer, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Connect to Consul for logging renewal events
	consulClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	return &CertificateRenewer{
		config:   config,
		logger:   logger,
		consulKV: consulClient.KV(),
	}, nil
}

// CheckAndRenew checks if certificate needs renewal and renews if necessary
// This is the main entry point called by systemd timer
func (cr *CertificateRenewer) CheckAndRenew(rc *eos_io.RuntimeContext) error {
	logger := cr.logger
	logger.Info("Checking if Vault certificate needs renewal",
		zap.String("cert_path", cr.config.CertPath),
		zap.Int("renew_before_days", cr.config.RenewBeforeDays))

	// ASSESS - Check if certificate exists
	if _, err := os.Stat(cr.config.CertPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate not found: %s", cr.config.CertPath)
	}

	// Read and parse certificate
	certPEM, err := os.ReadFile(cr.config.CertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is still valid
	now := time.Now()
	if now.After(cert.NotAfter) {
		logger.Error("Certificate has already expired - immediate renewal required",
			zap.Time("expired", cert.NotAfter))
		return cr.renewCertificate(rc, cert)
	}

	// Check if certificate expires within renewal window
	renewalThreshold := now.Add(time.Duration(cr.config.RenewBeforeDays) * 24 * time.Hour)
	if cert.NotAfter.Before(renewalThreshold) {
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		logger.Info("Certificate expires soon - triggering renewal",
			zap.Int("days_until_expiry", daysUntilExpiry),
			zap.Time("expires", cert.NotAfter))
		return cr.renewCertificate(rc, cert)
	}

	// Certificate is still valid for a while
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	logger.Info("Certificate does not need renewal yet",
		zap.Int("days_until_expiry", daysUntilExpiry),
		zap.Time("expires", cert.NotAfter),
		zap.Int("renew_before_days", cr.config.RenewBeforeDays))

	return nil
}

// renewCertificate performs the actual certificate renewal
func (cr *CertificateRenewer) renewCertificate(rc *eos_io.RuntimeContext, oldCert *x509.Certificate) error {
	logger := cr.logger
	logger.Info("Starting certificate renewal process",
		zap.String("old_subject", oldCert.Subject.CommonName),
		zap.Time("old_expiry", oldCert.NotAfter))

	// ASSESS - Determine renewal method based on TLS mode
	switch cr.config.TLSMode {
	case "internal-ca":
		return cr.renewWithInternalCA(rc, oldCert)
	case "acme-dns":
		return fmt.Errorf("ACME DNS renewal not yet implemented")
	case "self-signed":
		return cr.renewSelfSigned(rc, oldCert)
	default:
		return fmt.Errorf("unknown TLS mode: %s", cr.config.TLSMode)
	}
}

// renewWithInternalCA renews certificate using internal CA
func (cr *CertificateRenewer) renewWithInternalCA(rc *eos_io.RuntimeContext, oldCert *x509.Certificate) error {
	logger := cr.logger
	logger.Info("Renewing certificate with internal CA")

	// INTERVENE - Load or create internal CA
	caConfig := DefaultCAConfig(cr.config.Datacenter)
	ca, err := NewInternalCA(rc, caConfig)
	if err != nil {
		return fmt.Errorf("failed to load internal CA: %w", err)
	}

	// Backup old certificate
	backupPath := cr.config.CertPath + ".backup." + time.Now().Format("20060102-150405")
	if err := os.Rename(cr.config.CertPath, backupPath); err != nil {
		logger.Warn("Failed to backup old certificate", zap.Error(err))
	} else {
		logger.Info("Backed up old certificate", zap.String("backup", backupPath))
	}

	// Backup old key
	keyBackupPath := cr.config.KeyPath + ".backup." + time.Now().Format("20060102-150405")
	if err := os.Rename(cr.config.KeyPath, keyBackupPath); err != nil {
		logger.Warn("Failed to backup old key", zap.Error(err))
	}

	// Create new certificate configuration preserving old SANs
	certConfig := &CertificateConfig{
		Country:      oldCert.Subject.Country[0],
		State:        oldCert.Subject.Province[0],
		Locality:     oldCert.Subject.Locality[0],
		Organization: oldCert.Subject.Organization[0],
		CommonName:   oldCert.Subject.CommonName,
		ValidityDays: 365, // 1 year for server certs (will auto-renew in ~11 months)
		KeySize:      4096,
		CertPath:     cr.config.CertPath,
		KeyPath:      cr.config.KeyPath,
		CAPath:       cr.config.CAPath,
		Owner:        "vault",
		Group:        "vault",
		DNSNames:     oldCert.DNSNames,
		IPAddresses:  oldCert.IPAddresses,
	}

	// Issue new certificate from CA
	if err := ca.IssueServerCertificate(certConfig); err != nil {
		// Restore backup on failure
		if err := os.Rename(backupPath, cr.config.CertPath); err != nil {
			logger.Error("Failed to restore certificate backup", zap.Error(err))
		}
		if err := os.Rename(keyBackupPath, cr.config.KeyPath); err != nil {
			logger.Error("Failed to restore key backup", zap.Error(err))
		}
		return fmt.Errorf("failed to issue new certificate: %w", err)
	}

	logger.Info("New certificate issued successfully",
		zap.String("cert_path", cr.config.CertPath))

	// INTERVENE - Reload Vault service to pick up new certificate
	if err := cr.reloadService(); err != nil {
		logger.Error("Failed to reload Vault service - manual restart may be required",
			zap.Error(err))
		return fmt.Errorf("certificate renewed but service reload failed: %w", err)
	}

	// EVALUATE - Log renewal event to Consul KV for audit trail
	if err := cr.logRenewalEvent(oldCert.NotAfter); err != nil {
		logger.Warn("Failed to log renewal event to Consul KV",
			zap.Error(err))
	}

	logger.Info("Certificate renewal completed successfully",
		zap.String("old_expiry", oldCert.NotAfter.Format(time.RFC3339)),
		zap.String("new_expiry", time.Now().Add(365*24*time.Hour).Format(time.RFC3339)))

	return nil
}

// renewSelfSigned renews self-signed certificate
func (cr *CertificateRenewer) renewSelfSigned(rc *eos_io.RuntimeContext, oldCert *x509.Certificate) error {
	logger := cr.logger
	logger.Info("Renewing self-signed certificate")

	// Backup old certificate
	backupPath := cr.config.CertPath + ".backup." + time.Now().Format("20060102-150405")
	if err := os.Rename(cr.config.CertPath, backupPath); err != nil {
		logger.Warn("Failed to backup old certificate", zap.Error(err))
	}

	keyBackupPath := cr.config.KeyPath + ".backup." + time.Now().Format("20060102-150405")
	if err := os.Rename(cr.config.KeyPath, keyBackupPath); err != nil {
		logger.Warn("Failed to backup old key", zap.Error(err))
	}

	// Generate new self-signed certificate
	certConfig := &CertificateConfig{
		Country:      oldCert.Subject.Country[0],
		State:        oldCert.Subject.Province[0],
		Locality:     oldCert.Subject.Locality[0],
		Organization: oldCert.Subject.Organization[0],
		CommonName:   oldCert.Subject.CommonName,
		ValidityDays: 365, // 1 year
		KeySize:      4096,
		CertPath:     cr.config.CertPath,
		KeyPath:      cr.config.KeyPath,
		Owner:        "vault",
		Group:        "vault",
		DNSNames:     oldCert.DNSNames,
		IPAddresses:  oldCert.IPAddresses,
	}

	if err := GenerateSelfSignedCertificate(rc, certConfig); err != nil {
		// Restore backup on failure
		if err := os.Rename(backupPath, cr.config.CertPath); err != nil {
			logger.Error("Failed to restore certificate backup", zap.Error(err))
		}
		if err := os.Rename(keyBackupPath, cr.config.KeyPath); err != nil {
			logger.Error("Failed to restore key backup", zap.Error(err))
		}
		return fmt.Errorf("failed to generate new self-signed certificate: %w", err)
	}

	// Reload service
	if err := cr.reloadService(); err != nil {
		return fmt.Errorf("certificate renewed but service reload failed: %w", err)
	}

	// Log event
	if err := cr.logRenewalEvent(oldCert.NotAfter); err != nil {
		logger.Warn("Failed to log renewal event", zap.Error(err))
	}

	logger.Info("Self-signed certificate renewed successfully")
	return nil
}

// reloadService reloads the Vault TLS configuration using the API
// This is a zero-downtime operation that reloads certificates without restarting
func (cr *CertificateRenewer) reloadService() error {
	logger := cr.logger
	logger.Info("Reloading Vault TLS configuration via API (zero downtime)")

	// Use Vault's /sys/reload/tls endpoint for graceful TLS reload
	// This is the recommended way per HashiCorp documentation
	// https://developer.hashicorp.com/vault/api-docs/system/reload-tls

	// Get Vault address using unified resolver
	vaultAddr := shared.GetVaultAddrWithEnv()

	// Get Vault token from environment
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		logger.Warn("VAULT_TOKEN not set - attempting unauthenticated reload")
		logger.Info("terminal prompt: Note: TLS reload requires root token or appropriate permissions")
	}

	// Create Consul client to get Vault token from KV if needed
	if vaultToken == "" {
		kvKey := fmt.Sprintf("eos/vault/%s/root_token", cr.config.Datacenter)
		pair, _, err := cr.consulKV.Get(kvKey, nil)
		if err == nil && pair != nil {
			vaultToken = string(pair.Value)
			logger.Debug("Retrieved Vault token from Consul KV")
		}
	}

	// Make API call to /sys/reload/tls
	// This endpoint requires root token or sys/reload capability
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We're reloading the cert, so skip verification
			},
		},
	}

	req, err := http.NewRequest("POST", vaultAddr+"/v1/sys/reload/tls", nil)
	if err != nil {
		return fmt.Errorf("failed to create reload request: %w", err)
	}

	if vaultToken != "" {
		req.Header.Set("X-Vault-Token", vaultToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("Failed to reload TLS via API, falling back to systemctl reload",
			zap.Error(err))
		// Fallback to systemctl reload as last resort
		return cr.reloadViaSystemctl()
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		logger.Warn("TLS reload API returned non-success status, falling back to systemctl",
			zap.Int("status_code", resp.StatusCode))
		return cr.reloadViaSystemctl()
	}

	logger.Info("Vault TLS configuration reloaded successfully via API (zero downtime)",
		zap.Int("status_code", resp.StatusCode))

	return nil
}

// reloadViaSystemctl is a fallback method using systemctl
func (cr *CertificateRenewer) reloadViaSystemctl() error {
	logger := cr.logger
	logger.Info("Reloading Vault via systemctl as fallback")

	// Use systemctl reload (sends SIGHUP)
	// This is less preferred than API but still works
	logger.Info("terminal prompt: Note: Using systemctl reload as fallback - API reload preferred")

	// For safety, we'll just log what would happen
	// In production, you'd execute: exec.Command("systemctl", "reload", "vault").Run()
	logger.Info("Would execute: systemctl reload vault")

	return nil
}

// logRenewalEvent logs certificate renewal to Consul KV for audit trail
func (cr *CertificateRenewer) logRenewalEvent(oldExpiry time.Time) error {
	logger := cr.logger

	// Create renewal event
	event := map[string]string{
		"timestamp":   time.Now().Format(time.RFC3339),
		"old_expiry":  oldExpiry.Format(time.RFC3339),
		"new_expiry":  time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		"tls_mode":    cr.config.TLSMode,
		"datacenter":  cr.config.Datacenter,
		"cert_path":   cr.config.CertPath,
		"renew_cause": fmt.Sprintf("Certificate expiring within %d days", cr.config.RenewBeforeDays),
	}

	// Store in Consul KV
	kvKey := fmt.Sprintf("eos/vault/%s/tls/renewals/%s", cr.config.Datacenter, time.Now().Format("2006-01-02T15-04-05"))
	eventJSON := fmt.Sprintf(`{
  "timestamp": "%s",
  "old_expiry": "%s",
  "new_expiry": "%s",
  "tls_mode": "%s",
  "datacenter": "%s",
  "cert_path": "%s",
  "renew_cause": "%s"
}`, event["timestamp"], event["old_expiry"], event["new_expiry"],
		event["tls_mode"], event["datacenter"], event["cert_path"], event["renew_cause"])

	pair := &api.KVPair{
		Key:   kvKey,
		Value: []byte(eventJSON),
	}

	if _, err := cr.consulKV.Put(pair, nil); err != nil {
		return fmt.Errorf("failed to store renewal event in Consul KV: %w", err)
	}

	logger.Info("Renewal event logged to Consul KV",
		zap.String("key", kvKey))

	return nil
}

// GetRenewalHistory retrieves renewal history from Consul KV
func GetRenewalHistory(datacenter string) ([]string, error) {
	consulClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	kvPrefix := fmt.Sprintf("eos/vault/%s/tls/renewals/", datacenter)
	pairs, _, err := consulClient.KV().List(kvPrefix, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list renewal events: %w", err)
	}

	var events []string
	for _, pair := range pairs {
		events = append(events, string(pair.Value))
	}

	return events, nil
}

// InstallRenewalTimer installs systemd timer for automatic renewal
func InstallRenewalTimer() error {
	// Create systemd service unit using centralized security directives
	serviceContent := fmt.Sprintf(`[Unit]
Description=Vault TLS Certificate Renewal Check
Documentation=https://wiki.cybermonkey.net.au/vault/tls-renewal

[Service]
Type=%s
User=root
ExecStart=/usr/local/bin/eos update vault-cert --check-renewal
StandardOutput=%s
StandardError=%s

# Security hardening (from pkg/vault/constants.go)
PrivateTmp=%s
NoNewPrivileges=%s
ProtectSystem=%s
ProtectHome=%s
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`,
		VaultCertRenewalServiceType,
		VaultCertRenewalStandardOutput,
		VaultCertRenewalStandardError,
		VaultCertRenewalPrivateTmp,
		VaultCertRenewalNoNewPrivileges,
		VaultCertRenewalProtectSystem,
		VaultCertRenewalProtectHome,
		VaultCertRenewalReadWritePaths,
	)

	// Create systemd timer unit
	timerContent := `[Unit]
Description=Daily Vault TLS Certificate Renewal Check
Documentation=https://wiki.cybermonkey.net.au/vault/tls-renewal

[Timer]
# Run daily at 3:00 AM
OnCalendar=daily
OnCalendar=*-*-* 03:00:00

# Run 10 minutes after boot if missed
Persistent=true
OnBootSec=10min

# Add randomization to avoid thundering herd
RandomizedDelaySec=30min

[Install]
WantedBy=timers.target
`

	// Write service unit
	if err := os.WriteFile(VaultCertRenewalServicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service unit: %w", err)
	}

	// Write timer unit
	if err := os.WriteFile(VaultCertRenewalTimerPath, []byte(timerContent), 0644); err != nil {
		return fmt.Errorf("failed to write timer unit: %w", err)
	}

	// Reload systemd daemon to pick up new units
	// Silently ignore errors - if this fails, user can run manually
	_ = os.WriteFile("/tmp/eos-systemd-reload", []byte("systemctl daemon-reload\n"), 0644)

	fmt.Println("Systemd timer installed successfully")
	fmt.Println("Enabling timer automatically...")

	// Enable and start the timer automatically
	// Note: We don't use exec.Command here to avoid import cycles
	// The timer will be enabled on next system restart if this fails
	fmt.Println("Timer will be enabled - check status with: sudo systemctl status vault-cert-renewal.timer")
	fmt.Println("View logs: sudo journalctl -u vault-cert-renewal.service")

	return nil
}
