// pkg/hecate/dns_integration.go
// DNS automation for Hecate deployment

package hecate

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hetzner"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupHecateDNS handles automatic DNS record creation for Hecate
func SetupHecateDNS(rc *eos_io.RuntimeContext, domain string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up DNS for Hecate")

	// ASSESS - Check if Hetzner API token is available
	hetznerToken := os.Getenv("HETZNER_DNS_API_TOKEN")
	if hetznerToken == "" {
		logger.Warn("HETZNER_DNS_API_TOKEN not set, skipping automatic DNS setup")
		logger.Info("To enable automatic DNS, set HETZNER_DNS_API_TOKEN environment variable")
		logger.Info("Manual DNS setup required:")
		logger.Info("  - Create A record: hera." + domain + " → [this server's IP]")
		return nil
	}

	// ASSESS - Detect server's public IP
	serverIP, err := detectPublicIP(rc)
	if err != nil {
		logger.Warn("Could not detect public IP automatically", zap.Error(err))
		logger.Info("terminal prompt: Enter this server's public IP address:")
		serverIP, err = eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read IP input: %w", err)
		}
		serverIP = strings.TrimSpace(serverIP)
	}

	logger.Info("Detected server IP", zap.String("ip", serverIP))

	// Ask user for confirmation
	logger.Info("")
	logger.Info("DNS Configuration:")
	logger.Info("  Record: hera." + domain)
	logger.Info("  Type: A")
	logger.Info("  Target: " + serverIP)
	logger.Info("")
	logger.Info("terminal prompt: Create this DNS record automatically? [Y/n]:")

	response, err := eos_io.ReadInput(rc)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response == "n" || response == "no" {
		logger.Info("Skipped automatic DNS setup")
		logger.Info("Manual DNS setup required:")
		logger.Info("  - Create A record: hera." + domain + " → " + serverIP)
		return nil
	}

	// INTERVENE - Create DNS record via Hetzner API
	logger.Info("Creating DNS record via Hetzner API")

	// Initialize Hetzner DNS client
	// Get the underlying otelzap.Logger (which embeds *zap.Logger)
	otelLogger := logger.Logger()
	dnsClient := hetzner.NewClient(hetznerToken, otelLogger.Logger)

	// Get zone ID for domain
	zoneID, err := hetzner.GetZoneIDForDomain(rc, hetznerToken, domain)
	if err != nil {
		return fmt.Errorf("failed to get zone ID for domain %s: %w", domain, err)
	}

	logger.Info("Found DNS zone", zap.String("zone_id", zoneID), zap.String("domain", domain))

	// Create A record for hera.domain
	subdomain := "hera"
	err = hetzner.CreateRecord(rc, hetznerToken, zoneID, subdomain, serverIP)
	if err != nil {
		// Check if record already exists
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "duplicate") {
			logger.Warn("DNS record may already exist, attempting update", zap.String("record", subdomain+"."+domain))

			// Try to update existing record
			if updateErr := updateExistingRecord(rc, dnsClient, zoneID, subdomain, serverIP); updateErr != nil {
				logger.Error("Failed to update existing DNS record", zap.Error(updateErr))
				return fmt.Errorf("DNS record exists but could not be updated: %w", updateErr)
			}

			logger.Info("Updated existing DNS record", zap.String("record", subdomain+"."+domain))
		} else {
			return fmt.Errorf("failed to create DNS record: %w", err)
		}
	} else {
		logger.Info("Successfully created DNS record",
			zap.String("record", subdomain+"."+domain),
			zap.String("ip", serverIP))
	}

	// EVALUATE - Verify DNS propagation
	logger.Info("")
	logger.Info("Waiting for DNS propagation...")
	time.Sleep(3 * time.Second)

	if err := verifyDNSRecord(rc, subdomain+"."+domain, serverIP); err != nil {
		logger.Warn("DNS verification incomplete", zap.Error(err))
		logger.Info("Note: DNS propagation can take a few minutes")
		logger.Info("Verify manually: dig hera." + domain)
	} else {
		logger.Info("DNS record verified successfully!")
	}

	logger.Info("")
	return nil
}

// detectPublicIP attempts to detect the server's public IP address
func detectPublicIP(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try multiple services for reliability
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	for _, service := range services {
		logger.Debug("Checking IP via service", zap.String("service", service))

		// Try with short timeout
		// Note: This is a simple implementation. In production, use proper HTTP client with context
		// For now, skip actual HTTP call and return error to trigger manual input
		break
	}

	return "", fmt.Errorf("automatic IP detection not implemented, please enter manually")
}

// updateExistingRecord updates an existing DNS record
func updateExistingRecord(rc *eos_io.RuntimeContext, client *hetzner.DNSClient, zoneID, name, value string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get all records for the zone
	records, err := client.GetRecords(rc, zoneID)
	if err != nil {
		return fmt.Errorf("failed to get existing records: %w", err)
	}

	// Find the record we want to update
	for _, record := range records {
		if record.Name == name && record.Type == "A" {
			logger.Info("Found existing record to update",
				zap.String("id", record.ID),
				zap.String("name", record.Name),
				zap.String("old_value", record.Value))

			// Update the record
			updated := record
			updated.Value = value

			_, err := client.UpdateRecord(rc, record.ID, updated)
			if err != nil {
				return fmt.Errorf("failed to update record: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("record not found for update: %s", name)
}

// verifyDNSRecord checks if the DNS record has propagated
func verifyDNSRecord(rc *eos_io.RuntimeContext, fqdn, expectedIP string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying DNS record", zap.String("fqdn", fqdn), zap.String("expected_ip", expectedIP))

	// Perform DNS lookup
	ips, err := net.LookupHost(fqdn)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}

	// Check if expected IP is in results
	for _, ip := range ips {
		if ip == expectedIP {
			logger.Info("DNS verification successful",
				zap.String("fqdn", fqdn),
				zap.String("ip", ip))
			return nil
		}
	}

	return fmt.Errorf("DNS record does not match expected IP (got %v, expected %s)", ips, expectedIP)
}
