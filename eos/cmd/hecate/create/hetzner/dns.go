// cmd/create/hetzner/dns.go

package hetzner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"eos/pkg/logger"
)

var log = logger.L()

const hetznerAPIBase = "https://dns.hetzner.com/api/v1"

// CreateRecordRequest is the request body for creating or updating a DNS record.
type CreateRecordRequest struct {
	ZoneID string `json:"zone_id"`
	Type   string `json:"type"` // e.g. "A", "CNAME"
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}

// RecordResponse holds data for the record creation response.
type RecordResponse struct {
	Record struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"record"`
}

// ZonesResponse is used to decode the JSON containing a list of zones.
type ZonesResponse struct {
	Zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"zones"`
}

// NewCreateHetznerWildcardCmd creates a Cobra command for setting a wildcard A record (with fallback) on Hetzner.
func NewCreateHetznerWildcardCmd() *cobra.Command {
	var (
		domain string
		ip     string
	)

	cmd := &cobra.Command{
		Use:   "hetzner-dns",
		Short: "Create a DNS A record on Hetzner (wildcard by default)",
		Long: `Create a DNS A record on Hetzner for the given domain and IP address.
By default, this attempts to create a wildcard record (*.example.com). If the provider
doesn't allow it or returns an error, it falls back to creating 'wildcard-fallback.example.com'.
    
Examples:
  hecate create hetzner-dns --domain example.com --ip 1.2.3.4

Note: You must set the environment variable HETZNER_DNS_API_TOKEN for authentication.
	To do this, login to your Hetzner account at 'https://dns.hetzner.com//'
 	-> Manage API tokens,
  	-> Enter name, eg. 'hecate-token',
  	-> Follow the prompts to then select 'Create access token'.
   	-> Copy the token value and store it securely.

To use it here, run:
 
 	export HETZNER_DNS_API_TOKEN="YOUR-HETZNER-TOKEN-HERE"

Replace YOUR-HETZNER-TOKEN-HERE with the actual token you copied from Hetzner.

To confirm that your variable is set correctly, run:

    	echo $HETZNER_DNS_API_TOKEN
   
Then, run this command again.
     `,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Basic validation
			if domain == "" || ip == "" {
				err := fmt.Errorf("domain and ip are required")
				log.Error("Missing required flags", zap.String("domain", domain), zap.String("ip", ip), zap.Error(err))
				return err
			}

			// Get token
			hetznerToken := os.Getenv("HETZNER_DNS_API_TOKEN")
			if hetznerToken == "" {
				err := fmt.Errorf("missing Hetzner DNS API token (env HETZNER_DNS_API_TOKEN)")
				log.Error("No Hetzner API token found in environment", zap.Error(err))
				return err
			}

			// 1) Fetch the zone ID
			zoneID, err := getZoneIDForDomain(hetznerToken, domain)
			if err != nil {
				log.Error("Failed to get zone for domain",
					zap.String("domain", domain),
					zap.Error(err),
				)
				return fmt.Errorf("failed to get zone for domain %q: %v", domain, err)
			}

			log.Info("Using zone for domain",
				zap.String("zoneID", zoneID),
				zap.String("domain", domain),
			)
			log.Info("Attempting to create wildcard record",
				zap.String("wildcard", "*."+domain),
				zap.String("ip", ip),
			)

			// 2) Attempt to create a wildcard record
			err = createRecord(hetznerToken, zoneID, "*", ip)
			if err != nil {
				log.Warn("Wildcard record creation failed",
					zap.Error(err),
					zap.String("wildcard", "*."+domain),
				)

				// Fallback to a normal subdomain
				subdomain := "wildcard-fallback"
				log.Info("Falling back to normal subdomain record",
					zap.String("subdomain", subdomain),
					zap.String("domain", domain),
					zap.String("ip", ip),
				)

				fallbackErr := createRecord(hetznerToken, zoneID, subdomain, ip)
				if fallbackErr != nil {
					log.Error("Subdomain creation failed after wildcard failure",
						zap.String("subdomain", subdomain),
						zap.String("domain", domain),
						zap.String("ip", ip),
						zap.Error(fallbackErr),
					)
					return fmt.Errorf("subdomain creation failed after wildcard failure: %v", fallbackErr)
				}

				log.Info("Successfully created subdomain record",
					zap.String("record", subdomain+"."+domain),
					zap.String("ip", ip),
				)
				return nil
			}

			// If we succeed with wildcard
			log.Info("Successfully created wildcard record",
				zap.String("wildcard", "*."+domain),
				zap.String("ip", ip),
			)
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "Root domain name (e.g. example.com)")
	cmd.Flags().StringVar(&ip, "ip", "", "IP address for the A record")

	return cmd
}

// getZoneIDForDomain fetches all zones from Hetzner and attempts to match the given domain.
func getZoneIDForDomain(token, domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")

	req, err := http.NewRequest("GET", hetznerAPIBase+"/zones", nil)
	if err != nil {
		log.Error("Failed to create request for fetching zones", zap.Error(err))
		return "", err
	}
	req.Header.Set("Auth-API-Token", token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Failed to execute HTTP request for fetching zones", zap.Error(err))
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error("Unexpected status from zones list",
			zap.Int("statusCode", resp.StatusCode),
		)
		return "", fmt.Errorf("unexpected status from zones list: %s", resp.Status)
	}

	var zr ZonesResponse
	if err := json.NewDecoder(resp.Body).Decode(&zr); err != nil {
		log.Error("Failed to decode JSON for zones response", zap.Error(err))
		return "", err
	}

	for _, z := range zr.Zones {
		zoneName := strings.TrimSuffix(z.Name, ".")
		if zoneName == domain || strings.HasSuffix(domain, zoneName) {
			return z.ID, nil
		}
	}

	err = fmt.Errorf("zone not found for domain %q", domain)
	log.Error("Zone not found for domain", zap.String("domain", domain), zap.Error(err))
	return "", err
}

// createRecord tries to create an A record in Hetzner DNS.
func createRecord(token, zoneID, name, ip string) error {
	reqBody := CreateRecordRequest{
		ZoneID: zoneID,
		Type:   "A",
		Name:   name, // "*" for wildcard or fallback subdomain
		Value:  ip,
		TTL:    300, // Adjust as desired
	}

	bodyBytes, err := json.Marshal(&reqBody)
	if err != nil {
		log.Error("Failed to marshal CreateRecordRequest", zap.Error(err))
		return err
	}

	req, err := http.NewRequest("POST", hetznerAPIBase+"/records", bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Error("Failed to create request for creating record", zap.Error(err))
		return err
	}
	req.Header.Set("Auth-API-Token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Failed to execute HTTP request for creating record", zap.Error(err))
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var responseBody bytes.Buffer
		_, _ = responseBody.ReadFrom(resp.Body)
		errMsg := fmt.Sprintf("record creation failed (%d): %s",
			resp.StatusCode,
			responseBody.String(),
		)
		log.Error("createRecord: unexpected status", zap.String("error", errMsg))
		return fmt.Errorf(errMsg)
	}

	var recordResp RecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&recordResp); err != nil {
		log.Error("Failed to decode record creation response", zap.Error(err))
		return err
	}

	log.Debug("Record creation response decoded successfully",
		zap.String("recordID", recordResp.Record.ID),
		zap.String("recordName", recordResp.Record.Name),
		zap.String("recordType", recordResp.Record.Type),
	)
	return nil
}
