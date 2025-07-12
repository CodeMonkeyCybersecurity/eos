// cmd/create/hecate-dns.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hetzner"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	hetznerDNSDomain string
	hetznerDNSIP     string
)

// hetznerWildcardCmd creates a DNS A record on Hetzner (wildcard by default)
var hetznerWildcardCmd = &cobra.Command{
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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Basic validation
		if hetznerDNSDomain == "" || hetznerDNSIP == "" {
			err := fmt.Errorf("domain and ip are required")
			otelzap.Ctx(rc.Ctx).Error("Missing required flags", zap.String("domain", hetznerDNSDomain), zap.String("ip", hetznerDNSIP), zap.Error(err))
			return err
		}

		// Get token
		hetznerToken := os.Getenv("HETZNER_DNS_API_TOKEN")
		if hetznerToken == "" {
			err := fmt.Errorf("missing Hetzner DNS API token (env HETZNER_DNS_API_TOKEN)")
			otelzap.Ctx(rc.Ctx).Error("No Hetzner API token found in environment", zap.Error(err))
			return err
		}

		// 1) Fetch the zone ID
		zoneID, err := hetzner.GetZoneIDForDomain(rc, hetznerToken, hetznerDNSDomain)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to get zone for domain",
				zap.String("domain", hetznerDNSDomain),
				zap.Error(err),
			)
			return fmt.Errorf("failed to get zone for domain %q: %v", hetznerDNSDomain, err)
		}

		otelzap.Ctx(rc.Ctx).Info("Using zone for domain",
			zap.String("zoneID", zoneID),
			zap.String("domain", hetznerDNSDomain),
		)
		otelzap.Ctx(rc.Ctx).Info("Attempting to create wildcard record",
			zap.String("wildcard", "*."+hetznerDNSDomain),
			zap.String("ip", hetznerDNSIP),
		)

		// 2) Attempt to create a wildcard record
		err = hetzner.CreateRecord(rc, hetznerToken, zoneID, "*", hetznerDNSIP)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Wildcard record creation failed",
				zap.Error(err),
				zap.String("wildcard", "*."+hetznerDNSDomain),
			)

			// Fallback to a normal subdomain
			subdomain := "wildcard-fallback"
			otelzap.Ctx(rc.Ctx).Info("Falling back to normal subdomain record",
				zap.String("subdomain", subdomain),
				zap.String("domain", hetznerDNSDomain),
				zap.String("ip", hetznerDNSIP),
			)

			fallbackErr := hetzner.CreateRecord(rc, hetznerToken, zoneID, subdomain, hetznerDNSIP)
			if fallbackErr != nil {
				otelzap.Ctx(rc.Ctx).Error("Subdomain creation failed after wildcard failure",
					zap.String("subdomain", subdomain),
					zap.String("domain", hetznerDNSDomain),
					zap.String("ip", hetznerDNSIP),
					zap.Error(fallbackErr),
				)
				return fmt.Errorf("subdomain creation failed after wildcard failure: %v", fallbackErr)
			}

			otelzap.Ctx(rc.Ctx).Info("Successfully created subdomain record",
				zap.String("record", subdomain+"."+hetznerDNSDomain),
				zap.String("ip", hetznerDNSIP),
			)
			return nil
		}

		// If we succeed with wildcard
		otelzap.Ctx(rc.Ctx).Info("Successfully created wildcard record",
			zap.String("wildcard", "*."+hetznerDNSDomain),
			zap.String("ip", hetznerDNSIP),
		)
		return nil
	}),
}

func init() {
	hetznerWildcardCmd.Flags().StringVar(&hetznerDNSDomain, "domain", "", "Root domain name (e.g. example.com)")
	hetznerWildcardCmd.Flags().StringVar(&hetznerDNSIP, "ip", "", "IP address for the A record")
}
