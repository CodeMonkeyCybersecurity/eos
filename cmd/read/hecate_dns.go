package read

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var readHecateDNSCmd = &cobra.Command{
	Use:   "dns",
	Short: "Read Hecate DNS records and status",
	Long: `Read DNS records managed by Hecate and show DNS reconciliation status.

This command shows all DNS records managed by Hecate via Terraform,
including reconciliation metrics and DNS health status.

Examples:
  eos read hecate dns                    # List all DNS records
  eos read hecate dns --domain app.com   # Show specific domain
  eos read hecate dns --metrics          # Show DNS metrics
  eos read hecate dns --reconcile        # Trigger reconciliation`,
	RunE: eos_cli.Wrap(runReadHecateDNS),
}

func init() {
	readHecateCmd.AddCommand(readHecateDNSCmd)

	readHecateDNSCmd.Flags().String("domain", "", "Show specific domain")
	readHecateDNSCmd.Flags().Bool("metrics", false, "Show DNS management metrics")
	readHecateDNSCmd.Flags().Bool("reconcile", false, "Trigger DNS reconciliation")
	readHecateDNSCmd.Flags().String("format", "table", "Output format: table, json")
}

func runReadHecateDNS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Reading Hecate DNS records")

	// Get flags
	domain, _ := cmd.Flags().GetString("domain")
	showMetrics, _ := cmd.Flags().GetBool("metrics")
	triggerReconcile, _ := cmd.Flags().GetBool("reconcile")
	format, _ := cmd.Flags().GetString("format")

	// Initialize Hecate client
	config := &hecate.ClientConfig{
		CaddyAdminAddr:     getEnvOrDefault("CADDY_ADMIN_ADDR", "http://localhost:2019"),
		ConsulAddr:         getEnvOrDefault("CONSUL_ADDR", "localhost:8500"),
		VaultAddr:          getEnvOrDefault("VAULT_ADDR", fmt.Sprintf("http://localhost:%d", shared.PortVault)),
		VaultToken:         getEnvOrDefault("VAULT_TOKEN", ""),
		TerraformWorkspace: getEnvOrDefault("TERRAFORM_WORKSPACE", "/var/lib/hecate/terraform"),
	}

	client, err := hecate.NewHecateClient(rc, config)
	if err != nil {
		return err
	}

	dm := hecate.NewDNSManager(client)

	// Handle reconciliation trigger
	if triggerReconcile {
		logger.Info("Triggering DNS reconciliation")
		result, err := dm.ReconcileDNS(rc.Ctx)
		if err != nil {
			return fmt.Errorf("DNS reconciliation failed: %w", err)
		}

		fmt.Printf(" DNS Reconciliation Results:\n")
		fmt.Printf("  Created: %d domains\n", len(result.Created))
		fmt.Printf("  Updated: %d domains\n", len(result.Updated))
		fmt.Printf("  Deleted: %d domains\n", len(result.Deleted))
		fmt.Printf("  Errors:  %d\n", len(result.Errors))
		fmt.Printf("  Duration: %s\n\n", result.Duration)

		if len(result.Created) > 0 {
			fmt.Printf(" Created domains: %v\n", result.Created)
		}
		if len(result.Updated) > 0 {
			fmt.Printf(" Updated domains: %v\n", result.Updated)
		}
		if len(result.Deleted) > 0 {
			fmt.Printf("  Deleted domains: %v\n", result.Deleted)
		}
		if len(result.Errors) > 0 {
			fmt.Printf(" Errors:\n")
			for _, errMsg := range result.Errors {
				fmt.Printf("  - %s\n", errMsg)
			}
		}
		fmt.Println()
	}

	// Handle metrics display
	if showMetrics {
		logger.Info("Getting DNS metrics")
		metrics, err := dm.GetDNSMetrics(rc.Ctx)
		if err != nil {
			return fmt.Errorf("failed to get DNS metrics: %w", err)
		}

		fmt.Printf("📊 DNS Management Metrics:\n")
		fmt.Printf("  Total Routes:      %d\n", metrics.TotalRoutes)
		fmt.Printf("  Managed Domains:   %d\n", metrics.ManagedDomains)
		fmt.Printf("  Orphaned Records:  %d\n", metrics.OrphanedRecords)
		fmt.Printf("  Last Reconcile:    %s\n\n", metrics.LastReconcile.Format(time.RFC3339))

		if metrics.OrphanedRecords > 0 {
			fmt.Printf("Found %d orphaned DNS records. Run with --reconcile to clean them up.\n\n", metrics.OrphanedRecords)
		}
	}

	// List DNS records
	logger.Info("Listing DNS records")
	records, err := dm.ListDNSRecords(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %w", err)
	}

	if domain != "" {
		// Show specific domain
		if record, exists := records[domain]; exists {
			fmt.Printf(" DNS Record: %s\n", domain)
			fmt.Printf("  Type:  %s\n", record.Type)
			fmt.Printf("  Value: %s\n", record.Value)
			fmt.Printf("  TTL:   %d\n", record.TTL)
		} else {
			fmt.Printf(" Domain not found: %s\n", domain)
		}
		return nil
	}

	// Show all records
	if len(records) == 0 {
		fmt.Printf("📭 No DNS records found\n")
		fmt.Printf("Create records with: eos create hecate dns --domain example.com --target 1.2.3.4\n")
		return nil
	}

	fmt.Printf(" Hecate DNS Records (%d total):\n\n", len(records))

	if format == "json" {
		// JSON output
		for domain, record := range records {
			fmt.Printf(`{"domain": "%s", "type": "%s", "value": "%s", "ttl": %d}`+"\n",
				domain, record.Type, record.Value, record.TTL)
		}
	} else {
		// Table output
		fmt.Printf("%-30s %-6s %-15s %-6s\n", "DOMAIN", "TYPE", "VALUE", "TTL")
		fmt.Printf("%-30s %-6s %-15s %-6s\n", "------", "----", "-----", "---")
		for domain, record := range records {
			fmt.Printf("%-30s %-6s %-15s %-6d\n",
				domain, record.Type, record.Value, record.TTL)
		}
	}

	return nil
}

func getEnvOrDefault(envVar, defaultValue string) string {
	// Implementation would be the same as in other files
	return defaultValue
}
