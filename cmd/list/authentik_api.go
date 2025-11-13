// cmd/list/authentik_api.go
// List Authentik resources using declarative API client framework
//
// ARCHITECTURE: Thin orchestration layer - delegates to pkg/apiclient/executor.go
// HUMAN-CENTRIC: Plain language CLI → REST API translation
// COMPLIANCE: Follows CLAUDE.md P0 rules (structured logging, RuntimeContext, error handling)
// NOTE: Complements existing authentik.go (flows/bindings) - this handles users/groups/applications

package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/apiclient"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var authentikAPICmd = &cobra.Command{
	Use:   "authentik-api [resource]",
	Short: "List Authentik API resources (users, groups, applications)",
	Long: `List Authentik API resources using the declarative API client framework.

Available resources:
  users         - List Authentik users
  groups        - List Authentik groups
  applications  - List Authentik applications
  providers     - List Authentik proxy providers
  brands        - List Authentik brands

Examples:
  # List all users
  eos list authentik-api users

  # List external users only
  eos list authentik-api users --type=external

  # List active superusers
  eos list authentik-api users --superuser --active

  # List groups containing specific user
  eos list authentik-api groups --member=123e4567-e89b-12d3-a456-426614174000

  # List applications
  eos list authentik-api applications

  # Output as JSON
  eos list authentik-api users --format=json

  # Output as CSV (for spreadsheets)
  eos list authentik-api users --format=csv

NOTE: For flow and stage binding inspection, use 'eos list authentik flows' instead.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Require resource argument
		if len(args) < 1 {
			return fmt.Errorf("resource type required\n\n" +
				"Available resources:\n" +
				"  users        - Authentik users\n" +
				"  groups       - Authentik groups\n" +
				"  applications - Authentik applications\n" +
				"  providers    - Authentik proxy providers\n" +
				"  brands       - Authentik brands\n\n" +
				"Examples:\n" +
				"  eos list authentik-api users\n" +
				"  eos list authentik-api groups\n" +
				"  eos list authentik-api applications")
		}

		resource := args[0]

		logger.Info("Listing Authentik API resources",
			zap.String("resource", resource))

		// Create executor (loads API definition, discovers auth)
		executor, err := apiclient.NewExecutor(rc, "authentik")
		if err != nil {
			return fmt.Errorf("failed to initialize Authentik API client: %w\n\n"+
				"Troubleshooting:\n"+
				"  1. Ensure Authentik is configured in /opt/hecate/.env\n"+
				"  2. Check AUTHENTIK_TOKEN and AUTHENTIK_URL are set\n"+
				"  3. Verify Authentik is running: curl https://localhost/api/v3/\n"+
				"  4. Run: eos debug hecate", err)
		}

		// Extract filters from flags based on resource type
		filters := make(map[string]interface{})

		switch resource {
		case "users":
			// Users filters
			if cmd.Flags().Changed("superuser") {
				superuser, _ := cmd.Flags().GetBool("superuser")
				filters["is_superuser"] = superuser
			}
			if cmd.Flags().Changed("active") {
				active, _ := cmd.Flags().GetBool("active")
				filters["is_active"] = active
			}
			if cmd.Flags().Changed("type") {
				userType, _ := cmd.Flags().GetString("type")
				filters["type"] = userType
			}
			if cmd.Flags().Changed("email") {
				email, _ := cmd.Flags().GetString("email")
				filters["email"] = email
			}
			if cmd.Flags().Changed("username") {
				username, _ := cmd.Flags().GetString("username")
				filters["username"] = username
			}

		case "groups":
			// Groups filters
			if cmd.Flags().Changed("member") {
				member, _ := cmd.Flags().GetString("member")
				filters["members_by_pk"] = member
			}
			if cmd.Flags().Changed("name") {
				name, _ := cmd.Flags().GetString("name")
				filters["name"] = name
			}

		case "applications":
			// Applications filters
			if cmd.Flags().Changed("name") {
				name, _ := cmd.Flags().GetString("name")
				filters["name"] = name
			}
			if cmd.Flags().Changed("slug") {
				slug, _ := cmd.Flags().GetString("slug")
				filters["slug"] = slug
			}

		case "providers":
			// Providers filters
			if cmd.Flags().Changed("name") {
				name, _ := cmd.Flags().GetString("name")
				filters["name"] = name
			}

		case "brands":
			// Brands filters
			if cmd.Flags().Changed("domain") {
				domain, _ := cmd.Flags().GetString("domain")
				filters["domain"] = domain
			}
		}

		logger.Debug("Extracted filters from flags",
			zap.String("resource", resource),
			zap.Any("filters", filters))

		// Execute list operation
		result, err := executor.List(rc.Ctx, resource, filters)
		if err != nil {
			return fmt.Errorf("failed to list %s: %w\n\n"+
				"Troubleshooting:\n"+
				"  1. Check if resource name is correct (users, groups, applications, etc.)\n"+
				"  2. Verify Authentik API token has read permissions\n"+
				"  3. Check Authentik API logs for errors\n"+
				"  4. Run: eos debug hecate",
				resource, err)
		}

		logger.Info("Retrieved resources",
			zap.String("resource", resource),
			zap.Int("count", len(result.Items)),
			zap.Int("total", result.TotalCount))

		// Format and display output
		format, _ := cmd.Flags().GetString("format")
		if err := apiclient.FormatOutput(result, format); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		return nil
	}),
}

func init() {
	// ─────────────────────────────────────────────────────────────────────────
	// Standard flags (all resources)
	// ─────────────────────────────────────────────────────────────────────────
	authentikAPICmd.Flags().String("format", "table", "Output format (table, json, yaml, csv)")

	// ─────────────────────────────────────────────────────────────────────────
	// Users filters
	// ─────────────────────────────────────────────────────────────────────────
	authentikAPICmd.Flags().Bool("superuser", false, "Filter by superuser status")
	authentikAPICmd.Flags().Bool("active", false, "Filter by active status")
	authentikAPICmd.Flags().String("type", "", "Filter by user type (internal, external, service_account)")
	authentikAPICmd.Flags().String("email", "", "Filter by email address")
	authentikAPICmd.Flags().String("username", "", "Filter by username")

	// ─────────────────────────────────────────────────────────────────────────
	// Groups filters
	// ─────────────────────────────────────────────────────────────────────────
	authentikAPICmd.Flags().String("member", "", "Filter groups by member UUID")

	// ─────────────────────────────────────────────────────────────────────────
	// Common filters (name, slug, domain)
	// ─────────────────────────────────────────────────────────────────────────
	authentikAPICmd.Flags().String("name", "", "Filter by name")
	authentikAPICmd.Flags().String("slug", "", "Filter by slug")
	authentikAPICmd.Flags().String("domain", "", "Filter by domain (brands only)")

	// Register command
	ListCmd.AddCommand(authentikAPICmd)
}
