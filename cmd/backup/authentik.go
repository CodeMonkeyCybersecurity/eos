// cmd/backup/authentik.go
package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// AuthentikCmd represents the 'eos backup authentik' command
var AuthentikCmd = &cobra.Command{
	Use:   "authentik [flags]",
	Short: "Backup Authentik configuration and data",
	Long: `Create a comprehensive backup of Authentik configuration including:
- SAML/OAuth2/LDAP providers and applications
- Property mappings (critical for Wazuh SSO)
- Authentication flows and stages
- Groups, users, and policies
- Certificates and keys (optional)
- Custom branding and templates

The backup extracts configuration via the Authentik API, not filesystem backup.
This is ideal for migrating configurations between Authentik instances.

Examples:
  # Full configuration backup
  eos backup authentik --url https://auth.example.com --token $TOKEN

  # Backup specific applications (e.g., Wazuh SSO)
  eos backup authentik --apps delphi-saml,wazuh-sso

  # Backup with secrets included
  eos backup authentik --include-secrets --output auth-backup.yaml`,
	RunE: eos.Wrap(backupAuthentik),
}

func init() {
	authentikFlags := AuthentikCmd.Flags()

	// API connection flags
	authentikFlags.String("url", os.Getenv("AUTHENTIK_URL"),
		"Authentik URL (or set AUTHENTIK_URL env var)")
	authentikFlags.String("token", os.Getenv("AUTHENTIK_TOKEN"),
		"API Token (or set AUTHENTIK_TOKEN env var)")

	// Output configuration
	authentikFlags.StringP("output", "o", "",
		"Output file path (default: authentik-backup-TIMESTAMP.yaml)")
	authentikFlags.String("format", "yaml", "Output format: yaml or json")

	// Selective backup options
	authentikFlags.StringSlice("types", nil,
		"Resource types to backup (providers,applications,mappings,flows,stages,groups,policies,certificates,blueprints,outposts,tenants)")
	authentikFlags.StringSlice("apps", nil, "Backup only specific applications by name")
	authentikFlags.StringSlice("providers", nil, "Backup only specific providers by name")

	// Security options
	authentikFlags.Bool("include-secrets", false,
		"Include sensitive data like private keys and secrets")
	authentikFlags.Bool("extract-wazuh", false,
		"Extract only Wazuh/Delphi SSO specific configuration")

	// Legacy filesystem backup flags (kept for compatibility)
	authentikFlags.Bool("include-media", false, "Include media files (filesystem backup only)")
	authentikFlags.Bool("include-database", false, "Include database dump (filesystem backup only)")
	authentikFlags.StringP("path", "p", "/opt/authentik", "Path to Authentik installation (filesystem backup only)")

	// Register command
	BackupCmd.AddCommand(AuthentikCmd)
}

func backupAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get flags
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	types, _ := cmd.Flags().GetStringSlice("types")
	apps, _ := cmd.Flags().GetStringSlice("apps")
	providers, _ := cmd.Flags().GetStringSlice("providers")
	includeSecrets, _ := cmd.Flags().GetBool("include-secrets")
	extractWazuh, _ := cmd.Flags().GetBool("extract-wazuh")

	// Check if this is a filesystem backup request (legacy)
	includeMedia, _ := cmd.Flags().GetBool("include-media")
	includeDatabase, _ := cmd.Flags().GetBool("include-database")
	if includeMedia || includeDatabase {
		return backupAuthentikFilesystem(rc, cmd)
	}

	// ASSESS - Validate API parameters
	logger.Info("Starting Authentik configuration backup")

	if url == "" {
		input, err := eos_io.PromptInput(rc, "Enter Authentik URL (e.g., https://auth.example.com): ", "authentik_url")
		if err != nil {
			return err
		}
		url = input
	}

	// Auto-add https:// if no protocol specified
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
		logger.Info("Added https:// prefix to URL", zap.String("url", url))
	}

	if token == "" {
		input, err := eos_io.PromptSecurePassword(rc, "Enter Authentik API token: ")
		if err != nil {
			return err
		}
		token = input
	}

	if url == "" || token == "" {
		return eos_err.NewUserError("Authentik URL and token are required")
	}

	// Determine output file - default to /mnt for centralized backup storage
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		backupDir := "/mnt/eos-backups/authentik"

		// Create backup directory if it doesn't exist
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			logger.Warn("Failed to create /mnt backup directory, using current directory",
				zap.Error(err))
			output = fmt.Sprintf("authentik-backup-%s.%s", timestamp, format)
		} else {
			output = filepath.Join(backupDir, fmt.Sprintf("authentik-backup-%s.%s", timestamp, format))
		}
	}

	// Create backup directory if needed
	backupDir := filepath.Dir(output)
	if backupDir != "." && backupDir != "/" {
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// INTERVENE - Extract configuration
	logger.Info("Extracting Authentik configuration",
		zap.String("url", url),
		zap.String("output", output))

	// If extracting Wazuh-specific config
	if extractWazuh {
		types = []string{"providers", "applications", "mappings", "groups"}
		logger.Info("Extracting Wazuh/Delphi SSO specific configuration")
	}

	// Default to all types if none specified
	if len(types) == 0 && !extractWazuh {
		types = []string{"providers", "applications", "mappings", "flows",
			"stages", "groups", "policies", "certificates", "blueprints", "outposts", "tenants"}
	}

	// Extract configuration using the helper function
	config, err := authentik.ExtractConfigurationAPI(rc.Ctx, url, token, types, apps, providers, includeSecrets)
	if err != nil {
		return fmt.Errorf("failed to extract configuration: %w", err)
	}

	// Save to file
	var data []byte
	if format == "yaml" {
		data, err = yaml.Marshal(config)
	} else {
		data, err = json.MarshalIndent(config, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(output, data, 0600); err != nil {
		return fmt.Errorf("failed to save backup: %w", err)
	}

	// EVALUATE - Verify and report
	logger.Info("Backup completed successfully",
		zap.String("file", output),
		zap.Int("providers", len(config.Providers)),
		zap.Int("applications", len(config.Applications)),
		zap.Int("mappings", len(config.PropertyMappings)),
		zap.Int("flows", len(config.Flows)),
		zap.Int("stages", len(config.Stages)),
		zap.Int("groups", len(config.Groups)),
		zap.Int("policies", len(config.Policies)),
		zap.Int("certificates", len(config.Certificates)),
		zap.Int("blueprints", len(config.Blueprints)),
		zap.Int("outposts", len(config.Outposts)),
		zap.Int("tenants", len(config.Tenants)))

	// Check for critical Wazuh configuration
	if extractWazuh || checkWazuhConfiguration(config) {
		logger.Info("Found Wazuh/Delphi SSO configuration",
			zap.String("tip", "Use 'eos update authentik --from-backup' to import"))

		// Verify critical Roles mapping
		if !checkRolesMapping(config) {
			logger.Warn("Missing critical 'Roles' property mapping required for Wazuh SSO")
		}
	}

	return nil
}

// backupAuthentikFilesystem handles legacy filesystem-based backups
func backupAuthentikFilesystem(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Filesystem backup mode is deprecated. Consider using API-based backup instead.")

	// TODO: Implement filesystem backup if needed
	return eos_err.NewUserError("Filesystem backup not yet implemented. Use API-based backup with --url and --token flags")
}

// checkWazuhConfiguration checks if the config contains Wazuh/Delphi related items
func checkWazuhConfiguration(config *authentik.AuthentikConfig) bool {
	keywords := []string{"wazuh", "delphi", "analyst", "soc", "siem"}

	// Check providers
	for _, provider := range config.Providers {
		lowerName := strings.ToLower(provider.Name)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) {
				return true
			}
		}
	}

	// Check applications
	for _, app := range config.Applications {
		lowerName := strings.ToLower(app.Name)
		lowerSlug := strings.ToLower(app.Slug)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) || strings.Contains(lowerSlug, keyword) {
				return true
			}
		}
	}

	// Check groups
	for _, group := range config.Groups {
		lowerName := strings.ToLower(group.Name)
		for _, keyword := range keywords {
			if strings.Contains(lowerName, keyword) {
				return true
			}
		}
	}

	return false
}

// checkRolesMapping checks if the config contains the critical Roles property mapping
func checkRolesMapping(config *authentik.AuthentikConfig) bool {
	for _, mapping := range config.PropertyMappings {
		// Check if this is a SAML mapping with the critical "Roles" attribute name
		if mapping.SAMLName == "Roles" {
			return true
		}
	}
	return false
}
