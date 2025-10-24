// cmd/authentik/extract.go

package authentik

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// AuthentikConfig represents the complete Authentik configuration
type AuthentikConfig struct {
	Metadata         ConfigMetadata    `json:"metadata" yaml:"metadata"`
	Providers        []Provider        `json:"providers" yaml:"providers"`
	Applications     []Application     `json:"applications" yaml:"applications"`
	PropertyMappings []PropertyMapping `json:"property_mappings" yaml:"property_mappings"`
	Flows            []Flow            `json:"flows" yaml:"flows"`
	Stages           []Stage           `json:"stages" yaml:"stages"`
	Groups           []Group           `json:"groups" yaml:"groups"`
	Policies         []Policy          `json:"policies" yaml:"policies"`
	Certificates     []Certificate     `json:"certificates" yaml:"certificates"`
	Outposts         []Outpost         `json:"outposts" yaml:"outposts"`
	Tenants          []Tenant          `json:"tenants" yaml:"tenants"`
	Blueprints       []Blueprint       `json:"blueprints" yaml:"blueprints"`
}

// ConfigMetadata contains information about the export
type ConfigMetadata struct {
	ExportedAt       time.Time `json:"exported_at" yaml:"exported_at"`
	AuthentikVersion string    `json:"authentik_version" yaml:"authentik_version"`
	SourceURL        string    `json:"source_url" yaml:"source_url"`
	ExportedBy       string    `json:"exported_by" yaml:"exported_by"`
	SelectiveExport  bool      `json:"selective_export" yaml:"selective_export"`
}

// Provider represents any type of provider (SAML, OAuth2, LDAP, etc.)
type Provider struct {
	PK     string                 `json:"pk" yaml:"pk"`
	Name   string                 `json:"name" yaml:"name"`
	Type   string                 `json:"type" yaml:"type"`
	Config map[string]interface{} `json:"config" yaml:"config"`
}

// Application represents an Authentik application
type Application struct {
	PK               string                 `json:"pk" yaml:"pk"`
	Name             string                 `json:"name" yaml:"name"`
	Slug             string                 `json:"slug" yaml:"slug"`
	Provider         string                 `json:"provider,omitempty" yaml:"provider,omitempty"`
	MetaLaunchURL    string                 `json:"meta_launch_url,omitempty" yaml:"meta_launch_url,omitempty"`
	MetaDescription  string                 `json:"meta_description,omitempty" yaml:"meta_description,omitempty"`
	MetaPublisher    string                 `json:"meta_publisher,omitempty" yaml:"meta_publisher,omitempty"`
	PolicyEngineMode string                 `json:"policy_engine_mode" yaml:"policy_engine_mode"`
	Config           map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// Group represents a user group
type Group struct {
	PK          string                 `json:"pk" yaml:"pk"`
	Name        string                 `json:"name" yaml:"name"`
	IsSuperuser bool                   `json:"is_superuser" yaml:"is_superuser"`
	Parent      string                 `json:"parent,omitempty" yaml:"parent,omitempty"`
	Users       []string               `json:"users,omitempty" yaml:"users,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Flow represents an authentication flow
type Flow struct {
	PK                string                 `json:"pk" yaml:"pk"`
	Slug              string                 `json:"slug" yaml:"slug"`
	Name              string                 `json:"name" yaml:"name"`
	Title             string                 `json:"title" yaml:"title"`
	Designation       string                 `json:"designation" yaml:"designation"`
	PolicyEngineMode  string                 `json:"policy_engine_mode" yaml:"policy_engine_mode"`
	CompatibilityMode bool                   `json:"compatibility_mode" yaml:"compatibility_mode"`
	Layout            string                 `json:"layout" yaml:"layout"`
	DeniedAction      string                 `json:"denied_action" yaml:"denied_action"`
	Stages            []string               `json:"stages,omitempty" yaml:"stages,omitempty"`
	Config            map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// Stage represents a flow stage
type Stage struct {
	PK     string                 `json:"pk" yaml:"pk"`
	Name   string                 `json:"name" yaml:"name"`
	Type   string                 `json:"type" yaml:"type"`
	Config map[string]interface{} `json:"config" yaml:"config"`
}

// Policy represents an Authentik policy
type Policy struct {
	PK               string                 `json:"pk" yaml:"pk"`
	Name             string                 `json:"name" yaml:"name"`
	Type             string                 `json:"type" yaml:"type"`
	ExecutionLogging bool                   `json:"execution_logging" yaml:"execution_logging"`
	Config           map[string]interface{} `json:"config" yaml:"config"`
}

// Certificate represents a certificate/key pair
type Certificate struct {
	PK          string    `json:"pk" yaml:"pk"`
	Name        string    `json:"name" yaml:"name"`
	Certificate string    `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	KeyData     string    `json:"key_data,omitempty" yaml:"key_data,omitempty"`
	Managed     string    `json:"managed,omitempty" yaml:"managed,omitempty"`
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
}

// Outpost represents an Authentik outpost
type Outpost struct {
	PK                string                 `json:"pk" yaml:"pk"`
	Name              string                 `json:"name" yaml:"name"`
	Type              string                 `json:"type" yaml:"type"`
	ServiceConnection string                 `json:"service_connection,omitempty" yaml:"service_connection,omitempty"`
	Providers         []string               `json:"providers" yaml:"providers"`
	Config            map[string]interface{} `json:"config" yaml:"config"`
}

// Tenant represents an Authentik tenant
type Tenant struct {
	PK                 string                 `json:"pk" yaml:"pk"`
	Domain             string                 `json:"domain" yaml:"domain"`
	Default            bool                   `json:"default" yaml:"default"`
	BrandingTitle      string                 `json:"branding_title,omitempty" yaml:"branding_title,omitempty"`
	BrandingLogo       string                 `json:"branding_logo,omitempty" yaml:"branding_logo,omitempty"`
	BrandingFavicon    string                 `json:"branding_favicon,omitempty" yaml:"branding_favicon,omitempty"`
	FlowAuthentication string                 `json:"flow_authentication,omitempty" yaml:"flow_authentication,omitempty"`
	FlowInvalidation   string                 `json:"flow_invalidation,omitempty" yaml:"flow_invalidation,omitempty"`
	FlowRecovery       string                 `json:"flow_recovery,omitempty" yaml:"flow_recovery,omitempty"`
	FlowUnenrollment   string                 `json:"flow_unenrollment,omitempty" yaml:"flow_unenrollment,omitempty"`
	Config             map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// Blueprint represents an Authentik blueprint
type Blueprint struct {
	PK      string                 `json:"pk" yaml:"pk"`
	Name    string                 `json:"name" yaml:"name"`
	Path    string                 `json:"path" yaml:"path"`
	Context map[string]interface{} `json:"context,omitempty" yaml:"context,omitempty"`
	Enabled bool                   `json:"enabled" yaml:"enabled"`
	Content string                 `json:"content,omitempty" yaml:"content,omitempty"`
}

// extractCmd is the main extract command
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract Authentik configuration",
	Long: `Extract configuration from an Authentik instance for backup or migration.

This command connects to an Authentik instance via API and extracts all
configuration including providers, applications, flows, policies, etc.`,
	RunE: runExtract,
}

// listCmd lists available configurations
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List Authentik configurations",
	Long:  `List all available configurations in an Authentik instance.`,
	RunE:  runList,
}

func init() {
	// Extract command flags
	extractCmd.Flags().String("url", "", "Authentik API URL (required)")
	extractCmd.Flags().String("token", "", "API token (required)")
	extractCmd.Flags().String("output", "", "Output file path (default: authentik-config-<timestamp>.yaml)")
	extractCmd.Flags().String("format", "yaml", "Output format (yaml/json)")
	extractCmd.Flags().Bool("include-secrets", false, "Include sensitive data like private keys")
	extractCmd.Flags().StringSlice("types", []string{}, "Specific types to export (providers,applications,flows,etc.)")
	extractCmd.Flags().StringSlice("apps", []string{}, "Specific applications to export (by slug)")
	extractCmd.Flags().StringSlice("providers", []string{}, "Specific providers to export (by name)")
	extractCmd.Flags().Bool("dry-run", false, "Show what would be exported without actually exporting")

	_ = extractCmd.MarkFlagRequired("url")
	_ = extractCmd.MarkFlagRequired("token")

	// List command flags
	listCmd.Flags().String("url", "", "Authentik API URL (required)")
	listCmd.Flags().String("token", "", "API token (required)")
	listCmd.Flags().String("type", "", "List specific type (providers/applications/flows/groups/policies)")
	listCmd.Flags().Bool("detailed", false, "Show detailed information")

	_ = listCmd.MarkFlagRequired("url")
	_ = listCmd.MarkFlagRequired("token")
}

func runExtract(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	outputPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	includeSecrets, _ := cmd.Flags().GetBool("include-secrets")
	types, _ := cmd.Flags().GetStringSlice("types")
	apps, _ := cmd.Flags().GetStringSlice("apps")
	providers, _ := cmd.Flags().GetStringSlice("providers")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Create API client
	client := &AuthentikAPIClient{
		BaseURL: url,
		Token:   token,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}

	fmt.Println(" Extracting Authentik configuration...")
	fmt.Printf("   Source: %s\n", url)

	// Initialize config
	config := &AuthentikConfig{
		Metadata: ConfigMetadata{
			ExportedAt:      time.Now(),
			SourceURL:       url,
			ExportedBy:      os.Getenv("USER"),
			SelectiveExport: len(types) > 0 || len(apps) > 0 || len(providers) > 0,
		},
	}

	// Get Authentik version
	version, err := client.GetVersion()
	if err != nil {
		fmt.Printf("Warning: Could not get Authentik version: %v\n", err)
	} else {
		config.Metadata.AuthentikVersion = version
		fmt.Printf("   Version: %s\n", version)
	}

	// Determine what to export
	exportTypes := types
	if len(exportTypes) == 0 {
		exportTypes = []string{"providers", "applications", "property_mappings",
			"flows", "stages", "groups", "policies", "certificates",
			"outposts", "tenants", "blueprints"}
	}

	if dryRun {
		fmt.Println("\n Dry run - would export:")
		for _, t := range exportTypes {
			fmt.Printf("   - %s\n", t)
		}
		if len(apps) > 0 {
			fmt.Printf("   Applications filter: %v\n", apps)
		}
		if len(providers) > 0 {
			fmt.Printf("   Providers filter: %v\n", providers)
		}
		return nil
	}

	// Extract each component
	for _, exportType := range exportTypes {
		switch exportType {
		case "providers":
			fmt.Print("   Extracting providers... ")
			items, err := client.GetProviders(providers)
			if err != nil {
				return fmt.Errorf("failed to get providers: %w", err)
			}
			config.Providers = items
			fmt.Printf(" (%d found)\n", len(items))

		case "applications":
			fmt.Print("   Extracting applications... ")
			items, err := client.GetApplications(apps)
			if err != nil {
				return fmt.Errorf("failed to get applications: %w", err)
			}
			config.Applications = items
			fmt.Printf(" (%d found)\n", len(items))

		case "property_mappings":
			fmt.Print("   Extracting property mappings... ")
			items, err := client.GetPropertyMappings()
			if err != nil {
				return fmt.Errorf("failed to get property mappings: %w", err)
			}
			config.PropertyMappings = items
			fmt.Printf(" (%d found)\n", len(items))

		case "flows":
			fmt.Print("   Extracting flows... ")
			items, err := client.GetFlows()
			if err != nil {
				return fmt.Errorf("failed to get flows: %w", err)
			}
			config.Flows = items
			fmt.Printf(" (%d found)\n", len(items))

		case "stages":
			fmt.Print("   Extracting stages... ")
			items, err := client.GetStages()
			if err != nil {
				return fmt.Errorf("failed to get stages: %w", err)
			}
			config.Stages = items
			fmt.Printf(" (%d found)\n", len(items))

		case "groups":
			fmt.Print("   Extracting groups... ")
			items, err := client.GetGroups()
			if err != nil {
				return fmt.Errorf("failed to get groups: %w", err)
			}
			config.Groups = items
			fmt.Printf(" (%d found)\n", len(items))

		case "policies":
			fmt.Print("   Extracting policies... ")
			items, err := client.GetPolicies()
			if err != nil {
				return fmt.Errorf("failed to get policies: %w", err)
			}
			config.Policies = items
			fmt.Printf(" (%d found)\n", len(items))

		case "certificates":
			fmt.Print("   Extracting certificates... ")
			items, err := client.GetCertificates(includeSecrets)
			if err != nil {
				return fmt.Errorf("failed to get certificates: %w", err)
			}
			config.Certificates = items
			fmt.Printf(" (%d found)\n", len(items))

		case "outposts":
			fmt.Print("   Extracting outposts... ")
			items, err := client.GetOutposts()
			if err != nil {
				return fmt.Errorf("failed to get outposts: %w", err)
			}
			config.Outposts = items
			fmt.Printf(" (%d found)\n", len(items))

		case "tenants":
			fmt.Print("   Extracting tenants... ")
			items, err := client.GetTenants()
			if err != nil {
				return fmt.Errorf("failed to get tenants: %w", err)
			}
			config.Tenants = items
			fmt.Printf(" (%d found)\n", len(items))

		case "blueprints":
			fmt.Print("   Extracting blueprints... ")
			items, err := client.GetBlueprints()
			if err != nil {
				return fmt.Errorf("failed to get blueprints: %w", err)
			}
			config.Blueprints = items
			fmt.Printf(" (%d found)\n", len(items))
		}
	}

	// Clean sensitive data if not included
	if !includeSecrets {
		cleanSensitiveData(config)
	}

	// Generate output filename if not provided
	if outputPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		outputPath = fmt.Sprintf("authentik-config-%s.%s", timestamp, format)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal configuration
	var data []byte
	if format == "json" {
		data, err = json.MarshalIndent(config, "", "  ")
	} else {
		data, err = yaml.Marshal(config)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write to file with secure permissions (0600 - owner read/write only)
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	fmt.Printf("\n Configuration exported to: %s\n", outputPath)
	fmt.Printf("   Total size: %.2f KB\n", float64(len(data))/1024)

	// Show summary
	fmt.Println("\n Export Summary:")
	fmt.Printf("   Providers:         %d\n", len(config.Providers))
	fmt.Printf("   Applications:      %d\n", len(config.Applications))
	fmt.Printf("   Property Mappings: %d\n", len(config.PropertyMappings))
	fmt.Printf("   Flows:            %d\n", len(config.Flows))
	fmt.Printf("   Stages:           %d\n", len(config.Stages))
	fmt.Printf("   Groups:           %d\n", len(config.Groups))
	fmt.Printf("   Policies:         %d\n", len(config.Policies))
	fmt.Printf("   Certificates:     %d\n", len(config.Certificates))
	fmt.Printf("   Outposts:         %d\n", len(config.Outposts))
	fmt.Printf("   Tenants:          %d\n", len(config.Tenants))
	fmt.Printf("   Blueprints:       %d\n", len(config.Blueprints))

	if !includeSecrets {
		fmt.Println("\nNote: Sensitive data (private keys, secrets) was excluded.")
		fmt.Println("   Use --include-secrets flag to include sensitive data.")
	}

	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	listType, _ := cmd.Flags().GetString("type")
	detailed, _ := cmd.Flags().GetBool("detailed")

	client := &AuthentikAPIClient{
		BaseURL: url,
		Token:   token,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}

	fmt.Printf(" Listing Authentik configurations from: %s\n\n", url)

	// If no specific type, show summary
	if listType == "" {
		showSummary(client)
		return nil
	}

	// Show specific type
	switch listType {
	case "providers":
		return listProviders(client, detailed)
	case "applications":
		return listApplications(client, detailed)
	case "flows":
		return listFlows(client, detailed)
	case "groups":
		return listGroups(client, detailed)
	case "policies":
		return listPolicies(client, detailed)
	default:
		return fmt.Errorf("unknown type: %s", listType)
	}
}

func showSummary(client *AuthentikAPIClient) error {
	// Get counts for each type
	providers, _ := client.GetProviders(nil)
	apps, _ := client.GetApplications(nil)
	flows, _ := client.GetFlows()
	groups, _ := client.GetGroups()
	policies, _ := client.GetPolicies()

	fmt.Println("Configuration Summary:")
	fmt.Println("─────────────────────")
	fmt.Printf("Providers:    %d\n", len(providers))
	fmt.Printf("Applications: %d\n", len(apps))
	fmt.Printf("Flows:        %d\n", len(flows))
	fmt.Printf("Groups:       %d\n", len(groups))
	fmt.Printf("Policies:     %d\n", len(policies))

	fmt.Println("\nUse --type=<type> for detailed listing")
	return nil
}

func listProviders(client *AuthentikAPIClient, detailed bool) error {
	providers, err := client.GetProviders(nil)
	if err != nil {
		return err
	}

	fmt.Printf("Providers (%d):\n", len(providers))
	fmt.Println("──────────────")

	for _, p := range providers {
		if detailed {
			fmt.Printf("\n %s\n", p.Name)
			fmt.Printf("   PK:   %s\n", p.PK)
			fmt.Printf("   Type: %s\n", p.Type)
			if p.Config["acs_url"] != nil {
				fmt.Printf("   ACS URL: %v\n", p.Config["acs_url"])
			}
			if p.Config["authorization_flow"] != nil {
				fmt.Printf("   Auth Flow: %v\n", p.Config["authorization_flow"])
			}
		} else {
			fmt.Printf("• %s (%s)\n", p.Name, p.Type)
		}
	}

	return nil
}

func listApplications(client *AuthentikAPIClient, detailed bool) error {
	apps, err := client.GetApplications(nil)
	if err != nil {
		return err
	}

	fmt.Printf("Applications (%d):\n", len(apps))
	fmt.Println("─────────────────")

	for _, a := range apps {
		if detailed {
			fmt.Printf("\n %s\n", a.Name)
			fmt.Printf("   Slug: %s\n", a.Slug)
			fmt.Printf("   Provider: %s\n", a.Provider)
			if a.MetaLaunchURL != "" {
				fmt.Printf("   Launch URL: %s\n", a.MetaLaunchURL)
			}
			if a.MetaDescription != "" {
				fmt.Printf("   Description: %s\n", a.MetaDescription)
			}
		} else {
			fmt.Printf("• %s [%s]\n", a.Name, a.Slug)
		}
	}

	return nil
}

func listFlows(client *AuthentikAPIClient, detailed bool) error {
	flows, err := client.GetFlows()
	if err != nil {
		return err
	}

	fmt.Printf("Flows (%d):\n", len(flows))
	fmt.Println("───────────")

	for _, f := range flows {
		if detailed {
			fmt.Printf("\n %s\n", f.Name)
			fmt.Printf("   Slug: %s\n", f.Slug)
			fmt.Printf("   Title: %s\n", f.Title)
			fmt.Printf("   Designation: %s\n", f.Designation)
			fmt.Printf("   Stages: %d\n", len(f.Stages))
		} else {
			fmt.Printf("• %s (%s) - %s\n", f.Name, f.Slug, f.Designation)
		}
	}

	return nil
}

func listGroups(client *AuthentikAPIClient, detailed bool) error {
	groups, err := client.GetGroups()
	if err != nil {
		return err
	}

	fmt.Printf("Groups (%d):\n", len(groups))
	fmt.Println("────────────")

	for _, g := range groups {
		if detailed {
			fmt.Printf("\n👥 %s\n", g.Name)
			fmt.Printf("   PK: %s\n", g.PK)
			if g.IsSuperuser {
				fmt.Printf("   Superuser: Yes\n")
			}
			if g.Parent != "" {
				fmt.Printf("   Parent: %s\n", g.Parent)
			}
			fmt.Printf("   Users: %d\n", len(g.Users))
		} else {
			superuser := ""
			if g.IsSuperuser {
				superuser = " [SUPERUSER]"
			}
			fmt.Printf("• %s%s\n", g.Name, superuser)
		}
	}

	return nil
}

func listPolicies(client *AuthentikAPIClient, detailed bool) error {
	policies, err := client.GetPolicies()
	if err != nil {
		return err
	}

	fmt.Printf("Policies (%d):\n", len(policies))
	fmt.Println("──────────────")

	for _, p := range policies {
		if detailed {
			fmt.Printf("\n📜 %s\n", p.Name)
			fmt.Printf("   Type: %s\n", p.Type)
			fmt.Printf("   Execution Logging: %v\n", p.ExecutionLogging)
		} else {
			fmt.Printf("• %s (%s)\n", p.Name, p.Type)
		}
	}

	return nil
}

func cleanSensitiveData(config *AuthentikConfig) {
	// Remove private keys from certificates
	for i := range config.Certificates {
		config.Certificates[i].KeyData = ""
	}

	// Remove sensitive provider config
	for i := range config.Providers {
		if config.Providers[i].Config["client_secret"] != nil {
			config.Providers[i].Config["client_secret"] = "REDACTED"
		}
		if config.Providers[i].Config["shared_secret"] != nil {
			config.Providers[i].Config["shared_secret"] = "REDACTED"
		}
	}

	// Clean other sensitive fields as needed
}

// AuthentikAPIClient handles API communication
type AuthentikAPIClient struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func (c *AuthentikAPIClient) makeRequest(endpoint string) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v3/%s", c.BaseURL, endpoint), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed (status %d): %s", resp.StatusCode, body)
	}

	return io.ReadAll(resp.Body)
}

func (c *AuthentikAPIClient) GetVersion() (string, error) {
	data, err := c.makeRequest("root/config/")
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}

	if version, ok := result["version"].(string); ok {
		return version, nil
	}

	return "unknown", nil
}

func (c *AuthentikAPIClient) GetProviders(filter []string) ([]Provider, error) {
	endpoint := "providers/all/"
	if len(filter) > 0 {
		endpoint += "?search=" + strings.Join(filter, ",")
	}

	data, err := c.makeRequest(endpoint)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Provider `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetApplications(filter []string) ([]Application, error) {
	endpoint := "core/applications/"
	if len(filter) > 0 {
		endpoint += "?slug__in=" + strings.Join(filter, ",")
	}

	data, err := c.makeRequest(endpoint)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Application `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetPropertyMappings() ([]PropertyMapping, error) {
	data, err := c.makeRequest("propertymappings/all/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []PropertyMapping `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetFlows() ([]Flow, error) {
	data, err := c.makeRequest("flows/instances/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Flow `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetStages() ([]Stage, error) {
	data, err := c.makeRequest("stages/all/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Stage `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetGroups() ([]Group, error) {
	data, err := c.makeRequest("core/groups/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Group `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetPolicies() ([]Policy, error) {
	data, err := c.makeRequest("policies/all/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Policy `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetCertificates(includePrivateKeys bool) ([]Certificate, error) {
	endpoint := "crypto/certificatekeypairs/"
	if includePrivateKeys {
		endpoint += "?include_private_key=true"
	}

	data, err := c.makeRequest(endpoint)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Certificate `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetOutposts() ([]Outpost, error) {
	data, err := c.makeRequest("outposts/instances/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Outpost `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetTenants() ([]Tenant, error) {
	data, err := c.makeRequest("core/tenants/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Tenant `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}

func (c *AuthentikAPIClient) GetBlueprints() ([]Blueprint, error) {
	data, err := c.makeRequest("blueprints/instances/")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []Blueprint `json:"results"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Results, nil
}
