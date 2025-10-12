// cmd/authentik/import.go
package authentik

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// ImportOptions contains options for the import process
type ImportOptions struct {
	SkipExisting   bool
	UpdateExisting bool
	DryRun         bool
	ValidateOnly   bool
	MapFile        string
	SkipTypes      []string
	OnlyTypes      []string
	Force          bool
	CreateBackup   bool
	MappingRules   map[string]string
}

// ImportResult tracks the result of the import
type ImportResult struct {
	Created  int
	Updated  int
	Skipped  int
	Failed   int
	Errors   []string
	Warnings []string
}

// importCmd is the main import command
var importCmd = &cobra.Command{
	Use:   "import <config-file>",
	Short: "Import Authentik configuration",
	Long: `Import configuration into an Authentik instance from a backup file.

This command reads a configuration file created by 'eos authentik extract' and
imports it into a target Authentik instance. It supports selective import,
conflict resolution, and validation.`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

// compareCmd compares two Authentik instances or configs
var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare Authentik configurations",
	Long: `Compare configurations between two Authentik instances or config files.

This helps identify differences before migration or to audit changes.`,
	RunE: runCompare,
}

// validateCmd validates a configuration file
var validateCmd = &cobra.Command{
	Use:   "validate <config-file>",
	Short: "Validate an Authentik configuration file",
	Long:  `Validate the structure and content of an Authentik configuration file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runValidate,
}

func init() {
	// Import command flags
	importCmd.Flags().String("url", "", "Target Authentik API URL (required)")
	importCmd.Flags().String("token", "", "API token (required)")
	importCmd.Flags().Bool("skip-existing", false, "Skip resources that already exist")
	importCmd.Flags().Bool("update-existing", false, "Update existing resources")
	importCmd.Flags().Bool("dry-run", false, "Simulate import without making changes")
	importCmd.Flags().Bool("validate-only", false, "Only validate the configuration file")
	importCmd.Flags().String("map-file", "", "Mapping file for ID/reference translations")
	importCmd.Flags().StringSlice("skip-types", []string{}, "Resource types to skip")
	importCmd.Flags().StringSlice("only-types", []string{}, "Only import these resource types")
	importCmd.Flags().Bool("force", false, "Force import even with warnings")
	importCmd.Flags().Bool("create-backup", true, "Create backup before importing")

	importCmd.MarkFlagRequired("url")
	importCmd.MarkFlagRequired("token")

	// Compare command flags
	compareCmd.Flags().String("source", "", "Source (URL or file)")
	compareCmd.Flags().String("source-token", "", "Source API token (if URL)")
	compareCmd.Flags().String("target", "", "Target (URL or file)")
	compareCmd.Flags().String("target-token", "", "Target API token (if URL)")
	compareCmd.Flags().String("output", "", "Output comparison to file")
	compareCmd.Flags().Bool("detailed", false, "Show detailed differences")

	compareCmd.MarkFlagRequired("source")
	compareCmd.MarkFlagRequired("target")
}

func runImport(cmd *cobra.Command, args []string) error {
	configFile := args[0]
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")

	options := ImportOptions{
		SkipExisting:   getFlag(cmd, "skip-existing").(bool),
		UpdateExisting: getFlag(cmd, "update-existing").(bool),
		DryRun:         getFlag(cmd, "dry-run").(bool),
		ValidateOnly:   getFlag(cmd, "validate-only").(bool),
		MapFile:        getFlag(cmd, "map-file").(string),
		SkipTypes:      getFlag(cmd, "skip-types").([]string),
		OnlyTypes:      getFlag(cmd, "only-types").([]string),
		Force:          getFlag(cmd, "force").(bool),
		CreateBackup:   getFlag(cmd, "create-backup").(bool),
	}

	// Load configuration file
	fmt.Printf("📂 Loading configuration from: %s\n", configFile)
	config, err := loadConfigFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Printf("   Source: %s\n", config.Metadata.SourceURL)
	fmt.Printf("   Exported: %s\n", config.Metadata.ExportedAt.Format(time.RFC3339))
	fmt.Printf("   Version: %s\n", config.Metadata.AuthentikVersion)

	// Validate configuration
	fmt.Print("\n Validating configuration... ")
	warnings, errors := validateConfig(config)

	if len(errors) > 0 {
		fmt.Println("")
		fmt.Println("\nValidation errors:")
		for _, err := range errors {
			fmt.Printf("   • %s\n", err)
		}
		if !options.Force {
			return fmt.Errorf("validation failed, use --force to continue anyway")
		}
		fmt.Println("   Continuing with --force flag")
	} else {
		fmt.Println("")
	}

	if len(warnings) > 0 {
		fmt.Println("\nValidation warnings:")
		for _, warn := range warnings {
			fmt.Printf("   • %s\n", warn)
		}
	}

	if options.ValidateOnly {
		fmt.Println("\n Validation complete (--validate-only flag set)")
		return nil
	}

	// Create backup if requested
	if options.CreateBackup && !options.DryRun {
		fmt.Print("\n💾 Creating backup of target instance... ")
		backupFile := fmt.Sprintf("authentik-backup-%s.yaml", time.Now().Format("20060102-150405"))
		extractCmd := &cobra.Command{}
		extractCmd.Flags().String("url", url, "")
		extractCmd.Flags().String("token", token, "")
		extractCmd.Flags().String("output", backupFile, "")
		extractCmd.Flags().String("format", "yaml", "")

		if err := runExtract(extractCmd, []string{}); err != nil {
			fmt.Printf("Warning: Could not create backup: %v\n", err)
		} else {
			fmt.Printf(" Saved to %s\n", backupFile)
		}
	}

	// Load mapping rules if provided
	if options.MapFile != "" {
		fmt.Printf("\n📋 Loading mapping rules from: %s\n", options.MapFile)
		options.MappingRules, err = loadMappingRules(options.MapFile)
		if err != nil {
			return fmt.Errorf("failed to load mapping rules: %w", err)
		}
		fmt.Printf("   Loaded %d mapping rules\n", len(options.MappingRules))
	}

	// Create API client
	client := &AuthentikAPIClient{
		BaseURL: url,
		Token:   token,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}

	// Check target version compatibility
	targetVersion, err := client.GetVersion()
	if err != nil {
		fmt.Printf("Warning: Could not check target version: %v\n", err)
	} else {
		fmt.Printf("\n🎯 Target Authentik version: %s\n", targetVersion)
		if !isVersionCompatible(config.Metadata.AuthentikVersion, targetVersion) {
			fmt.Printf("Warning: Version mismatch (source: %s, target: %s)\n",
				config.Metadata.AuthentikVersion, targetVersion)
			if !options.Force {
				return fmt.Errorf("version incompatibility detected, use --force to continue")
			}
		}
	}

	// Start import process
	fmt.Println("\n Starting import process...")
	if options.DryRun {
		fmt.Println("   🔸 DRY RUN MODE - No changes will be made")
	}

	result := &ImportResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	// Import order matters - dependencies first
	importOrder := []string{
		"certificates",
		"property_mappings",
		"policies",
		"stages",
		"flows",
		"providers",
		"applications",
		"groups",
		"outposts",
		"tenants",
		"blueprints",
	}

	for _, resourceType := range importOrder {
		// Skip if not in only-types or in skip-types
		if len(options.OnlyTypes) > 0 && !contains(options.OnlyTypes, resourceType) {
			continue
		}
		if contains(options.SkipTypes, resourceType) {
			continue
		}

		fmt.Printf("\n Importing %s...\n", resourceType)

		switch resourceType {
		case "certificates":
			importCertificates(client, config.Certificates, options, result)
		case "property_mappings":
			importPropertyMappings(client, config.PropertyMappings, options, result)
		case "policies":
			importPolicies(client, config.Policies, options, result)
		case "stages":
			importStages(client, config.Stages, options, result)
		case "flows":
			importFlows(client, config.Flows, options, result)
		case "providers":
			importProviders(client, config.Providers, options, result)
		case "applications":
			importApplications(client, config.Applications, options, result)
		case "groups":
			importGroups(client, config.Groups, options, result)
		case "outposts":
			importOutposts(client, config.Outposts, options, result)
		case "tenants":
			importTenants(client, config.Tenants, options, result)
		case "blueprints":
			importBlueprints(client, config.Blueprints, options, result)
		}
	}

	// Show import summary
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("📊 Import Summary:")
	fmt.Printf("   Created: %d\n", result.Created)
	fmt.Printf("   Updated: %d\n", result.Updated)
	fmt.Printf("   Skipped: %d\n", result.Skipped)
	fmt.Printf("   Failed:  %d\n", result.Failed)

	if len(result.Errors) > 0 {
		fmt.Println("\n Errors encountered:")
		for _, err := range result.Errors {
			fmt.Printf("   • %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, warn := range result.Warnings {
			fmt.Printf("   • %s\n", warn)
		}
	}

	if result.Failed == 0 {
		fmt.Println("\n Import completed successfully!")
	} else {
		fmt.Printf("\nImport completed with %d failures\n", result.Failed)
	}

	return nil
}

func runCompare(cmd *cobra.Command, args []string) error {
	source, _ := cmd.Flags().GetString("source")
	sourceToken, _ := cmd.Flags().GetString("source-token")
	target, _ := cmd.Flags().GetString("target")
	targetToken, _ := cmd.Flags().GetString("target-token")
	output, _ := cmd.Flags().GetString("output")
	detailed, _ := cmd.Flags().GetBool("detailed")

	fmt.Println(" Comparing Authentik configurations...")

	// Load source configuration
	var sourceConfig *AuthentikConfig
	if strings.HasPrefix(source, "http") {
		fmt.Printf("   Loading source from: %s\n", source)
		client := &AuthentikAPIClient{
			BaseURL: source,
			Token:   sourceToken,
			Client:  &http.Client{Timeout: 30 * time.Second},
		}
		sourceConfig = extractFullConfig(client)
	} else {
		fmt.Printf("   Loading source from file: %s\n", source)
		var err error
		sourceConfig, err = loadConfigFile(source)
		if err != nil {
			return fmt.Errorf("failed to load source: %w", err)
		}
	}

	// Load target configuration
	var targetConfig *AuthentikConfig
	if strings.HasPrefix(target, "http") {
		fmt.Printf("   Loading target from: %s\n", target)
		client := &AuthentikAPIClient{
			BaseURL: target,
			Token:   targetToken,
			Client:  &http.Client{Timeout: 30 * time.Second},
		}
		targetConfig = extractFullConfig(client)
	} else {
		fmt.Printf("   Loading target from file: %s\n", target)
		var err error
		targetConfig, err = loadConfigFile(target)
		if err != nil {
			return fmt.Errorf("failed to load target: %w", err)
		}
	}

	// Perform comparison
	comparison := compareConfigurations(sourceConfig, targetConfig, detailed)

	// Output results
	if output != "" {
		data, _ := json.MarshalIndent(comparison, "", "  ")
		if err := os.WriteFile(output, data, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("\n📄 Comparison saved to: %s\n", output)
	} else {
		// Print to console
		printComparison(comparison)
	}

	return nil
}

func runValidate(cmd *cobra.Command, args []string) error {
	configFile := args[0]

	fmt.Printf(" Validating configuration file: %s\n\n", configFile)

	// Load configuration
	config, err := loadConfigFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate
	warnings, errors := validateConfig(config)

	if len(errors) == 0 && len(warnings) == 0 {
		fmt.Println(" Configuration is valid!")
		return nil
	}

	if len(warnings) > 0 {
		fmt.Println("Warnings found:")
		for _, warn := range warnings {
			fmt.Printf("   • %s\n", warn)
		}
	}

	if len(errors) > 0 {
		fmt.Println("\n Errors found:")
		for _, err := range errors {
			fmt.Printf("   • %s\n", err)
		}
		return fmt.Errorf("validation failed with %d errors", len(errors))
	}

	return nil
}

// Import functions for each resource type

func importCertificates(client *AuthentikAPIClient, certificates []Certificate, options ImportOptions, result *ImportResult) {
	for _, cert := range certificates {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import certificate: %s\n", cert.Name)
			continue
		}

		// Check if exists
		exists, existingID := client.CertificateExists(cert.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing certificate: %s\n", cert.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Certificate exists (use --update-existing to update): %s\n", cert.Name)
			result.Skipped++
			continue
		}

		// Create or update
		var err error
		if exists {
			err = client.UpdateCertificate(existingID, cert)
			if err == nil {
				fmt.Printf("    Updated certificate: %s\n", cert.Name)
				result.Updated++
			}
		} else {
			err = client.CreateCertificate(cert)
			if err == nil {
				fmt.Printf("    Created certificate: %s\n", cert.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import certificate %s: %v\n", cert.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Certificate %s: %v", cert.Name, err))
		}
	}
}

func importPropertyMappings(client *AuthentikAPIClient, mappings []PropertyMapping, options ImportOptions, result *ImportResult) {
	for _, mapping := range mappings {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import property mapping: %s\n", mapping.Name)
			continue
		}

		// Check for critical mappings (like Wazuh Roles)
		if strings.Contains(mapping.Name, "Roles") && mapping.SAMLName == "Roles" {
			fmt.Printf("   Critical mapping detected: %s (SAML Name: %s)\n", mapping.Name, mapping.SAMLName)
		}

		exists, existingID := client.PropertyMappingExists(mapping.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing property mapping: %s\n", mapping.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Property mapping exists: %s\n", mapping.Name)
			result.Skipped++
			continue
		}

		// Apply any mapping rules
		if options.MappingRules != nil {
			mapping = applyMappingRules(mapping, options.MappingRules)
		}

		var err error
		if exists {
			err = client.UpdatePropertyMapping(existingID, mapping)
			if err == nil {
				fmt.Printf("    Updated property mapping: %s\n", mapping.Name)
				result.Updated++
			}
		} else {
			err = client.CreatePropertyMapping(mapping)
			if err == nil {
				fmt.Printf("    Created property mapping: %s\n", mapping.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import property mapping %s: %v\n", mapping.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Property mapping %s: %v", mapping.Name, err))
		}
	}
}

func importFlows(client *AuthentikAPIClient, flows []Flow, options ImportOptions, result *ImportResult) {
	for _, flow := range flows {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import flow: %s\n", flow.Name)
			continue
		}

		exists, existingID := client.FlowExists(flow.Slug)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing flow: %s\n", flow.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Flow exists: %s\n", flow.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateFlow(existingID, flow)
			if err == nil {
				fmt.Printf("    Updated flow: %s\n", flow.Name)
				result.Updated++
			}
		} else {
			err = client.CreateFlow(flow)
			if err == nil {
				fmt.Printf("    Created flow: %s\n", flow.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import flow %s: %v\n", flow.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Flow %s: %v", flow.Name, err))
		}
	}
}

func importProviders(client *AuthentikAPIClient, providers []Provider, options ImportOptions, result *ImportResult) {
	for _, provider := range providers {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import %s provider: %s\n", provider.Type, provider.Name)
			continue
		}

		exists, existingID := client.ProviderExists(provider.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing provider: %s\n", provider.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Provider exists: %s\n", provider.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateProvider(existingID, provider)
			if err == nil {
				fmt.Printf("    Updated %s provider: %s\n", provider.Type, provider.Name)
				result.Updated++
			}
		} else {
			err = client.CreateProvider(provider)
			if err == nil {
				fmt.Printf("    Created %s provider: %s\n", provider.Type, provider.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import provider %s: %v\n", provider.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Provider %s: %v", provider.Name, err))
		}
	}
}

func importApplications(client *AuthentikAPIClient, apps []Application, options ImportOptions, result *ImportResult) {
	for _, app := range apps {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import application: %s\n", app.Name)
			continue
		}

		exists, existingID := client.ApplicationExists(app.Slug)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing application: %s\n", app.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Application exists: %s\n", app.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateApplication(existingID, app)
			if err == nil {
				fmt.Printf("    Updated application: %s\n", app.Name)
				result.Updated++
			}
		} else {
			err = client.CreateApplication(app)
			if err == nil {
				fmt.Printf("    Created application: %s\n", app.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import application %s: %v\n", app.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Application %s: %v", app.Name, err))
		}
	}
}

func importGroups(client *AuthentikAPIClient, groups []Group, options ImportOptions, result *ImportResult) {
	// Import parent groups first
	var parentGroups []Group
	var childGroups []Group

	for _, group := range groups {
		if group.Parent == "" {
			parentGroups = append(parentGroups, group)
		} else {
			childGroups = append(childGroups, group)
		}
	}

	// Import parent groups
	for _, group := range parentGroups {
		importSingleGroup(client, group, options, result)
	}

	// Then import child groups
	for _, group := range childGroups {
		importSingleGroup(client, group, options, result)
	}
}

func importSingleGroup(client *AuthentikAPIClient, group Group, options ImportOptions, result *ImportResult) {
	if options.DryRun {
		fmt.Printf("   [DRY RUN] Would import group: %s\n", group.Name)
		return
	}

	exists, existingID := client.GroupExists(group.Name)

	if exists && options.SkipExisting {
		fmt.Printf("   ⏭️  Skipping existing group: %s\n", group.Name)
		result.Skipped++
		return
	}

	if exists && !options.UpdateExisting {
		fmt.Printf("   ⏭️  Group exists: %s\n", group.Name)
		result.Skipped++
		return
	}

	var err error
	if exists {
		err = client.UpdateGroup(existingID, group)
		if err == nil {
			fmt.Printf("    Updated group: %s\n", group.Name)
			result.Updated++
		}
	} else {
		err = client.CreateGroup(group)
		if err == nil {
			fmt.Printf("    Created group: %s\n", group.Name)
			result.Created++
		}
	}

	if err != nil {
		fmt.Printf("    Failed to import group %s: %v\n", group.Name, err)
		result.Failed++
		result.Errors = append(result.Errors, fmt.Sprintf("Group %s: %v", group.Name, err))
	}
}

func importPolicies(client *AuthentikAPIClient, policies []Policy, options ImportOptions, result *ImportResult) {
	for _, policy := range policies {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import %s policy: %s\n", policy.Type, policy.Name)
			continue
		}

		exists, existingID := client.PolicyExists(policy.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing policy: %s\n", policy.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Policy exists: %s\n", policy.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdatePolicy(existingID, policy)
			if err == nil {
				fmt.Printf("    Updated policy: %s\n", policy.Name)
				result.Updated++
			}
		} else {
			err = client.CreatePolicy(policy)
			if err == nil {
				fmt.Printf("    Created policy: %s\n", policy.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import policy %s: %v\n", policy.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Policy %s: %v", policy.Name, err))
		}
	}
}

func importStages(client *AuthentikAPIClient, stages []Stage, options ImportOptions, result *ImportResult) {
	for _, stage := range stages {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import %s stage: %s\n", stage.Type, stage.Name)
			continue
		}

		// Stages are typically referenced by flows, so we need to track mappings
		exists, existingID := client.StageExists(stage.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing stage: %s\n", stage.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Stage exists: %s\n", stage.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateStage(existingID, stage)
			if err == nil {
				fmt.Printf("    Updated stage: %s\n", stage.Name)
				result.Updated++
			}
		} else {
			err = client.CreateStage(stage)
			if err == nil {
				fmt.Printf("    Created stage: %s\n", stage.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import stage %s: %v\n", stage.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Stage %s: %v", stage.Name, err))
		}
	}
}

func importOutposts(client *AuthentikAPIClient, outposts []Outpost, options ImportOptions, result *ImportResult) {
	for _, outpost := range outposts {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import %s outpost: %s\n", outpost.Type, outpost.Name)
			continue
		}

		exists, existingID := client.OutpostExists(outpost.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing outpost: %s\n", outpost.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Outpost exists: %s\n", outpost.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateOutpost(existingID, outpost)
			if err == nil {
				fmt.Printf("    Updated outpost: %s\n", outpost.Name)
				result.Updated++
			}
		} else {
			err = client.CreateOutpost(outpost)
			if err == nil {
				fmt.Printf("    Created outpost: %s\n", outpost.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import outpost %s: %v\n", outpost.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Outpost %s: %v", outpost.Name, err))
		}
	}
}

func importTenants(client *AuthentikAPIClient, tenants []Tenant, options ImportOptions, result *ImportResult) {
	for _, tenant := range tenants {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import tenant: %s\n", tenant.Domain)
			continue
		}

		exists, existingID := client.TenantExists(tenant.Domain)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing tenant: %s\n", tenant.Domain)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Tenant exists: %s\n", tenant.Domain)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateTenant(existingID, tenant)
			if err == nil {
				fmt.Printf("    Updated tenant: %s\n", tenant.Domain)
				result.Updated++
			}
		} else {
			err = client.CreateTenant(tenant)
			if err == nil {
				fmt.Printf("    Created tenant: %s\n", tenant.Domain)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import tenant %s: %v\n", tenant.Domain, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Tenant %s: %v", tenant.Domain, err))
		}
	}
}

func importBlueprints(client *AuthentikAPIClient, blueprints []Blueprint, options ImportOptions, result *ImportResult) {
	for _, blueprint := range blueprints {
		if options.DryRun {
			fmt.Printf("   [DRY RUN] Would import blueprint: %s\n", blueprint.Name)
			continue
		}

		exists, existingID := client.BlueprintExists(blueprint.Name)

		if exists && options.SkipExisting {
			fmt.Printf("   ⏭️  Skipping existing blueprint: %s\n", blueprint.Name)
			result.Skipped++
			continue
		}

		if exists && !options.UpdateExisting {
			fmt.Printf("   ⏭️  Blueprint exists: %s\n", blueprint.Name)
			result.Skipped++
			continue
		}

		var err error
		if exists {
			err = client.UpdateBlueprint(existingID, blueprint)
			if err == nil {
				fmt.Printf("    Updated blueprint: %s\n", blueprint.Name)
				result.Updated++
			}
		} else {
			err = client.CreateBlueprint(blueprint)
			if err == nil {
				fmt.Printf("    Created blueprint: %s\n", blueprint.Name)
				result.Created++
			}
		}

		if err != nil {
			fmt.Printf("    Failed to import blueprint %s: %v\n", blueprint.Name, err)
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("Blueprint %s: %v", blueprint.Name, err))
		}
	}
}

// Helper functions

func loadConfigFile(filename string) (*AuthentikConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config AuthentikConfig

	// Try to detect format
	if strings.HasSuffix(filename, ".json") || bytes.HasPrefix(data, []byte("{")) {
		err = json.Unmarshal(data, &config)
	} else {
		err = yaml.Unmarshal(data, &config)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	return &config, nil
}

func validateConfig(config *AuthentikConfig) (warnings []string, errors []string) {
	// Check metadata
	if config.Metadata.AuthentikVersion == "" {
		warnings = append(warnings, "No Authentik version information in metadata")
	}

	// Check for critical configurations
	hasRolesMapping := false
	for _, mapping := range config.PropertyMappings {
		if mapping.SAMLName == "Roles" {
			hasRolesMapping = true
			warnings = append(warnings, fmt.Sprintf("Found critical Roles mapping: %s", mapping.Name))
		}
	}

	if len(config.PropertyMappings) > 0 && !hasRolesMapping {
		warnings = append(warnings, "No 'Roles' property mapping found (may be needed for SSO)")
	}

	// Check for dependencies
	providerMap := make(map[string]bool)
	for _, provider := range config.Providers {
		providerMap[provider.PK] = true
	}

	for _, app := range config.Applications {
		if app.Provider != "" && !providerMap[app.Provider] {
			errors = append(errors, fmt.Sprintf("Application '%s' references non-existent provider: %s",
				app.Name, app.Provider))
		}
	}

	// Check flows and stages
	stageMap := make(map[string]bool)
	for _, stage := range config.Stages {
		stageMap[stage.PK] = true
	}

	for _, flow := range config.Flows {
		for _, stagePK := range flow.Stages {
			if !stageMap[stagePK] {
				warnings = append(warnings, fmt.Sprintf("Flow '%s' references non-existent stage: %s",
					flow.Name, stagePK))
			}
		}
	}

	return warnings, errors
}

func isVersionCompatible(source, target string) bool {
	// Simple version check - can be made more sophisticated
	// For now, just check major version
	sourceParts := strings.Split(source, ".")
	targetParts := strings.Split(target, ".")

	if len(sourceParts) == 0 || len(targetParts) == 0 {
		return true // Can't determine, assume compatible
	}

	// Check major version
	if sourceParts[0] != targetParts[0] {
		return false
	}

	return true
}

func loadMappingRules(filename string) (map[string]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	rules := make(map[string]string)
	if err := json.Unmarshal(data, &rules); err != nil {
		// Try YAML
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("failed to parse mapping rules: %w", err)
		}
	}

	return rules, nil
}

func applyMappingRules(mapping PropertyMapping, rules map[string]string) PropertyMapping {
	// Apply any transformation rules
	// This is a simplified example - can be extended
	for oldValue, newValue := range rules {
		mapping.Expression = strings.ReplaceAll(mapping.Expression, oldValue, newValue)
		if mapping.SAMLName == oldValue {
			mapping.SAMLName = newValue
		}
	}
	return mapping
}

func extractFullConfig(client *AuthentikAPIClient) *AuthentikConfig {
	// Extract full configuration from API
	config := &AuthentikConfig{
		Metadata: ConfigMetadata{
			ExportedAt: time.Now(),
			SourceURL:  client.BaseURL,
		},
	}

	// Get all resources
	config.Providers, _ = client.GetProviders(nil)
	config.Applications, _ = client.GetApplications(nil)
	config.PropertyMappings, _ = client.GetPropertyMappings()
	config.Flows, _ = client.GetFlows()
	config.Stages, _ = client.GetStages()
	config.Groups, _ = client.GetGroups()
	config.Policies, _ = client.GetPolicies()
	config.Certificates, _ = client.GetCertificates(false)
	config.Outposts, _ = client.GetOutposts()
	config.Tenants, _ = client.GetTenants()
	config.Blueprints, _ = client.GetBlueprints()

	return config
}

type ConfigComparison struct {
	Source       ConfigSummary `json:"source"`
	Target       ConfigSummary `json:"target"`
	OnlyInSource ConfigItems   `json:"only_in_source"`
	OnlyInTarget ConfigItems   `json:"only_in_target"`
	Modified     ConfigItems   `json:"modified"`
	Identical    ConfigItems   `json:"identical"`
}

type ConfigSummary struct {
	URL              string `json:"url,omitempty"`
	Version          string `json:"version"`
	ProviderCount    int    `json:"provider_count"`
	ApplicationCount int    `json:"application_count"`
	FlowCount        int    `json:"flow_count"`
	GroupCount       int    `json:"group_count"`
}

type ConfigItems struct {
	Providers    []string `json:"providers,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Flows        []string `json:"flows,omitempty"`
	Groups       []string `json:"groups,omitempty"`
}

func compareConfigurations(source, target *AuthentikConfig, detailed bool) ConfigComparison {
	comparison := ConfigComparison{
		Source: ConfigSummary{
			URL:              source.Metadata.SourceURL,
			Version:          source.Metadata.AuthentikVersion,
			ProviderCount:    len(source.Providers),
			ApplicationCount: len(source.Applications),
			FlowCount:        len(source.Flows),
			GroupCount:       len(source.Groups),
		},
		Target: ConfigSummary{
			URL:              target.Metadata.SourceURL,
			Version:          target.Metadata.AuthentikVersion,
			ProviderCount:    len(target.Providers),
			ApplicationCount: len(target.Applications),
			FlowCount:        len(target.Flows),
			GroupCount:       len(target.Groups),
		},
		OnlyInSource: ConfigItems{},
		OnlyInTarget: ConfigItems{},
		Modified:     ConfigItems{},
		Identical:    ConfigItems{},
	}

	// Compare providers
	sourceProviders := make(map[string]Provider)
	for _, p := range source.Providers {
		sourceProviders[p.Name] = p
	}

	targetProviders := make(map[string]Provider)
	for _, p := range target.Providers {
		targetProviders[p.Name] = p
	}

	for name := range sourceProviders {
		if _, exists := targetProviders[name]; !exists {
			comparison.OnlyInSource.Providers = append(comparison.OnlyInSource.Providers, name)
		} else if detailed {
			// Check if modified
			// Simplified - should deep compare
			comparison.Identical.Providers = append(comparison.Identical.Providers, name)
		}
	}

	for name := range targetProviders {
		if _, exists := sourceProviders[name]; !exists {
			comparison.OnlyInTarget.Providers = append(comparison.OnlyInTarget.Providers, name)
		}
	}

	// Similar comparisons for other resource types...

	return comparison
}

func printComparison(comp ConfigComparison) {
	fmt.Println("\n📊 Configuration Comparison:")
	fmt.Println(strings.Repeat("=", 50))

	fmt.Println("\n📌 Source:")
	fmt.Printf("   Version:      %s\n", comp.Source.Version)
	fmt.Printf("   Providers:    %d\n", comp.Source.ProviderCount)
	fmt.Printf("   Applications: %d\n", comp.Source.ApplicationCount)
	fmt.Printf("   Flows:        %d\n", comp.Source.FlowCount)
	fmt.Printf("   Groups:       %d\n", comp.Source.GroupCount)

	fmt.Println("\n📌 Target:")
	fmt.Printf("   Version:      %s\n", comp.Target.Version)
	fmt.Printf("   Providers:    %d\n", comp.Target.ProviderCount)
	fmt.Printf("   Applications: %d\n", comp.Target.ApplicationCount)
	fmt.Printf("   Flows:        %d\n", comp.Target.FlowCount)
	fmt.Printf("   Groups:       %d\n", comp.Target.GroupCount)

	if len(comp.OnlyInSource.Providers) > 0 {
		fmt.Println("\n➕ Only in Source:")
		fmt.Printf("   Providers: %v\n", comp.OnlyInSource.Providers)
	}

	if len(comp.OnlyInTarget.Providers) > 0 {
		fmt.Println("\n➖ Only in Target:")
		fmt.Printf("   Providers: %v\n", comp.OnlyInTarget.Providers)
	}
}

func getFlag(cmd *cobra.Command, name string) interface{} {
	// Helper to get flag value
	switch name {
	case "skip-existing", "update-existing", "dry-run", "validate-only", "force", "create-backup":
		val, _ := cmd.Flags().GetBool(name)
		return val
	case "map-file":
		val, _ := cmd.Flags().GetString(name)
		return val
	case "skip-types", "only-types":
		val, _ := cmd.Flags().GetStringSlice(name)
		return val
	default:
		return nil
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Add stub methods to AuthentikAPIClient for all the existence checks and create/update operations
// These would be implemented with actual API calls

func (c *AuthentikAPIClient) CertificateExists(name string) (bool, string) {
	// Implementation would check API
	return false, ""
}

func (c *AuthentikAPIClient) CreateCertificate(cert Certificate) error {
	// Implementation would call API
	return nil
}

func (c *AuthentikAPIClient) UpdateCertificate(id string, cert Certificate) error {
	// Implementation would call API
	return nil
}

// Similar methods for other resource types...
func (c *AuthentikAPIClient) PropertyMappingExists(name string) (bool, string)         { return false, "" }
func (c *AuthentikAPIClient) CreatePropertyMapping(m PropertyMapping) error            { return nil }
func (c *AuthentikAPIClient) UpdatePropertyMapping(id string, m PropertyMapping) error { return nil }

func (c *AuthentikAPIClient) FlowExists(slug string) (bool, string) { return false, "" }
func (c *AuthentikAPIClient) CreateFlow(f Flow) error               { return nil }
func (c *AuthentikAPIClient) UpdateFlow(id string, f Flow) error    { return nil }

func (c *AuthentikAPIClient) ProviderExists(name string) (bool, string)  { return false, "" }
func (c *AuthentikAPIClient) CreateProvider(p Provider) error            { return nil }
func (c *AuthentikAPIClient) UpdateProvider(id string, p Provider) error { return nil }

func (c *AuthentikAPIClient) ApplicationExists(slug string) (bool, string)     { return false, "" }
func (c *AuthentikAPIClient) CreateApplication(a Application) error            { return nil }
func (c *AuthentikAPIClient) UpdateApplication(id string, a Application) error { return nil }

func (c *AuthentikAPIClient) GroupExists(name string) (bool, string) { return false, "" }
func (c *AuthentikAPIClient) CreateGroup(g Group) error              { return nil }
func (c *AuthentikAPIClient) UpdateGroup(id string, g Group) error   { return nil }

func (c *AuthentikAPIClient) PolicyExists(name string) (bool, string) { return false, "" }
func (c *AuthentikAPIClient) CreatePolicy(p Policy) error             { return nil }
func (c *AuthentikAPIClient) UpdatePolicy(id string, p Policy) error  { return nil }

func (c *AuthentikAPIClient) StageExists(name string) (bool, string) { return false, "" }
func (c *AuthentikAPIClient) CreateStage(s Stage) error              { return nil }
func (c *AuthentikAPIClient) UpdateStage(id string, s Stage) error   { return nil }

func (c *AuthentikAPIClient) OutpostExists(name string) (bool, string) { return false, "" }
func (c *AuthentikAPIClient) CreateOutpost(o Outpost) error            { return nil }
func (c *AuthentikAPIClient) UpdateOutpost(id string, o Outpost) error { return nil }

func (c *AuthentikAPIClient) TenantExists(domain string) (bool, string) { return false, "" }
func (c *AuthentikAPIClient) CreateTenant(t Tenant) error               { return nil }
func (c *AuthentikAPIClient) UpdateTenant(id string, t Tenant) error    { return nil }

func (c *AuthentikAPIClient) BlueprintExists(name string) (bool, string)   { return false, "" }
func (c *AuthentikAPIClient) CreateBlueprint(b Blueprint) error            { return nil }
func (c *AuthentikAPIClient) UpdateBlueprint(id string, b Blueprint) error { return nil }
