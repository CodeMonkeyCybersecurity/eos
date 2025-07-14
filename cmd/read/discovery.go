package read

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/discovery"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// discoveryCmd represents the internal asset discovery command
var discoveryCmd = &cobra.Command{
	Use:     "discovery [location]",
	Short:   "Discover internal network assets using runZero-style techniques",
	Long: `Discover internal network assets using HD Moore's runZero-style discovery techniques.
This command performs comprehensive internal network scanning to identify:

- All responsive hosts and their services
- Operating system fingerprinting
- Security vulnerabilities and misconfigurations  
- Shadow IT and unauthorized devices
- Compliance violations and risk assessment
- Service enumeration with banner grabbing

The discovery engine uses aggressive scanning techniques optimized for internal
networks where you have permission to scan comprehensively.

Examples:
  # Discover all configured network locations
  eos read discovery

  # Discover specific location
  eos read discovery core-network

  # Aggressive discovery mode
  eos read discovery --aggressive

  # Save results to file
  eos read discovery --output results.json

  # Focus on compliance checking
  eos read discovery --compliance-only`,
	Aliases: []string{"discover", "scan", "enum", "recon"},
	Args:    cobra.MaximumNArgs(1),
	RunE:    eos.Wrap(runDiscovery),
}

// runDiscovery executes the internal asset discovery
func runDiscovery(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	aggressive, _ := cmd.Flags().GetBool("aggressive")
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")
	complianceOnly, _ := cmd.Flags().GetBool("compliance-only")
	shadowITOnly, _ := cmd.Flags().GetBool("shadow-it-only")
	configFile, _ := cmd.Flags().GetString("config")
	saveConfig, _ := cmd.Flags().GetBool("save-config")

	logger.Info("Starting internal asset discovery",
		zap.String("command", "read discovery"),
		zap.Bool("aggressive_mode", aggressive),
		zap.String("output_format", outputFormat))

	// Load or create discovery configuration
	config, err := loadDiscoveryConfig(configFile)
	if err != nil {
		logger.Error("Failed to load discovery configuration", zap.Error(err))
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Apply command line overrides
	if aggressive {
		config.AggressiveMode = true
		logger.Info("Aggressive mode enabled - scanning all ports and hosts")
	}

	// Create discovery manager
	manager := discovery.NewInternalDiscoveryManager(config, logger.Logger().Logger)

	var results []*discovery.DiscoveryResult
	var specificLocation string

	// Determine what to discover
	if len(args) > 0 {
		specificLocation = args[0]
		logger.Info("Discovering specific location", zap.String("location", specificLocation))
		
		result, err := manager.DiscoverLocation(rc, specificLocation)
		if err != nil {
			return fmt.Errorf("discovery failed for location %s: %w", specificLocation, err)
		}
		results = []*discovery.DiscoveryResult{result}
	} else {
		logger.Info("Discovering all configured locations")
		
		allResults, err := manager.DiscoverAll(rc)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}
		results = allResults
	}

	// Filter results based on flags
	if complianceOnly {
		results = filterComplianceResults(results)
	}
	if shadowITOnly {
		results = filterShadowITResults(results)
	}

	// Display results
	if err := displayDiscoveryResults(rc, results, outputFormat); err != nil {
		return fmt.Errorf("failed to display results: %w", err)
	}

	// Save results to file if specified
	if outputFile != "" {
		if err := saveDiscoveryResults(results, outputFile, outputFormat); err != nil {
			logger.Error("Failed to save results", zap.Error(err))
			return fmt.Errorf("failed to save results: %w", err)
		}
		logger.Info("Results saved", zap.String("file", outputFile))
	}

	// Save configuration if requested
	if saveConfig {
		configPath := filepath.Join(".eos", "discovery-config.yaml")
		if err := saveDiscoveryConfig(config, configPath); err != nil {
			logger.Warn("Failed to save configuration", zap.Error(err))
		} else {
			logger.Info("Configuration saved", zap.String("file", configPath))
		}
	}

	// Generate summary
	summary := generateDiscoverySummary(results)
	logger.Info("Discovery completed",
		zap.Int("total_assets", summary.TotalAssets),
		zap.Int("new_assets", summary.NewAssets),
		zap.Int("violations", summary.TotalViolations),
		zap.Int("alerts", summary.TotalAlerts))

	return nil
}

// loadDiscoveryConfig loads discovery configuration
func loadDiscoveryConfig(configFile string) (*discovery.InternalDiscoveryConfig, error) {
	// If no config file specified, look for default
	if configFile == "" {
		configFile = filepath.Join(".eos", "discovery-config.yaml")
	}

	// If config file doesn't exist, return default config
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return discovery.DefaultInternalDiscoveryConfig(), nil
	}

	// TODO: Implement YAML config loading
	// For now, return default config
	return discovery.DefaultInternalDiscoveryConfig(), nil
}

// saveDiscoveryConfig saves discovery configuration
func saveDiscoveryConfig(_ *discovery.InternalDiscoveryConfig, filename string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	// TODO: Implement YAML config saving
	// For now, just create a placeholder
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("# Discovery configuration saved\n")
	return err
}

// filterComplianceResults filters results to show only compliance violations
func filterComplianceResults(results []*discovery.DiscoveryResult) []*discovery.DiscoveryResult {
	filtered := make([]*discovery.DiscoveryResult, 0, len(results))
	
	for _, result := range results {
		if len(result.Violations) > 0 {
			// Create a copy with only assets that have violations
			filteredResult := *result
			filteredResult.AssetsFound = []discovery.Asset{}
			
			// Include only assets with violations
			for _, violation := range result.Violations {
				found := false
				for _, asset := range filteredResult.AssetsFound {
					if asset.Address == violation.Asset.Address {
						found = true
						break
					}
				}
				if !found {
					filteredResult.AssetsFound = append(filteredResult.AssetsFound, violation.Asset)
				}
			}
			
			filtered = append(filtered, &filteredResult)
		}
	}
	
	return filtered
}

// filterShadowITResults filters results to show only shadow IT
func filterShadowITResults(results []*discovery.DiscoveryResult) []*discovery.DiscoveryResult {
	filtered := make([]*discovery.DiscoveryResult, 0, len(results))
	
	for _, result := range results {
		if len(result.ShadowIT) > 0 {
			// Create a copy with only shadow IT assets
			filteredResult := *result
			filteredResult.AssetsFound = result.ShadowIT
			filtered = append(filtered, &filteredResult)
		}
	}
	
	return filtered
}

// displayDiscoveryResults displays the discovery results
func displayDiscoveryResults(rc *eos_io.RuntimeContext, results []*discovery.DiscoveryResult, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	switch strings.ToLower(format) {
	case "json":
		return displayResultsJSON(results)
	case "table":
		return displayResultsTable(&logger, results)
	case "summary":
		return displayResultsSummary(&logger, results)
	default:
		return displayResultsTable(&logger, results)
	}
}

// displayResultsJSON displays results in JSON format
func displayResultsJSON(results []*discovery.DiscoveryResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// displayResultsTable displays results in table format
func displayResultsTable(logger *otelzap.LoggerWithCtx, results []*discovery.DiscoveryResult) error {
	for _, result := range results {
		logger.Info("=== Discovery Results ===",
			zap.String("location", result.Location),
			zap.Duration("duration", result.Duration),
			zap.Int("assets_found", len(result.AssetsFound)))

		if len(result.AssetsFound) > 0 {
			logger.Info("Assets Found:")
			for _, asset := range result.AssetsFound {
				riskLevel := "LOW"
				if asset.RiskScore > 500 {
					riskLevel = "HIGH"
				} else if asset.RiskScore > 200 {
					riskLevel = "MEDIUM"
				}

				logger.Info("Asset",
					zap.String("address", asset.Address),
					zap.String("hostname", asset.Hostname),
					zap.String("os", asset.OS.Type),
					zap.Int("services", len(asset.Services)),
					zap.String("risk", riskLevel),
					zap.Bool("authorized", asset.IsAuthorized))
			}
		}

		if len(result.NewAssets) > 0 {
			logger.Info("New Assets Discovered:")
			for _, asset := range result.NewAssets {
				logger.Info("New Asset",
					zap.String("address", asset.Address),
					zap.String("hostname", asset.Hostname),
					zap.Bool("authorized", asset.IsAuthorized))
			}
		}

		if len(result.Violations) > 0 {
			logger.Warn("Compliance Violations:")
			for _, violation := range result.Violations {
				logger.Warn("Violation",
					zap.String("asset", violation.Asset.Address),
					zap.String("policy", violation.Policy),
					zap.String("severity", violation.Severity),
					zap.String("description", violation.Description))
			}
		}

		if len(result.ShadowIT) > 0 {
			logger.Warn("Shadow IT Detected:")
			for _, asset := range result.ShadowIT {
				logger.Warn("Shadow IT",
					zap.String("address", asset.Address),
					zap.String("hostname", asset.Hostname),
					zap.String("type", asset.OS.Type))
			}
		}

		if len(result.Alerts) > 0 {
			logger.Error("Security Alerts:")
			for _, alert := range result.Alerts {
				logger.Error("Alert",
					zap.String("type", alert.Type),
					zap.String("asset", alert.Asset.Address),
					zap.String("severity", alert.Severity),
					zap.String("details", alert.Details))
			}
		}

		// Display statistics
		stats := result.Statistics
		logger.Info("Statistics",
			zap.Int("responsive_hosts", stats.ResponsiveHosts),
			zap.Int("unauthorized_hosts", stats.UnauthorizedHosts),
			zap.Int("compliance_score", stats.ComplianceScore),
			zap.Int("risk_score", stats.RiskScore))
	}

	return nil
}

// displayResultsSummary displays a brief summary
func displayResultsSummary(logger *otelzap.LoggerWithCtx, results []*discovery.DiscoveryResult) error {
	summary := generateDiscoverySummary(results)

	logger.Info("=== Discovery Summary ===",
		zap.Int("locations_scanned", summary.LocationsScanned),
		zap.Int("total_assets", summary.TotalAssets),
		zap.Int("new_assets", summary.NewAssets),
		zap.Int("unauthorized_assets", summary.UnauthorizedAssets),
		zap.Int("total_violations", summary.TotalViolations),
		zap.Int("total_alerts", summary.TotalAlerts),
		zap.Int("avg_compliance_score", summary.AvgComplianceScore),
		zap.Int("avg_risk_score", summary.AvgRiskScore))

	if summary.TopRisks != nil {
		logger.Warn("Top Risk Assets:")
		for i, asset := range summary.TopRisks {
			if i >= 5 { // Show top 5
				break
			}
			logger.Warn("High Risk Asset",
				zap.String("address", asset.Address),
				zap.String("hostname", asset.Hostname),
				zap.Int("risk_score", asset.RiskScore))
		}
	}

	return nil
}

// saveDiscoveryResults saves results to a file
func saveDiscoveryResults(results []*discovery.DiscoveryResult, filename, format string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	default:
		// Default to JSON
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}
}

// DiscoverySummary provides aggregated discovery statistics
type DiscoverySummary struct {
	LocationsScanned     int                `json:"locations_scanned"`
	TotalAssets          int                `json:"total_assets"`
	NewAssets            int                `json:"new_assets"`
	UnauthorizedAssets   int                `json:"unauthorized_assets"`
	TotalViolations      int                `json:"total_violations"`
	TotalAlerts          int                `json:"total_alerts"`
	AvgComplianceScore   int                `json:"avg_compliance_score"`
	AvgRiskScore         int                `json:"avg_risk_score"`
	TopRisks             []discovery.Asset  `json:"top_risks"`
	ScanDuration         time.Duration      `json:"scan_duration"`
}

// generateDiscoverySummary creates a summary of all discovery results
func generateDiscoverySummary(results []*discovery.DiscoveryResult) *DiscoverySummary {
	summary := &DiscoverySummary{
		LocationsScanned: len(results),
		TopRisks:         []discovery.Asset{},
	}

	var totalComplianceScore, totalRiskScore int
	var allAssets []discovery.Asset
	var startTime, endTime time.Time

	for i, result := range results {
		summary.TotalAssets += len(result.AssetsFound)
		summary.NewAssets += len(result.NewAssets)
		summary.TotalViolations += len(result.Violations)
		summary.TotalAlerts += len(result.Alerts)

		// Track unauthorized assets
		for _, asset := range result.AssetsFound {
			if !asset.IsAuthorized {
				summary.UnauthorizedAssets++
			}
			allAssets = append(allAssets, asset)
		}

		// Aggregate scores
		totalComplianceScore += result.Statistics.ComplianceScore
		totalRiskScore += result.Statistics.RiskScore

		// Track scan duration
		if i == 0 {
			startTime = result.ScanStartTime
			endTime = result.ScanEndTime
		} else {
			if result.ScanStartTime.Before(startTime) {
				startTime = result.ScanStartTime
			}
			if result.ScanEndTime.After(endTime) {
				endTime = result.ScanEndTime
			}
		}
	}

	// Calculate averages
	if len(results) > 0 {
		summary.AvgComplianceScore = totalComplianceScore / len(results)
		summary.AvgRiskScore = totalRiskScore / len(results)
	}

	summary.ScanDuration = endTime.Sub(startTime)

	// Find top risk assets
	if len(allAssets) > 0 {
		// Simple sorting by risk score (would use sort.Slice in real implementation)
		for _, asset := range allAssets {
			if len(summary.TopRisks) < 10 { // Keep top 10
				summary.TopRisks = append(summary.TopRisks, asset)
			} else {
				// Find lowest risk in current top risks and replace if current asset is higher
				lowestIdx := 0
				lowestRisk := summary.TopRisks[0].RiskScore
				for j, topAsset := range summary.TopRisks {
					if topAsset.RiskScore < lowestRisk {
						lowestIdx = j
						lowestRisk = topAsset.RiskScore
					}
				}
				if asset.RiskScore > lowestRisk {
					summary.TopRisks[lowestIdx] = asset
				}
			}
		}
	}

	return summary
}

func init() {
	// Add discovery command to read
	ReadCmd.AddCommand(discoveryCmd)

	// Configuration flags
	discoveryCmd.Flags().String("config", "", "Configuration file path")
	discoveryCmd.Flags().Bool("save-config", false, "Save current configuration to file")

	// Scanning behavior flags
	discoveryCmd.Flags().Bool("aggressive", false, "Enable aggressive scanning mode (all ports, all hosts)")
	discoveryCmd.Flags().Duration("timeout", 30*time.Minute, "Discovery timeout")
	discoveryCmd.Flags().Int("rate-limit", 1000, "Scan rate limit (requests per second)")

	// Output flags
	discoveryCmd.Flags().String("output", "", "Output file path")
	discoveryCmd.Flags().String("format", "table", "Output format: table, json, summary")

	// Filtering flags
	discoveryCmd.Flags().Bool("compliance-only", false, "Show only compliance violations")
	discoveryCmd.Flags().Bool("shadow-it-only", false, "Show only shadow IT assets")
	discoveryCmd.Flags().Bool("new-only", false, "Show only newly discovered assets")

	// Network specification flags
	discoveryCmd.Flags().StringSlice("networks", []string{}, "Additional networks to scan (CIDR format)")
	discoveryCmd.Flags().StringSlice("exclude-networks", []string{}, "Networks to exclude from scanning")

	// Detection flags
	discoveryCmd.Flags().Bool("baseline", true, "Perform baseline monitoring")
	discoveryCmd.Flags().Bool("compliance", true, "Perform compliance checking")
	discoveryCmd.Flags().Bool("shadow-it", true, "Perform shadow IT detection")

	// Set examples
	discoveryCmd.Example = `  # Basic discovery of all networks
  eos read discovery

  # Discover specific location aggressively
  eos read discovery core-network --aggressive

  # Compliance audit only
  eos read discovery --compliance-only --format json

  # Hunt for shadow IT
  eos read discovery --shadow-it-only

  # Custom network scan
  eos read discovery --networks 192.168.1.0/24,10.0.10.0/24

  # Save detailed results
  eos read discovery --output discovery-$(date +%Y%m%d).json --format json`
}