// cmd/delphi/list/list.go

package list

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi_config"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap" // Make sure zap is imported for structured logging
)

// DelphiCmd represents the 'list' command for Delphi (Wazuh) data.
var DelphiCmd = &cobra.Command{
	Use:   "list", // Changed to "list"
	Short: "List Delphi (Wazuh) resources",
	Long: `The 'list' command provides functionality to enumerate various resources within your Delphi (Wazuh) instance.

Use this command to retrieve lists of agents, rules, groups, and other relevant data.

Subcommands are required to specify which type of resource to list.`,
	Aliases: []string{"ls", "show"}, // Common aliases for 'list'
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// If this command is meant to be a parent (requiring subcommands like 'eos delphi list agents'),
		// then its RunE should indicate missing subcommand and display its own help.
		otelzap.Ctx(rc.Ctx).Info("Command called without subcommand",
			zap.String("command", "eos delphi list"),
		)

		fmt.Println(" Missing subcommand for 'eos delphi list'.")
		fmt.Println("  Run `eos delphi list --help` to see available options for listing resources.")
		_ = cmd.Help() // Print built-in help for 'list' command
		return nil
	}),
}

func init() {
	// You would typically add subcommands specific to 'list' here.
	// For example, if you want 'eos delphi list agents' or 'eos delphi list rules':
	// ListCmd.AddCommand(NewListAgentsCmd()) // Assuming you have an agents subcommand
	// ListCmd.AddCommand(NewListRulesCmd())   // Assuming you have a rules subcommand

	// Flags for listing commands might include:
	// ListCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "Filter results by a specific criteria")
	// ListCmd.PersistentFlags().IntVarP(&limit, "limit", "l", 100, "Maximum number of items to return")
	// ListCmd.PersistentFlags().IntVarP(&offset, "offset", "o", 0, "Starting offset for pagination")
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check Python dependencies required by Delphi services",
	Long: `Check if all Python packages required by the Delphi security monitoring services are installed.

This command verifies the following dependencies:
- psycopg2-binary (PostgreSQL adapter)
- python-dotenv (Environment variable management)
- requests (HTTP requests library)
- pytz (Timezone handling)
- ipwhois (IP WHOIS lookup functionality)
- pyyaml (YAML parsing for configuration)

If any dependencies are missing, use 'eos delphi services install' to install them.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Checking Python dependencies for Delphi services")

		// Check Python and pip availability
		pythonCmd := exec.Command("python3", "--version")
		pythonOutput, err := pythonCmd.Output()
		if err != nil {
			logger.Error(" Python 3 not found", zap.Error(err))
			return err
		}

		pythonVersion := strings.TrimSpace(string(pythonOutput))
		logger.Info("🐍 Python version", zap.String("version", pythonVersion))

		pip3Path, err := exec.LookPath("pip3")
		if err != nil {
			logger.Error(" pip3 not found", zap.Error(err))
			return err
		}

		logger.Info(" pip3 available", zap.String("path", pip3Path))

		// Define required packages and their import names
		packages := map[string]string{
			"psycopg2-binary": "psycopg2",
			"python-dotenv":   "dotenv",
			"requests":        "requests",
			"pytz":            "pytz",
			"ipwhois":         "ipwhois",
			"pyyaml":          "yaml",
		}

		logger.Info(" Checking package availability",
			zap.Int("total_packages", len(packages)))

		var missingPackages []string
		var installedPackages []string

		for pkg, importName := range packages {
			// Try to import the package
			importCmd := exec.Command("python3", "-c", "import "+importName)
			if err := importCmd.Run(); err != nil {
				logger.Warn(" Package not available",
					zap.String("package", pkg),
					zap.String("import_name", importName))
				missingPackages = append(missingPackages, pkg)
			} else {
				logger.Info(" Package available",
					zap.String("package", pkg),
					zap.String("import_name", importName))
				installedPackages = append(installedPackages, pkg)
			}
		}

		// Show summary
		logger.Info(" Dependency check summary",
			zap.Int("total", len(packages)),
			zap.Int("installed", len(installedPackages)),
			zap.Int("missing", len(missingPackages)))

		if len(installedPackages) > 0 {
			logger.Info(" Installed packages",
				zap.Strings("packages", installedPackages))
		}

		if len(missingPackages) > 0 {
			logger.Warn("Missing packages",
				zap.Strings("packages", missingPackages))
			logger.Info(" To install missing packages, run:")
			logger.Info("   eos delphi services install")

			// Also show manual installation command
			logger.Info(" Or install manually with:")
			logger.Info("   sudo pip3 install " + strings.Join(missingPackages, " "))
		} else {
			logger.Info(" All Python dependencies are installed!")
			logger.Info(" Next steps:")
			logger.Info("   1. Ensure PostgreSQL is running")
			logger.Info("   2. Configure environment variables")
			logger.Info("   3. Check service status: eos delphi services status --all")
		}

		// Additional system checks
		logger.Info(" Additional system checks")

		// Check PostgreSQL client
		psqlCmd := exec.Command("psql", "--version")
		if psqlOutput, err := psqlCmd.Output(); err != nil {
			logger.Warn("PostgreSQL client (psql) not found",
				zap.Error(err))
		} else {
			logger.Info(" PostgreSQL client available",
				zap.String("version", strings.TrimSpace(string(psqlOutput))))
		}

		// Check if systemctl is available (for service management)
		systemctlCmd := exec.Command("systemctl", "--version")
		if systemctlOutput, err := systemctlCmd.Output(); err != nil {
			logger.Warn("systemctl not found - service management may not work",
				zap.Error(err))
		} else {
			systemctlVersion := strings.Split(string(systemctlOutput), "\n")[0]
			logger.Info(" systemctl available",
				zap.String("version", strings.TrimSpace(systemctlVersion)))
		}

		return nil
	}),
}

func init() {
	delphiConfigValidateCmd.Flags().String("env-file", "", "Load environment variables from file")
	delphiConfigValidateCmd.Flags().Bool("json", false, "Output results in JSON format")
	delphiConfigValidateCmd.Flags().Bool("verbose", false, "Show detailed information messages")
	delphiConfigValidateCmd.Flags().Bool("check-only", false, "Only show summary, suppress detailed output")

	delphiValidateCmd.AddCommand(delphiConfigValidateCmd)

	ListCmd.AddCommand(delphiValidateCmd)
	ListCmd.AddCommand(delphiConfigValidateCmd)
	ListCmd.AddCommand(checkCmd)
}

var delphiValidateCmd = &cobra.Command{
	Use:   "delphi-validate",
	Aliases: []string{"delphi-check", "validate-delphi", "delphi-validation"},
	Short: "Validate Delphi pipeline configuration",
	Long: `Validate the complete Delphi pipeline configuration including:
- Database connectivity and schema
- Environment variables and LLM configuration
- SMTP and notification channel setup
- File paths and security settings
- Parser and Wazuh API configuration

Examples:
  eos list delphi-validate
  eos list delphi-validate --help`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Delphi validation - use subcommands for specific validation")
		return cmd.Help()
	}),
}

var delphiConfigValidateCmd = &cobra.Command{
	Use:   "delphi-config-validate",
	Aliases: []string{"delphi-config", "validate-delphi-config"},
	Short: "Validate Delphi configuration and environment",
	Long: `Validates the complete Delphi pipeline configuration including database schema,
environment variables, notification channels, file paths, and external service connectivity.

This command performs comprehensive validation of all Delphi components and reports
errors, warnings, and informational messages about the configuration state.`,
	Example: `  # Validate current configuration
  eos list delphi-config-validate

  # Load environment from custom file
  eos list delphi-config-validate --env-file /opt/stackstorm/packs/delphi/.env

  # Output detailed JSON results
  eos list delphi-config-validate --json --verbose

  # Check configuration without detailed output
  eos list delphi-config-validate --check-only`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		envFile, _ := cmd.Flags().GetString("env-file")
		outputJSON, _ := cmd.Flags().GetBool("json")
		verbose, _ := cmd.Flags().GetBool("verbose")
		checkOnly, _ := cmd.Flags().GetBool("check-only")

		logger.Info("Starting Delphi configuration validation",
			zap.String("env_file", envFile),
			zap.Bool("json_output", outputJSON),
			zap.Bool("verbose", verbose),
			zap.Bool("check_only", checkOnly))

		// Load environment file if specified
		if envFile != "" {
			if err := loadEnvFile(envFile); err != nil {
				logger.Warn("Failed to load environment file",
					zap.String("file", envFile),
					zap.Error(err))
			} else {
				logger.Info("Loaded environment file", zap.String("file", envFile))
			}
		}

		// Create configuration from environment and defaults
		config := createConfigFromEnvironment()

		// Create validator and run validation
		validator := delphi_config.NewConfigValidator(config)
		summary := validator.ValidateAll()

		// Output results
		if outputJSON {
			return outputJSONResults(summary, verbose)
		} else {
			return outputTextResults(summary, verbose, checkOnly)
		}
	}),
}

// loadEnvFile loads environment variables from a file
func loadEnvFile(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Remove quotes if present
			if len(value) >= 2 &&
				((value[0] == '"' && value[len(value)-1] == '"') ||
					(value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}

			os.Setenv(key, value)
		}
	}

	return nil
}

// createConfigFromEnvironment creates a DelphiConfig from environment variables
func createConfigFromEnvironment() *delphi_config.DelphiConfig {
	config := delphi_config.DefaultDelphiConfig()

	// Database configuration
	config.Database.DSN = os.Getenv("PG_DSN")

	// LLM configuration
	config.LLM.APIKey = os.Getenv("OPENAI_API_KEY")
	if config.LLM.APIKey == "" {
		config.LLM.APIKey = os.Getenv("AZURE_OPENAI_API_KEY")
		config.LLM.EndpointURL = os.Getenv("ENDPOINT_URL")
		config.LLM.DeploymentName = os.Getenv("DEPLOYMENT_NAME")
		config.LLM.Provider = "azure"
	} else {
		config.LLM.Provider = "openai"
	}

	// SMTP configuration
	config.SMTP.Host = os.Getenv("SMTP_HOST")
	config.SMTP.Username = os.Getenv("SMTP_USER")
	config.SMTP.Password = os.Getenv("SMTP_PASS")
	config.SMTP.FromEmail = os.Getenv("SMTP_FROM")
	config.SMTP.FromName = os.Getenv("SMTP_FROM_NAME")

	if port := os.Getenv("SMTP_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.SMTP.Port = p
		}
	}

	// Security configuration
	config.Security.WebhookAuthToken = os.Getenv("WEBHOOK_AUTH_TOKEN")

	// Wazuh configuration
	config.Wazuh.APIURL = os.Getenv("WAZUH_API_URL")
	config.Wazuh.APIUser = os.Getenv("WAZUH_API_USER")
	config.Wazuh.APIPassword = os.Getenv("WAZUH_API_PASSWD")

	// File paths
	if promptFile := os.Getenv("PROMPT_FILE"); promptFile != "" {
		config.FilePaths.PromptFile = promptFile
	}
	if promptDir := os.Getenv("PROMPT_DIR"); promptDir != "" {
		config.FilePaths.PromptDirectory = promptDir
	}
	if templatePath := os.Getenv("DELPHI_EMAIL_TEMPLATE_PATH"); templatePath != "" {
		config.FilePaths.EmailTemplatePath = templatePath
	}

	// Parser configuration
	if threshold := os.Getenv("PARSER_FAILURE_THRESHOLD"); threshold != "" {
		if t, err := strconv.Atoi(threshold); err == nil {
			config.Parser.FailureThreshold = t
		}
	}
	if timeout := os.Getenv("PARSER_FAILURE_TIMEOUT"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil {
			config.Parser.FailureTimeout = time.Duration(t) * time.Second
		}
	}
	if abTest := os.Getenv("PARSER_AB_TEST_PERCENTAGE"); abTest != "" {
		if a, err := strconv.Atoi(abTest); err == nil {
			config.Parser.ABTestPercentage = a
		}
	}

	return config
}

// outputJSONResults outputs validation results in JSON format
func outputJSONResults(summary *delphi_config.ValidationSummary, verbose bool) error {
	if !verbose {
		// Simplified output without info messages
		simplified := struct {
			Success   bool                             `json:"success"`
			Timestamp time.Time                        `json:"timestamp"`
			Errors    []delphi_config.ValidationResult `json:"errors"`
			Warnings  []delphi_config.ValidationResult `json:"warnings"`
		}{
			Success:   summary.Success,
			Timestamp: summary.Timestamp,
			Errors:    summary.Errors,
			Warnings:  summary.Warnings,
		}

		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(simplified)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

// outputTextResults outputs validation results in human-readable format
func outputTextResults(summary *delphi_config.ValidationSummary, verbose, checkOnly bool) error {
	if !checkOnly {
		fmt.Println(" Delphi Configuration Validator")
		fmt.Println(strings.Repeat("=", 50))
	}

	// Show errors
	if len(summary.Errors) > 0 {
		if !checkOnly {
			fmt.Printf("\n❌ ERRORS (%d):\n", len(summary.Errors))
			for _, err := range summary.Errors {
				fmt.Printf("   • [%s] %s\n", err.Source, err.Message)
			}
		}
	}

	// Show warnings
	if len(summary.Warnings) > 0 && !checkOnly {
		fmt.Printf("\nWARNINGS (%d):\n", len(summary.Warnings))
		for _, warn := range summary.Warnings {
			fmt.Printf("   • [%s] %s\n", warn.Source, warn.Message)
		}
	}

	// Show info messages if verbose
	if verbose && len(summary.Info) > 0 && !checkOnly {
		fmt.Printf("\n SUCCESS (%d):\n", len(summary.Info))
		for _, info := range summary.Info {
			fmt.Printf("   • [%s] %s\n", info.Source, info.Message)
		}
	}

	// Summary
	if !checkOnly {
		fmt.Println("\n" + strings.Repeat("=", 50))
	}

	if summary.Success {
		fmt.Println(" ALL CHECKS PASSED - Delphi is ready for production!")
	} else if len(summary.Errors) == 0 {
		fmt.Println("WARNINGS FOUND - Delphi should work but check warnings")
	} else {
		fmt.Println("❌ CRITICAL ERRORS FOUND - Fix errors before running Delphi")

		// Return error exit code for CI/CD integration
		os.Exit(1)
	}

	if !checkOnly {
		fmt.Println(strings.Repeat("=", 50))
	}

	return nil
}
