package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi_config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewValidateCmd creates the validate command
func NewValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate Delphi pipeline configuration",
		Long: `Validate the complete Delphi pipeline configuration including:
- Database connectivity and schema
- Environment variables and LLM configuration
- SMTP and notification channel setup
- File paths and security settings
- Parser and Wazuh API configuration`,
	}

	cmd.AddCommand(NewConfigCmd())
	return cmd
}

// NewConfigCmd creates the config validation command
func NewConfigCmd() *cobra.Command {
	var (
		envFile    string
		outputJSON bool
		verbose    bool
		checkOnly  bool
	)

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Validate Delphi configuration and environment",
		Long: `Validates the complete Delphi pipeline configuration including database schema,
environment variables, notification channels, file paths, and external service connectivity.

This command performs comprehensive validation of all Delphi components and reports
errors, warnings, and informational messages about the configuration state.`,
		Example: `  # Validate current configuration
  eos delphi validate config

  # Load environment from custom file
  eos delphi validate config --env-file /opt/stackstorm/packs/delphi/.env

  # Output detailed JSON results
  eos delphi validate config --json --verbose

  # Check configuration without detailed output
  eos delphi validate config --check-only`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
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

	cmd.Flags().StringVar(&envFile, "env-file", "", "Load environment variables from file")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show detailed information messages")
	cmd.Flags().BoolVar(&checkOnly, "check-only", false, "Only show summary, suppress detailed output")

	return cmd
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
			Success   bool                              `json:"success"`
			Timestamp time.Time                         `json:"timestamp"`
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
		fmt.Println("🔍 Delphi Configuration Validator")
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
		fmt.Printf("\n⚠️  WARNINGS (%d):\n", len(summary.Warnings))
		for _, warn := range summary.Warnings {
			fmt.Printf("   • [%s] %s\n", warn.Source, warn.Message)
		}
	}

	// Show info messages if verbose
	if verbose && len(summary.Info) > 0 && !checkOnly {
		fmt.Printf("\n✅ SUCCESS (%d):\n", len(summary.Info))
		for _, info := range summary.Info {
			fmt.Printf("   • [%s] %s\n", info.Source, info.Message)
		}
	}

	// Summary
	if !checkOnly {
		fmt.Println("\n" + strings.Repeat("=", 50))
	}

	if summary.Success {
		fmt.Println("✅ ALL CHECKS PASSED - Delphi is ready for production!")
	} else if len(summary.Errors) == 0 {
		fmt.Println("⚠️  WARNINGS FOUND - Delphi should work but check warnings")
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