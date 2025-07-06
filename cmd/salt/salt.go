// cmd/salt/salt.go
package salt

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Global flags for Salt commands
var (
	saltURL       string
	saltUsername  string
	saltPassword  string
	saltEauth     string
	saltTimeout   int
	saltRetries   int
	jsonOutput    bool
	dryRun        bool
	concurrent    int
	batch         string
	targetType    string
	environment   string
)

// SaltCmd represents the salt command
var SaltCmd = &cobra.Command{
	Use:   "salt",
	Short: "SaltStack orchestration and management",
	Long: `Salt provides SaltStack orchestration and management capabilities.

This command suite integrates deeply with SaltStack as the primary orchestration
layer for all infrastructure-as-code functionality, especially for coordinating
HashiCorp tools like Vault, Terraform, Consul, Nomad, and Packer.

The Salt commands provide direct access to Salt API functionality as well as
high-level orchestration workflows that combine multiple tools and operations.

Examples:
  eos salt ping '*'                    # Ping all minions
  eos salt run 'web*' test.ping       # Run test.ping on web servers
  eos salt state 'db*' mysql.user     # Apply MySQL user state to database servers
  eos salt orchestrate vault-setup    # Run Vault setup orchestration
  eos salt workflow deploy-app        # Execute application deployment workflow
  
Configuration:
  Set Salt API connection details via flags or environment variables:
  --salt-url, --salt-username, --salt-password, --salt-eauth
  
  Or use environment variables:
  SALT_API_URL, SALT_USERNAME, SALT_PASSWORD, SALT_EAUTH`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		if len(args) == 0 {
			logger.Info("Salt command help requested")
			return cmd.Help()
		}
		
		logger.Info("Salt command executed with invalid arguments",
			zap.Strings("args", args))
		
		return fmt.Errorf("invalid salt command - use 'eos salt --help' for usage")
	}),
}

func init() {
	// Add persistent flags for all salt subcommands
	SaltCmd.PersistentFlags().StringVar(&saltURL, "salt-url", "", "Salt API URL (env: SALT_API_URL)")
	SaltCmd.PersistentFlags().StringVar(&saltUsername, "salt-username", "", "Salt API username (env: SALT_USERNAME)")
	SaltCmd.PersistentFlags().StringVar(&saltPassword, "salt-password", "", "Salt API password (env: SALT_PASSWORD)")
	SaltCmd.PersistentFlags().StringVar(&saltEauth, "salt-eauth", "pam", "Salt authentication backend (env: SALT_EAUTH)")
	SaltCmd.PersistentFlags().IntVar(&saltTimeout, "salt-timeout", 30, "Salt API timeout in seconds")
	SaltCmd.PersistentFlags().IntVar(&saltRetries, "salt-retries", 3, "Salt API retry attempts")
	SaltCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	SaltCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Test mode - don't make actual changes")
	SaltCmd.PersistentFlags().IntVar(&concurrent, "concurrent", 0, "Maximum concurrent executions")
	SaltCmd.PersistentFlags().StringVar(&batch, "batch", "", "Batch execution size")
	SaltCmd.PersistentFlags().StringVar(&targetType, "target-type", "glob", "Target type (glob, pcre, list, grain, pillar, nodegroup, range, compound, ipcidr)")
	SaltCmd.PersistentFlags().StringVar(&environment, "environment", "base", "Salt environment")

	// Add subcommands
	SaltCmd.AddCommand(SaltPingCmd)
	SaltCmd.AddCommand(SaltRunCmd)
	SaltCmd.AddCommand(SaltStateCmd)
	SaltCmd.AddCommand(SaltOrchestrateCmd)
	SaltCmd.AddCommand(SaltJobCmd)
	SaltCmd.AddCommand(SaltMinionCmd)
	SaltCmd.AddCommand(SaltKeyCmd)
	// TODO: Add remaining salt subcommands
	// SaltCmd.AddCommand(SaltWorkflowCmd)
	// SaltCmd.AddCommand(SaltPillarCmd)
	// SaltCmd.AddCommand(SaltGrainCmd)
	// SaltCmd.AddCommand(SaltFileCmd)
	// SaltCmd.AddCommand(SaltStatusCmd)
	// SaltCmd.AddCommand(SaltEventCmd)
}

// getSaltConfig creates Salt client configuration from flags and environment
func getSaltConfig() (*SaltClientConfig, error) {
	config := &SaltClientConfig{
		URL:      saltURL,
		Username: saltUsername,
		Password: saltPassword,
		Eauth:    saltEauth,
		Timeout:  saltTimeout,
		Retries:  saltRetries,
	}

	// Check environment variables if flags not set
	if config.URL == "" {
		config.URL = getEnvVar("SALT_API_URL", "")
	}
	if config.Username == "" {
		config.Username = getEnvVar("SALT_USERNAME", "")
	}
	if config.Password == "" {
		config.Password = getEnvVar("SALT_PASSWORD", "")
	}
	if config.Eauth == "pam" {
		config.Eauth = getEnvVar("SALT_EAUTH", "pam")
	}

	// Validate required configuration
	if config.URL == "" {
		return nil, fmt.Errorf("Salt API URL is required (use --salt-url or SALT_API_URL)")
	}
	if config.Username == "" {
		return nil, fmt.Errorf("Salt API username is required (use --salt-username or SALT_USERNAME)")
	}
	if config.Password == "" {
		return nil, fmt.Errorf("Salt API password is required (use --salt-password or SALT_PASSWORD)")
	}

	return config, nil
}

// SaltClientConfig represents Salt client configuration for commands
type SaltClientConfig struct {
	URL      string
	Username string
	Password string
	Eauth    string
	Timeout  int
	Retries  int
}

// getEnvVar gets environment variable with default value
func getEnvVar(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}