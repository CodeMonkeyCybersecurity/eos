package env

import (
	"github.com/spf13/cobra"
)

// EnvCmd represents the env command
var EnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage deployment environments",
	Long: `Manage deployment environments for the EOS CI/CD system.

Environments provide isolated contexts for deploying applications across different
stages of your development lifecycle (development, staging, production, etc.).

Each environment contains:
- Infrastructure configuration (Nomad, Consul, Vault, Terraform)
- Deployment policies and resource limits
- Security and compliance settings
- Monitoring and alerting configuration

Environment management follows the assessment→intervention→evaluation pattern
to ensure reliable environment operations.

Available Commands:
  list     List all environments
  show     Show detailed environment information
  use      Switch to a different environment
  apply    Create or update an environment from configuration
  create   Create a new environment interactively
  update   Update an existing environment
  delete   Delete an environment

Examples:
  # List all environments
  eos env list

  # Show current environment details
  eos env show

  # Switch to production environment
  eos env use production

  # Create environment from config file
  eos env apply staging --config environments/staging.yaml

  # Show environment with detailed information
  eos env show production --detailed`,
	Aliases: []string{"environment", "environments"},
}

func init() {
	// This function will be called by the root command to register this command
}