package deploy

import (
	"github.com/spf13/cobra"
)

// DeployCmd represents the deploy command
var DeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy applications and services to various environments",
	Long: `Deploy applications and services with advanced deployment strategies and comprehensive
orchestration following the Salt → Terraform → Nomad hierarchy.

The deployment system provides sophisticated deployment strategies, progressive rollouts,
comprehensive health checking, and automated rollback capabilities. All deployments follow
the assessment→intervention→evaluation pattern to ensure reliable and safe deployments.

Deployment features include:
- Multiple deployment strategies (rolling, blue-green, canary, immutable)
- Environment-aware deployments with validation and approval workflows
- Comprehensive health checking and smoke testing
- Automated rollback on failure with configurable thresholds
- Integration with HashiCorp stack (Nomad, Consul, Vault)
- Real-time deployment monitoring and progress tracking
- Deployment history and audit trails

Available Commands:
  app          Deploy a specific application
  service      Deploy a service component
  stack        Deploy multiple components as a stack
  rollback     Rollback a previous deployment
  status       Check deployment status (alias to read deployment-status)

Deployment Strategies:
  rolling      Rolling deployment with configurable batch sizes
  blue-green   Blue-green deployment with traffic switching
  canary       Canary deployment with gradual traffic shifting
  immutable    Immutable infrastructure replacement

Examples:
  # Rolling deployment to staging
  eos deploy app helen --environment staging

  # Blue-green deployment to production
  eos deploy app helen --environment production --strategy blue-green

  # Canary deployment with 10% initial traffic
  eos deploy app api --environment production --strategy canary --canary-percentage 10

  # Deploy entire stack
  eos deploy stack webapp --environment staging

Security and Compliance:
- All deployments require proper environment access
- Production deployments enforce approval workflows
- Comprehensive audit logging for compliance
- Automated security scanning and validation`,
	Aliases: []string{"deployment"},
}

func init() {
	// This function will be called by the root command to register this command
}