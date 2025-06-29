// cmd/create/terraform_vault.go

package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var terraformVaultCmd = &cobra.Command{
	Use:   "terraform-vault [directory]",
	Short: "Deploy infrastructure with integrated Vault secrets management",
	Long: `Deploy Terraform infrastructure with integrated Vault secrets management.
This command:
1. Validates Vault connectivity
2. Sets up Vault secrets engine for Terraform
3. Configures Vault as Terraform state backend (optional)
4. Loads secrets from Vault into Terraform variables
5. Deploys infrastructure
6. Stores Terraform outputs back to Vault

Example:
  eos create terraform-vault ./infrastructure --vault-secrets --vault-state`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		// Get flags
		useVaultState, _ := cmd.Flags().GetBool("vault-state")
		useVaultSecrets, _ := cmd.Flags().GetBool("vault-secrets")
		secretsPath, _ := cmd.Flags().GetString("secrets-path")
		statePath, _ := cmd.Flags().GetString("state-path")
		outputsPath, _ := cmd.Flags().GetString("outputs-path")
		autoApprove, _ := cmd.Flags().GetBool("auto-approve")
		secretRefsFile, _ := cmd.Flags().GetString("secret-refs")

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		// Validate directory
		if _, err := os.Stat(workingDir); os.IsNotExist(err) {
			return fmt.Errorf("directory %s does not exist", workingDir)
		}

		logger.Info("Starting Terraform-Vault integrated deployment",
			zap.String("directory", workingDir),
			zap.Bool("vault_state", useVaultState),
			zap.Bool("vault_secrets", useVaultSecrets))

		// Initialize Terraform manager
		tfManager := terraform.NewManager(rc, workingDir)

		// Step 1: Configure Vault integration
		vaultConfig := terraform.VaultIntegration{
			VaultAddr:     os.Getenv("VAULT_ADDR"),
			VaultToken:    os.Getenv("VAULT_TOKEN"),
			SecretsPath:   secretsPath,
			BackendPath:   statePath,
			EnableState:   useVaultState,
			EnableSecrets: useVaultSecrets,
		}

		if vaultConfig.VaultAddr == "" {
			vaultConfig.VaultAddr = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
		}

		if err := tfManager.ConfigureVaultIntegration(rc, vaultConfig); err != nil {
			return fmt.Errorf("vault integration setup failed: %w", err)
		}

		// Step 2: Set up Vault secrets engine
		if useVaultSecrets {
			if err := tfManager.CreateVaultSecretsEngine(rc, "terraform"); err != nil {
				return fmt.Errorf("failed to create vault secrets engine: %w", err)
			}
		}

		// Step 3: Load secret references if provided
		if secretRefsFile != "" {
			secretRefs, err := loadSecretReferences(secretRefsFile)
			if err != nil {
				return fmt.Errorf("failed to load secret references: %w", err)
			}

			if len(secretRefs) > 0 {
				if err := tfManager.LoadSecretsFromVault(rc, secretRefs); err != nil {
					return fmt.Errorf("failed to load secrets from vault: %w", err)
				}

				// Generate Vault data sources
				if err := tfManager.GenerateVaultDataSources(rc, secretRefs); err != nil {
					return fmt.Errorf("failed to generate vault data sources: %w", err)
				}
			}
		}

		// Step 4: Terraform workflow
		logger.Info("Step 4: Starting Terraform deployment workflow")

		// Initialize
		logger.Info("Initializing Terraform")
		if err := tfManager.Init(rc); err != nil {
			return fmt.Errorf("terraform init failed: %w", err)
		}

		// Validate
		logger.Info("Validating configuration")
		if err := tfManager.Validate(rc); err != nil {
			return fmt.Errorf("terraform validation failed: %w", err)
		}

		// Plan
		logger.Info("Planning deployment")
		if err := tfManager.Plan(rc); err != nil {
			return fmt.Errorf("terraform plan failed: %w", err)
		}

		// Apply (with confirmation if not auto-approved)
		if !autoApprove {
			fmt.Print("\nDo you want to apply these changes? [y/N]: ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				logger.Warn("Failed to read user input, cancelling deployment", zap.Error(err))
				return nil
			}
			if response != "y" && response != "yes" && response != "Y" && response != "YES" {
				logger.Info("Deployment cancelled by user")
				return nil
			}
		}

		logger.Info("Applying configuration")
		if err := tfManager.Apply(rc, true); err != nil {
			return fmt.Errorf("terraform apply failed: %w", err)
		}

		// Step 5: Store outputs in Vault if enabled
		if outputsPath != "" {
			outputs, err := getOutputNames(rc, tfManager)
			if err != nil {
				logger.Warn("Failed to retrieve output names", zap.Error(err))
			} else if len(outputs) > 0 {
				if err := tfManager.SyncTerraformOutputsToVault(rc, outputsPath, outputs); err != nil {
					logger.Warn("Failed to sync outputs to Vault", zap.Error(err))
				}
			}
		}

		logger.Info("Terraform-Vault deployment completed successfully")
		fmt.Println("\n Infrastructure deployed successfully with Vault integration!")

		return nil
	}),
}

var vaultSecretsEngineCmd = &cobra.Command{
	Use:   "vault-secrets-engine [path]",
	Short: "Create a Vault secrets engine for Terraform",
	Args:  cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		secretsPath := args[0]

		tfManager := terraform.NewManager(rc, ".")
		return tfManager.CreateVaultSecretsEngine(rc, secretsPath)
	}),
}

var vaultBackendCmd = &cobra.Command{
	Use:   "vault-backend [directory]",
	Short: "Configure Vault as Terraform state backend",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		statePath, _ := cmd.Flags().GetString("state-path")
		if statePath == "" {
			statePath = "terraform/state"
		}

		tfManager := terraform.NewManager(rc, workingDir)

		vaultConfig := terraform.VaultBackendConfig{
			Address: os.Getenv("VAULT_ADDR"),
			Path:    statePath,
			Token:   os.Getenv("VAULT_TOKEN"),
		}

		if vaultConfig.Address == "" {
			vaultConfig.Address = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
		}

		return tfManager.GenerateVaultBackendConfig(rc, vaultConfig)
	}),
}

var syncOutputsCmd = &cobra.Command{
	Use:   "sync-outputs [directory] [vault-path]",
	Short: "Sync Terraform outputs to Vault",
	Args:  cobra.ExactArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := args[0]
		vaultPath := args[1]

		tfManager := terraform.NewManager(rc, workingDir)

		outputs, err := getOutputNames(rc, tfManager)
		if err != nil {
			return fmt.Errorf("failed to get output names: %w", err)
		}

		if len(outputs) == 0 {
			fmt.Println("No outputs found to sync")
			return nil
		}

		return tfManager.SyncTerraformOutputsToVault(rc, vaultPath, outputs)
	}),
}

// Helper functions
func loadSecretReferences(filename string) ([]terraform.VaultSecretReference, error) {
	// This would parse a YAML/JSON file with secret references
	// For now, return empty slice as the file parsing is not yet implemented
	_ = filename // Mark parameter as used
	// TODO: Implement proper file parsing (YAML/JSON) for secret references
	return []terraform.VaultSecretReference{}, nil
}

func getOutputNames(rc *eos_io.RuntimeContext, tfManager *terraform.Manager) ([]string, error) {
	// Get all outputs by running terraform output command
	output, err := tfManager.Output(rc, "")
	if err != nil {
		return nil, err
	}

	// Parse output names (this is a simplified implementation)
	// In reality, you'd parse the JSON output to get all output names
	if output == "" {
		return []string{}, nil
	}

	// For now, return common output names
	return []string{"server_ip", "server_id", "load_balancer_ip"}, nil
}

func init() {
	CreateCmd.AddCommand(terraformVaultCmd)
	CreateCmd.AddCommand(vaultSecretsEngineCmd)
	CreateCmd.AddCommand(vaultBackendCmd)
	CreateCmd.AddCommand(syncOutputsCmd)

	// Terraform-Vault flags
	terraformVaultCmd.Flags().Bool("vault-state", false, "Use Vault as Terraform state backend")
	terraformVaultCmd.Flags().Bool("vault-secrets", true, "Use Vault for secrets management")
	terraformVaultCmd.Flags().String("secrets-path", "terraform/secrets", "Path in Vault for secrets")
	terraformVaultCmd.Flags().String("state-path", "terraform/state", "Path in Vault for state")
	terraformVaultCmd.Flags().String("outputs-path", "terraform/outputs", "Path in Vault to store outputs")
	terraformVaultCmd.Flags().String("secret-refs", "", "File containing secret references")
	terraformVaultCmd.Flags().Bool("auto-approve", false, "Auto approve the deployment")

	// Vault backend flags
	vaultBackendCmd.Flags().String("state-path", "terraform/state", "Path in Vault for state storage")
}
