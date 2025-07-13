// cmd/create/terraform_workflow.go

package create

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var terraformPlanCmd = &cobra.Command{
	Use:   "terraform-plan [directory]",
	Short: "Run terraform plan on a directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		return tfManager.Plan(rc)
	}),
}

var terraformApplyCmd = &cobra.Command{
	Use:   "terraform-apply [directory]",
	Short: "Run terraform apply on a directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		autoApprove, _ := cmd.Flags().GetBool("auto-approve")

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		return tfManager.Apply(rc, autoApprove)
	}),
}

var terraformDestroyCmd = &cobra.Command{
	Use:   "terraform-destroy [directory]",
	Short: "Run terraform destroy on a directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		autoApprove, _ := cmd.Flags().GetBool("auto-approve")

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		return tfManager.Destroy(rc, autoApprove)
	}),
}

var terraformInitCmd = &cobra.Command{
	Use:   "terraform-init [directory]",
	Short: "Run terraform init on a directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		return tfManager.Init(rc)
	}),
}

var terraformOutputCmd = &cobra.Command{
	Use:   "terraform-output [directory] [output_name]",
	Short: "Get terraform output from a directory",
	Args:  cobra.MaximumNArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		outputName := ""

		if len(args) > 0 {
			workingDir = args[0]
		}
		if len(args) > 1 {
			outputName = args[1]
		}

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		output, err := tfManager.Output(rc, outputName)
		if err != nil {
			return err
		}

		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", output)))
		return nil
	}),
}

var terraformWorkspaceCmd = &cobra.Command{
	Use:   "terraform-workspace",
	Short: "Manage Terraform workspaces",
}

var terraformValidateCmd = &cobra.Command{
	Use:   "terraform-validate [directory]",
	Short: "Validate terraform configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		return tfManager.Validate(rc)
	}),
}

var terraformFormatCmd = &cobra.Command{
	Use:   "terraform-fmt [directory]",
	Short: "Format terraform files",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		tfManager := terraform.NewManager(rc, workingDir)
		return tfManager.Format(rc)
	}),
}

var terraformFullWorkflowCmd = &cobra.Command{
	Use:   "terraform-deploy [directory]",
	Short: "Full Terraform workflow: init, validate, plan, apply",
	Args:  cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		workingDir := "."
		if len(args) > 0 {
			workingDir = args[0]
		}

		autoApprove, _ := cmd.Flags().GetBool("auto-approve")

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required: %w", err)
		}

		// Check if directory exists
		if _, err := os.Stat(workingDir); os.IsNotExist(err) {
			return fmt.Errorf("directory %s does not exist", workingDir)
		}

		// Check if it looks like a terraform directory
		mainTf := filepath.Join(workingDir, "main.tf")
		if _, err := os.Stat(mainTf); os.IsNotExist(err) {
			return fmt.Errorf("no main.tf found in %s", workingDir)
		}

		tfManager := terraform.NewManager(rc, workingDir)

		logger.Info("Starting Terraform deployment workflow", zap.String("directory", workingDir))

		// Step 1: Initialize
		logger.Info("Step 1: Initializing Terraform")
		if err := tfManager.Init(rc); err != nil {
			return fmt.Errorf("terraform init failed: %w", err)
		}

		// Step 2: Validate
		logger.Info("Step 2: Validating configuration")
		if err := tfManager.Validate(rc); err != nil {
			return fmt.Errorf("terraform validation failed: %w", err)
		}

		// Step 3: Plan
		logger.Info("Step 3: Planning deployment")
		if err := tfManager.Plan(rc); err != nil {
			return fmt.Errorf("terraform plan failed: %w", err)
		}

		// Step 4: Apply (if auto-approve or user confirms)
		if !autoApprove {
			logger.Info("terminal prompt: \nDo you want to apply these changes? [y/N]: ")
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

		logger.Info("Step 4: Applying configuration")
		if err := tfManager.Apply(rc, true); err != nil {
			return fmt.Errorf("terraform apply failed: %w", err)
		}

		logger.Info("Terraform deployment completed successfully")
		logger.Info("terminal prompt: \n Deployment completed successfully!")

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(terraformPlanCmd)
	CreateCmd.AddCommand(terraformApplyCmd)
	CreateCmd.AddCommand(terraformDestroyCmd)
	CreateCmd.AddCommand(terraformInitCmd)
	CreateCmd.AddCommand(terraformOutputCmd)
	CreateCmd.AddCommand(terraformWorkspaceCmd)
	CreateCmd.AddCommand(terraformValidateCmd)
	CreateCmd.AddCommand(terraformFormatCmd)
	CreateCmd.AddCommand(terraformFullWorkflowCmd)

	// Add flags
	terraformApplyCmd.Flags().Bool("auto-approve", false, "Auto approve the apply")
	terraformDestroyCmd.Flags().Bool("auto-approve", false, "Auto approve the destroy")
	terraformFullWorkflowCmd.Flags().Bool("auto-approve", false, "Auto approve the deployment")
}
