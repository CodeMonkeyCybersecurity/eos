package inspect

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var terraformGraphCmd = &cobra.Command{
	Use:   "terraform-graph",
	Short: "Generate and visualize Terraform infrastructure graphs with secure Vault integration",
	Long: `Generate comprehensive Terraform infrastructure dependency graphs with ASCII or DOT 
format output. Securely store graph metadata in HashiCorp Vault for audit and analysis.

This command analyzes Terraform configurations and creates visual representations of
resource dependencies, helping with infrastructure understanding and troubleshooting.

Features:
- ASCII art visualization for command-line viewing
- DOT format output for Graphviz integration
- Secure metadata storage in Vault
- Assessment->Intervention->Evaluation pattern for reliability
- Comprehensive error handling and logging

The process follows these phases:
1. Assessment: Verify Terraform availability and workspace readiness
2. Intervention: Initialize Terraform and generate dependency graph
3. Evaluation: Validate output and store metadata securely

Examples:
  # Generate ASCII graph in current directory
  eos inspect terraform-graph

  # Generate DOT format graph
  eos inspect terraform-graph --format dot --output graph.dot

  # Analyze specific Terraform directory
  eos inspect terraform-graph --terraform-dir /path/to/terraform

  # Store in specific namespace
  eos inspect terraform-graph --namespace production-graph

  # Use custom Vault address
  eos inspect terraform-graph --vault-addr http://vault.example.com:8179`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		logger.Info("Starting Terraform graph generation",
			zap.String("command", "inspect terraform-graph"),
			zap.String("component", rc.Component))
		
		// Parse command line flags
		config, err := parseTerraformGraphFlags(cmd)
		if err != nil {
			logger.Error("Failed to parse command flags", zap.Error(err))
			return fmt.Errorf("flag parsing failed: %w", err)
		}
		
		// Log configuration
		logger.Info("Terraform graph configuration",
			zap.String("terraform_path", config.TerraformPath),
			zap.String("working_dir", config.WorkingDir),
			zap.String("output_format", config.OutputFormat),
			zap.String("output_file", config.OutputFile),
			zap.String("vault_addr", config.VaultAddr),
			zap.String("namespace", config.Namespace))
		
		// Execute graph generation
		if err := terraform.GenerateGraph(rc, config); err != nil {
			logger.Error("Terraform graph generation failed", zap.Error(err))
			return fmt.Errorf("terraform graph generation failed: %w", err)
		}
		
		// Display success information
		logger.Info("Terraform graph generation completed successfully",
			zap.String("output_file", config.OutputFile),
			zap.String("format", config.OutputFormat),
			zap.String("namespace", config.Namespace))
		
		logger.Info("Graph details",
			zap.String("file_path", config.OutputFile),
			zap.String("terraform_dir", config.WorkingDir),
			zap.String("vault_metadata", fmt.Sprintf("secret/data/terraform-graph/%s", config.Namespace)))
		
		return nil
	}),
}

// parseTerraformGraphFlags parses command line flags and returns a Terraform graph configuration
func parseTerraformGraphFlags(cmd *cobra.Command) (*terraform.GraphConfig, error) {
	// Start with default configuration
	config := terraform.DefaultGraphConfig()
	
	// Parse flags
	if terraformPath, err := cmd.Flags().GetString("terraform-path"); err == nil && terraformPath != "" {
		config.TerraformPath = terraformPath
	}
	
	if workingDir, err := cmd.Flags().GetString("terraform-dir"); err == nil && workingDir != "" {
		config.WorkingDir = workingDir
	}
	
	if outputFormat, err := cmd.Flags().GetString("format"); err == nil && outputFormat != "" {
		config.OutputFormat = outputFormat
	}
	
	if outputFile, err := cmd.Flags().GetString("output"); err == nil && outputFile != "" {
		config.OutputFile = outputFile
	}
	
	if vaultAddr, err := cmd.Flags().GetString("vault-addr"); err == nil && vaultAddr != "" {
		config.VaultAddr = vaultAddr
	}
	
	if nomadAddr, err := cmd.Flags().GetString("nomad-addr"); err == nil && nomadAddr != "" {
		config.NomadAddr = nomadAddr
	}
	
	if namespace, err := cmd.Flags().GetString("namespace"); err == nil && namespace != "" {
		config.Namespace = namespace
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	return config, nil
}

func init() {
	// Add terraform-graph command to inspect
	InspectCmd.AddCommand(terraformGraphCmd)
	
	// Basic configuration flags
	terraformGraphCmd.Flags().String("terraform-path", "terraform", "Path to terraform binary")
	terraformGraphCmd.Flags().String("terraform-dir", ".", "Directory containing Terraform configuration")
	terraformGraphCmd.Flags().StringP("format", "f", "ascii", "Output format (ascii, dot)")
	terraformGraphCmd.Flags().StringP("output", "o", "terraform-graph.txt", "Output file path")
	terraformGraphCmd.Flags().String("vault-addr", "http://localhost:8179", "Vault server address")
	terraformGraphCmd.Flags().String("nomad-addr", "http://localhost:4646", "Nomad server address")
	terraformGraphCmd.Flags().String("namespace", "terraform-graph", "Namespace for metadata storage")
	
	// Set flag usage examples
	terraformGraphCmd.Example = `  # Generate ASCII graph in current directory
  eos inspect terraform-graph

  # Generate DOT format for Graphviz
  eos inspect terraform-graph --format dot --output infrastructure.dot

  # Analyze specific Terraform project
  eos inspect terraform-graph --terraform-dir /opt/terraform/production

  # Custom namespace for organization
  eos inspect terraform-graph --namespace prod-infrastructure

  # Output to specific file
  eos inspect terraform-graph --output /tmp/tf-graph.txt`
}
