package terraform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Assessment Phase Functions - Check current state

// assessPrerequisites checks if all required tools are available
func (m *GraphManager) assessPrerequisites(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing system prerequisites for Terraform graph generation")

	requiredTools := []string{"terraform"}

	for _, tool := range requiredTools {
		if err := m.checkCommandExists(tool); err != nil {
			logger.Error("Required tool not found",
				zap.String("tool", tool),
				zap.Error(err))
			return fmt.Errorf("required tool %s not found: %w", tool, err)
		}
		logger.Debug("Tool found", zap.String("tool", tool))
	}

	// Check if working directory exists and has Terraform files
	if _, err := os.Stat(m.config.WorkingDir); os.IsNotExist(err) {
		logger.Error("Working directory does not exist",
			zap.String("path", m.config.WorkingDir))
		return fmt.Errorf("working directory does not exist: %s", m.config.WorkingDir)
	}

	// Check for Terraform files
	hasTerraformFiles, err := m.checkTerraformFiles()
	if err != nil {
		return fmt.Errorf("failed to check Terraform files: %w", err)
	}

	if !hasTerraformFiles {
		logger.Warn("No Terraform files found in working directory",
			zap.String("path", m.config.WorkingDir))
	}

	return nil
}

// assessTerraformInit checks if Terraform is initialized
func (m *GraphManager) assessTerraformInit(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing Terraform initialization")

	// Check if .terraform directory exists
	terraformDir := filepath.Join(m.config.WorkingDir, ".terraform")
	if _, err := os.Stat(terraformDir); os.IsNotExist(err) {
		logger.Debug("Terraform not initialized, will initialize")
		return nil // Not an error, we'll initialize it
	}

	logger.Info("Terraform appears to be initialized")
	return nil
}

// assessGraphGeneration checks if we can generate a graph
func (m *GraphManager) assessGraphGeneration(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing graph generation readiness")

	// Check if output directory exists
	outputDir := filepath.Dir(m.config.OutputFile)
	if outputDir != "." {
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			logger.Debug("Output directory does not exist, will create",
				zap.String("dir", outputDir))
		}
	}

	return nil
}

// assessVaultStorage checks if we can connect to Vault
func (m *GraphManager) assessVaultStorage(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Assessing Vault connectivity")

	// Check if we can connect to Vault
	health, err := m.vaultClient.Sys().Health()
	if err != nil {
		logger.Warn("Cannot connect to Vault, will skip metadata storage", zap.Error(err))
		return nil // Not a fatal error
	}

	logger.Debug("Vault connection successful",
		zap.Bool("initialized", health.Initialized),
		zap.Bool("sealed", health.Sealed))

	return nil
}

// Intervention Phase Functions - Make changes

// ensurePrerequisites ensures all prerequisites are met
func (m *GraphManager) ensurePrerequisites(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Ensuring prerequisites are met")

	// Check Vault connectivity (non-fatal)
	if _, err := m.vaultClient.Sys().Health(); err != nil {
		logger.Warn("Cannot connect to Vault, metadata storage will be skipped", zap.Error(err))
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(m.config.OutputFile)
	if outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			logger.Error("Failed to create output directory", zap.Error(err))
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	logger.Info("All prerequisites verified")
	return nil
}

// initializeTerraform initializes Terraform if needed
func (m *GraphManager) initializeTerraform(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Initializing Terraform")

	// Check if already initialized
	terraformDir := filepath.Join(m.config.WorkingDir, ".terraform")
	if _, err := os.Stat(terraformDir); err == nil {
		logger.Info("Terraform already initialized")
		return nil
	}

	// Run terraform init
	cmd := exec.CommandContext(ctx, m.config.TerraformPath, "init")
	cmd.Dir = m.config.WorkingDir

	logger.Info("Running terraform init",
		zap.String("working_dir", m.config.WorkingDir),
		zap.String("command", cmd.String()))

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Terraform init failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("terraform init failed: %w", err)
	}

	logger.Info("Terraform initialized successfully")
	return nil
}

// generateTerraformGraph generates the Terraform graph
func (m *GraphManager) generateTerraformGraph(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Generating Terraform graph",
		zap.String("output_format", m.config.OutputFormat),
		zap.String("output_file", m.config.OutputFile))

	// Run terraform graph
	cmd := exec.CommandContext(ctx, m.config.TerraformPath, "graph")
	cmd.Dir = m.config.WorkingDir

	logger.Info("Running terraform graph",
		zap.String("working_dir", m.config.WorkingDir),
		zap.String("command", cmd.String()))

	output, err := cmd.Output()
	if err != nil {
		logger.Error("Terraform graph generation failed", zap.Error(err))
		return fmt.Errorf("terraform graph failed: %w", err)
	}

	// Process output based on format
	var finalOutput string
	switch m.config.OutputFormat {
	case "ascii":
		// Convert DOT format to ASCII
		finalOutput, err = m.convertToASCII(string(output))
		if err != nil {
			return fmt.Errorf("failed to convert to ASCII: %w", err)
		}
	case "dot":
		finalOutput = string(output)
	default:
		return fmt.Errorf("unsupported output format: %s", m.config.OutputFormat)
	}

	// Write to file
	if err := os.WriteFile(m.config.OutputFile, []byte(finalOutput), 0644); err != nil {
		logger.Error("Failed to write graph file", zap.Error(err))
		return fmt.Errorf("failed to write graph file: %w", err)
	}

	logger.Info("Terraform graph generated successfully",
		zap.String("file_path", m.config.OutputFile),
		zap.Int("size_bytes", len(finalOutput)))

	return nil
}

// storeGraphMetadata stores graph metadata in Vault
func (m *GraphManager) storeGraphMetadata(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Storing graph metadata in Vault")

	// Check if Vault is available
	if _, err := m.vaultClient.Sys().Health(); err != nil {
		logger.Warn("Vault not available, skipping metadata storage", zap.Error(err))
		return nil // Not a fatal error
	}

	// Get graph info
	info, err := m.GetGraphInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get graph info: %w", err)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"namespace":     info.Namespace,
		"format":        info.Format,
		"file_path":     info.FilePath,
		"file_size":     info.FileSize,
		"created_at":    info.CreatedAt.Format(time.RFC3339),
		"terraform_dir": info.TerraformDir,
		"nodes_count":   info.NodesCount,
		"edges_count":   info.EdgesCount,
		"generated_by":  "eos-terraform-graph",
	}

	// Write to Vault
	secretPath := fmt.Sprintf("secret/data/terraform-graph/%s", m.config.Namespace)
	_, err = m.vaultClient.Logical().Write(secretPath, map[string]interface{}{
		"data": metadata,
	})
	if err != nil {
		logger.Warn("Failed to write graph metadata to Vault", zap.Error(err))
		return nil // Not fatal
	}

	logger.Info("Graph metadata stored in Vault successfully")
	return nil
}

// Evaluation Phase Functions - Verify changes

// evaluatePrerequisites verifies prerequisites are working
func (m *GraphManager) evaluatePrerequisites(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating prerequisites")

	// Re-check that terraform is available
	if err := m.checkCommandExists(m.config.TerraformPath); err != nil {
		return fmt.Errorf("terraform binary validation failed: %w", err)
	}

	// Verify working directory exists
	if _, err := os.Stat(m.config.WorkingDir); os.IsNotExist(err) {
		return fmt.Errorf("working directory does not exist: %s", m.config.WorkingDir)
	}

	logger.Info("Prerequisites evaluation successful")
	return nil
}

// evaluateTerraformInit verifies Terraform initialization
func (m *GraphManager) evaluateTerraformInit(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating Terraform initialization")

	// Check if .terraform directory exists
	terraformDir := filepath.Join(m.config.WorkingDir, ".terraform")
	if _, err := os.Stat(terraformDir); os.IsNotExist(err) {
		return fmt.Errorf("terraform initialization verification failed: .terraform directory not found")
	}

	logger.Info("Terraform initialization evaluation successful")
	return nil
}

// evaluateGraphGeneration verifies the graph was generated correctly
func (m *GraphManager) evaluateGraphGeneration(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating graph generation")

	// Check if output file exists
	if _, err := os.Stat(m.config.OutputFile); os.IsNotExist(err) {
		return fmt.Errorf("graph file was not created: %s", m.config.OutputFile)
	}

	// Check if file has content
	content, err := os.ReadFile(m.config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to read graph file: %w", err)
	}

	if len(content) == 0 {
		return fmt.Errorf("graph file is empty")
	}

	logger.Info("Graph generation evaluation successful",
		zap.String("file_path", m.config.OutputFile),
		zap.Int("file_size", len(content)))

	return nil
}

// evaluateVaultStorage verifies metadata was stored correctly
func (m *GraphManager) evaluateVaultStorage(ctx context.Context, mgr *GraphManager) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Evaluating Vault storage")

	// Check if Vault is available
	if _, err := m.vaultClient.Sys().Health(); err != nil {
		logger.Info("Vault not available, skipping storage evaluation")
		return nil // Not a fatal error
	}

	// Try to read back the metadata
	secretPath := fmt.Sprintf("secret/data/terraform-graph/%s", m.config.Namespace)
	secret, err := m.vaultClient.Logical().Read(secretPath)
	if err != nil {
		logger.Warn("Failed to read graph metadata from Vault", zap.Error(err))
		return nil // Not fatal
	}

	if secret != nil && secret.Data != nil {
		logger.Info("Vault storage evaluation successful")
	} else {
		logger.Warn("Graph metadata not found in Vault")
	}

	return nil
}

// Helper functions

// checkCommandExists checks if a command is available
func (m *GraphManager) checkCommandExists(command string) error {
	_, err := exec.LookPath(command)
	return err
}

// checkTerraformFiles checks if the working directory contains Terraform files
func (m *GraphManager) checkTerraformFiles() (bool, error) {
	files, err := filepath.Glob(filepath.Join(m.config.WorkingDir, "*.tf"))
	if err != nil {
		return false, fmt.Errorf("failed to check for .tf files: %w", err)
	}

	return len(files) > 0, nil
}
