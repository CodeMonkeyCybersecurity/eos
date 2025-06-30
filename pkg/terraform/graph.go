package terraform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GraphConfig represents the configuration for Terraform graph generation
type GraphConfig struct {
	TerraformPath string `yaml:"terraform_path" json:"terraform_path"`
	WorkingDir    string `yaml:"working_dir" json:"working_dir"`
	OutputFormat  string `yaml:"output_format" json:"output_format"`
	OutputFile    string `yaml:"output_file" json:"output_file"`
	VaultAddr     string `yaml:"vault_addr" json:"vault_addr"`
	NomadAddr     string `yaml:"nomad_addr" json:"nomad_addr"`
	VaultToken    string `yaml:"vault_token" json:"vault_token"`
	Namespace     string `yaml:"namespace" json:"namespace"`
}

// DefaultGraphConfig returns a default graph configuration
func DefaultGraphConfig() *GraphConfig {
	return &GraphConfig{
		TerraformPath: "terraform",
		WorkingDir:    ".",
		OutputFormat:  "ascii",
		OutputFile:    "terraform-graph.txt",
		VaultAddr:     "http://localhost:8179", // Use Eos standard port
		NomadAddr:     "http://localhost:4646",
		Namespace:     "terraform-graph",
	}
}

// Validate checks if the configuration is valid
func (c *GraphConfig) Validate() error {
	if c.TerraformPath == "" {
		return fmt.Errorf("terraform_path cannot be empty")
	}

	if c.WorkingDir == "" {
		return fmt.Errorf("working_dir cannot be empty")
	}

	if c.OutputFormat == "" {
		c.OutputFormat = "ascii"
	}

	if c.Namespace == "" {
		c.Namespace = "terraform-graph"
	}

	// Check if terraform binary exists
	if _, err := exec.LookPath(c.TerraformPath); err != nil {
		return fmt.Errorf("terraform binary not found at %s: %w", c.TerraformPath, err)
	}

	// Check if working directory exists
	if _, err := os.Stat(c.WorkingDir); os.IsNotExist(err) {
		return fmt.Errorf("working directory does not exist: %s", c.WorkingDir)
	}

	return nil
}

// GraphManager manages Terraform graph generation
type GraphManager struct {
	config      *GraphConfig
	nomadClient *api.Client
	vaultClient *vault.Client
	statusChan  chan GraphStatus
}

// GraphStatus represents the status of graph generation
type GraphStatus struct {
	Step      string                 `json:"step"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

// GraphStep represents a step in the graph generation process
type GraphStep struct {
	Name          string
	Description   string
	AssessFunc    func(ctx context.Context, mgr *GraphManager) error
	InterventFunc func(ctx context.Context, mgr *GraphManager) error
	EvaluateFunc  func(ctx context.Context, mgr *GraphManager) error
}

// GraphInfo represents information about a generated graph
type GraphInfo struct {
	Namespace    string    `json:"namespace"`
	Format       string    `json:"format"`
	FilePath     string    `json:"file_path"`
	FileSize     int64     `json:"file_size"`
	CreatedAt    time.Time `json:"created_at"`
	TerraformDir string    `json:"terraform_dir"`
	NodesCount   int       `json:"nodes_count"`
	EdgesCount   int       `json:"edges_count"`
}

// NewGraphManager creates a new graph manager instance
func NewGraphManager(config *GraphConfig) (*GraphManager, error) {
	// Initialize Nomad client
	nomadConfig := api.DefaultConfig()
	if config.NomadAddr != "" {
		nomadConfig.Address = config.NomadAddr
	}
	nomadClient, err := api.NewClient(nomadConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Initialize Vault client
	vaultConfig := vault.DefaultConfig()
	if config.VaultAddr != "" {
		vaultConfig.Address = config.VaultAddr
	}
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	if config.VaultToken != "" {
		vaultClient.SetToken(config.VaultToken)
	}

	return &GraphManager{
		config:      config,
		nomadClient: nomadClient,
		vaultClient: vaultClient,
		statusChan:  make(chan GraphStatus, 100),
	}, nil
}

// GenerateGraph orchestrates the complete graph generation process
func (m *GraphManager) GenerateGraph(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting Terraform graph generation",
		zap.String("working_dir", m.config.WorkingDir),
		zap.String("output_format", m.config.OutputFormat))

	// Define graph generation steps following assessment->intervention->evaluation pattern
	steps := []GraphStep{
		{
			Name:          "prerequisites",
			Description:   "Verify system prerequisites",
			AssessFunc:    m.assessPrerequisites,
			InterventFunc: m.ensurePrerequisites,
			EvaluateFunc:  m.evaluatePrerequisites,
		},
		{
			Name:          "terraform_init",
			Description:   "Initialize Terraform",
			AssessFunc:    m.assessTerraformInit,
			InterventFunc: m.initializeTerraform,
			EvaluateFunc:  m.evaluateTerraformInit,
		},
		{
			Name:          "graph_generation",
			Description:   "Generate Terraform graph",
			AssessFunc:    m.assessGraphGeneration,
			InterventFunc: m.generateTerraformGraph,
			EvaluateFunc:  m.evaluateGraphGeneration,
		},
		{
			Name:          "vault_storage",
			Description:   "Store graph metadata in Vault",
			AssessFunc:    m.assessVaultStorage,
			InterventFunc: m.storeGraphMetadata,
			EvaluateFunc:  m.evaluateVaultStorage,
		},
	}

	// Execute each step
	for _, step := range steps {
		if err := m.executeStep(ctx, step); err != nil {
			m.reportStatus(step.Name+"_failed", false,
				fmt.Sprintf("Step %s failed", step.Description),
				map[string]interface{}{"error": err.Error()})
			return fmt.Errorf("graph generation step %s failed: %w", step.Name, err)
		}
	}

	m.reportStatus("generation_complete", true, "Terraform graph generation completed successfully",
		map[string]interface{}{
			"output_file": m.config.OutputFile,
			"format":      m.config.OutputFormat,
		})

	return nil
}

// executeStep executes a single graph generation step with assessment->intervention->evaluation
func (m *GraphManager) executeStep(ctx context.Context, step GraphStep) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing graph generation step",
		zap.String("step", step.Name),
		zap.String("description", step.Description))

	// Assessment phase
	m.reportStatus(step.Name+"_assess", true, "Assessing "+step.Description, nil)
	if err := step.AssessFunc(ctx, m); err != nil {
		logger.Error("Assessment failed",
			zap.String("step", step.Name),
			zap.Error(err))
		return fmt.Errorf("assessment failed: %w", err)
	}

	// Intervention phase
	m.reportStatus(step.Name+"_intervene", true, "Executing "+step.Description, nil)
	if err := step.InterventFunc(ctx, m); err != nil {
		logger.Error("Intervention failed",
			zap.String("step", step.Name),
			zap.Error(err))
		return fmt.Errorf("intervention failed: %w", err)
	}

	// Evaluation phase
	m.reportStatus(step.Name+"_evaluate", true, "Evaluating "+step.Description, nil)
	if err := step.EvaluateFunc(ctx, m); err != nil {
		logger.Error("Evaluation failed",
			zap.String("step", step.Name),
			zap.Error(err))
		return fmt.Errorf("evaluation failed: %w", err)
	}

	m.reportStatus(step.Name+"_complete", true, step.Description+" completed successfully", nil)
	return nil
}

// GetStatusChannel returns the status channel for monitoring
func (m *GraphManager) GetStatusChannel() <-chan GraphStatus {
	return m.statusChan
}

// reportStatus sends a status update to the status channel
func (m *GraphManager) reportStatus(step string, success bool, message string, details map[string]interface{}) {
	status := GraphStatus{
		Step:      step,
		Success:   success,
		Message:   message,
		Timestamp: time.Now(),
		Details:   details,
	}

	select {
	case m.statusChan <- status:
	default:
		// Channel full, skip
	}
}

// convertToASCII converts a Terraform graph to ASCII representation
func (m *GraphManager) convertToASCII(dotContent string) (string, error) {
	// Simple ASCII conversion - parse DOT format and create text representation
	lines := strings.Split(dotContent, "\n")
	var result strings.Builder

	result.WriteString("Terraform Infrastructure Graph\n")
	result.WriteString("================================\n\n")

	var nodes []string
	var edges []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Parse nodes (lines with [label=...])
		if strings.Contains(line, "[label=") && !strings.Contains(line, "->") {
			parts := strings.Split(line, " ")
			if len(parts) > 0 {
				nodeName := strings.Trim(parts[0], `"`)
				nodes = append(nodes, nodeName)
			}
		}

		// Parse edges (lines with ->)
		if strings.Contains(line, "->") {
			edges = append(edges, line)
		}
	}

	// Output nodes
	result.WriteString("Resources:\n")
	for i, node := range nodes {
		result.WriteString(fmt.Sprintf("%d. %s\n", i+1, node))
	}

	// Output dependencies
	result.WriteString("\nDependencies:\n")
	for _, edge := range edges {
		// Clean up the edge format
		cleanEdge := strings.ReplaceAll(edge, `"`, "")
		cleanEdge = strings.ReplaceAll(cleanEdge, ";", "")
		result.WriteString(fmt.Sprintf("  %s\n", cleanEdge))
	}

	return result.String(), nil
}

// GetGraphInfo retrieves information about a generated graph
func (m *GraphManager) GetGraphInfo(ctx context.Context) (*GraphInfo, error) {
	if _, err := os.Stat(m.config.OutputFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("graph file not found: %s", m.config.OutputFile)
	}

	stat, err := os.Stat(m.config.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to stat graph file: %w", err)
	}

	// Count nodes and edges by reading the file
	content, err := os.ReadFile(m.config.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read graph file: %w", err)
	}

	nodesCount := strings.Count(string(content), "[label=")
	edgesCount := strings.Count(string(content), "->")

	info := &GraphInfo{
		Namespace:    m.config.Namespace,
		Format:       m.config.OutputFormat,
		FilePath:     m.config.OutputFile,
		FileSize:     stat.Size(),
		CreatedAt:    stat.ModTime(),
		TerraformDir: m.config.WorkingDir,
		NodesCount:   nodesCount,
		EdgesCount:   edgesCount,
	}

	return info, nil
}
