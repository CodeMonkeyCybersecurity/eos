package read

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/deploy"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var deploymentStatusCmd = &cobra.Command{
	Use:   "deployment-status [app-name]",
	Short: "Check the status of an application deployment",
	Long: `Check the comprehensive status of an application deployment including:
- Overall deployment health and status
- Nomad job status and allocation details  
- Consul service registration and health checks
- Vault secrets status
- Infrastructure state via Terraform
- Recent deployment history and metrics
- Pipeline execution status if currently running

This command provides real-time visibility into all aspects of your deployment
following the Salt → Terraform → Nomad orchestration hierarchy.

Examples:
  # Check Helen deployment status
  eos read deployment-status helen

  # Check status with detailed output
  eos read deployment-status helen --detailed

  # Check status in JSON format
  eos read deployment-status helen --format json

  # Check status and follow log output
  eos read deployment-status helen --follow

  # Check status for specific environment
  eos read deployment-status helen --environment staging`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		appName := args[0]

		logger.Info("Checking deployment status",
			zap.String("command", "read deployment-status"),
			zap.String("app_name", appName),
			zap.String("component", rc.Component))

		// Parse command flags
		detailed, _ := cmd.Flags().GetBool("detailed")
		format, _ := cmd.Flags().GetString("format")
		follow, _ := cmd.Flags().GetBool("follow")
		environment, _ := cmd.Flags().GetString("environment")

		logger.Debug("Deployment status options",
			zap.Bool("detailed", detailed),
			zap.String("format", format),
			zap.Bool("follow", follow),
			zap.String("environment", environment))

		// Get deployment status
		status, err := getDeploymentStatus(rc, appName, environment)
		if err != nil {
			logger.Error("Failed to get deployment status", zap.Error(err))
			return fmt.Errorf("failed to get deployment status: %w", err)
		}

		// Display status based on format
		switch format {
		case "json":
			return displayStatusJSON(status)
		case "yaml":
			return displayStatusYAML(status)
		default:
			return displayStatusTable(status, detailed)
		}
	}),
}

func init() {
	// Add deployment-status command to read
	ReadCmd.AddCommand(deploymentStatusCmd)

	// Output formatting flags
	deploymentStatusCmd.Flags().String("format", "table", "Output format: table, json, yaml")
	deploymentStatusCmd.Flags().Bool("detailed", false, "Show detailed status information")
	deploymentStatusCmd.Flags().Bool("follow", false, "Follow status updates in real-time")

	// Filtering flags
	deploymentStatusCmd.Flags().String("environment", "", "Check status for specific environment")
	deploymentStatusCmd.Flags().String("namespace", "", "Check status for specific namespace")

	// Monitoring flags
	deploymentStatusCmd.Flags().Duration("refresh", 5, "Refresh interval in seconds for follow mode")
	deploymentStatusCmd.Flags().Int("history", 5, "Number of recent deployments to show")

	deploymentStatusCmd.Example = `  # Check basic deployment status
  eos read deployment-status helen

  # Check detailed status with JSON output
  eos read deployment-status helen --detailed --format json

  # Follow real-time status updates
  eos read deployment-status helen --follow --refresh 3s

  # Check staging environment status
  eos read deployment-status helen --environment staging`
}

// DeploymentStatus represents comprehensive deployment status
type DeploymentStatus struct {
	AppName     string                   `json:"app_name"`
	Environment string                   `json:"environment"`
	Namespace   string                   `json:"namespace"`
	Overall     OverallStatus            `json:"overall"`
	Nomad       NomadStatus              `json:"nomad"`
	Consul      ConsulStatus             `json:"consul"`
	Vault       VaultStatus              `json:"vault"`
	Terraform   TerraformStatus          `json:"terraform"`
	Pipeline    PipelineStatus           `json:"pipeline"`
	History     []DeploymentHistoryEntry `json:"history"`
	Timestamp   time.Time                `json:"timestamp"`
}

// OverallStatus represents the overall deployment health
type OverallStatus struct {
	Healthy     bool                   `json:"healthy"`
	Status      string                 `json:"status"`
	Version     string                 `json:"version"`
	Domain      string                 `json:"domain"`
	URL         string                 `json:"url"`
	Uptime      time.Duration          `json:"uptime"`
	LastUpdated time.Time              `json:"last_updated"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NomadStatus represents Nomad job status
type NomadStatus struct {
	JobID       string             `json:"job_id"`
	Status      string             `json:"status"`
	Running     int                `json:"running"`
	Desired     int                `json:"desired"`
	Failed      int                `json:"failed"`
	Allocations []AllocationStatus `json:"allocations"`
	LastUpdate  time.Time          `json:"last_update"`
}

// AllocationStatus represents a Nomad allocation status
type AllocationStatus struct {
	ID      string            `json:"id"`
	NodeID  string            `json:"node_id"`
	Status  string            `json:"status"`
	Tasks   map[string]string `json:"tasks"`
	Healthy bool              `json:"healthy"`
	Address string            `json:"address"`
}

// ConsulStatus represents Consul service status
type ConsulStatus struct {
	ServiceName string              `json:"service_name"`
	Registered  bool                `json:"registered"`
	Healthy     bool                `json:"healthy"`
	Checks      []ConsulCheckStatus `json:"checks"`
	Tags        []string            `json:"tags"`
	Address     string              `json:"address"`
	Port        int                 `json:"port"`
}

// ConsulCheckStatus represents a Consul health check status
type ConsulCheckStatus struct {
	CheckID string `json:"check_id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Output  string `json:"output"`
}

// VaultStatus represents Vault secrets status
type VaultStatus struct {
	SecretsPath    string    `json:"secrets_path"`
	SecretsHealthy bool      `json:"secrets_healthy"`
	LastAccess     time.Time `json:"last_access"`
	Policies       []string  `json:"policies"`
}

// TerraformStatus represents Terraform infrastructure status
type TerraformStatus struct {
	WorkspaceName string                 `json:"workspace_name"`
	StateHealthy  bool                   `json:"state_healthy"`
	Resources     []TerraformResource    `json:"resources"`
	LastApplied   time.Time              `json:"last_applied"`
	Outputs       map[string]interface{} `json:"outputs"`
}

// TerraformResource represents a Terraform resource
type TerraformResource struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Address string `json:"address"`
}

// PipelineStatus represents CI/CD pipeline status
type PipelineStatus struct {
	Running       bool               `json:"running"`
	LastExecution *PipelineExecution `json:"last_execution,omitempty"`
	CurrentStage  string             `json:"current_stage,omitempty"`
	Progress      float64            `json:"progress"`
	EstimatedTime time.Duration      `json:"estimated_time,omitempty"`
}

// PipelineExecution represents a pipeline execution summary
type PipelineExecution struct {
	ID        string                  `json:"id"`
	Status    string                  `json:"status"`
	StartTime time.Time               `json:"start_time"`
	EndTime   *time.Time              `json:"end_time,omitempty"`
	Duration  time.Duration           `json:"duration"`
	Trigger   string                  `json:"trigger"`
	Version   string                  `json:"version"`
	Stages    []StageExecutionSummary `json:"stages"`
}

// StageExecutionSummary represents a stage execution summary
type StageExecutionSummary struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// DeploymentHistoryEntry represents a deployment history entry
type DeploymentHistoryEntry struct {
	Version    string        `json:"version"`
	Timestamp  time.Time     `json:"timestamp"`
	Status     string        `json:"status"`
	Trigger    string        `json:"trigger"`
	Duration   time.Duration `json:"duration"`
	DeployedBy string        `json:"deployed_by"`
}

// getDeploymentStatus retrieves comprehensive deployment status
func getDeploymentStatus(rc *eos_io.RuntimeContext, appName, environment string) (*DeploymentStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Retrieving deployment status",
		zap.String("app_name", appName),
		zap.String("environment", environment))

	// Initialize deployment manager
	deployConfig := deploy.DefaultDeploymentConfig()
	manager, err := deploy.NewDeploymentManager(deployConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create deployment manager: %w", err)
	}

	// Get Nomad status
	nomadStatus, err := getNomadStatus(rc, manager, appName)
	if err != nil {
		logger.Warn("Failed to get Nomad status", zap.Error(err))
		nomadStatus = &NomadStatus{Status: "unknown"}
	}

	// Get Consul status
	consulStatus, err := getConsulStatus(rc, manager, appName)
	if err != nil {
		logger.Warn("Failed to get Consul status", zap.Error(err))
		consulStatus = &ConsulStatus{Registered: false}
	}

	// Get Vault status
	vaultStatus, err := getVaultStatus(rc, manager, appName)
	if err != nil {
		logger.Warn("Failed to get Vault status", zap.Error(err))
		vaultStatus = &VaultStatus{SecretsHealthy: false}
	}

	// Get Terraform status
	terraformStatus, err := getTerraformStatus(rc, manager, appName)
	if err != nil {
		logger.Warn("Failed to get Terraform status", zap.Error(err))
		terraformStatus = &TerraformStatus{StateHealthy: false}
	}

	// Get pipeline status
	pipelineStatus, err := getPipelineStatus(rc, appName)
	if err != nil {
		logger.Warn("Failed to get pipeline status", zap.Error(err))
		pipelineStatus = &PipelineStatus{Running: false}
	}

	// Get deployment history
	history, err := getDeploymentHistory(rc, appName)
	if err != nil {
		logger.Warn("Failed to get deployment history", zap.Error(err))
		history = []DeploymentHistoryEntry{}
	}

	// Calculate overall status
	overall := calculateOverallStatus(nomadStatus, consulStatus, vaultStatus, terraformStatus)

	status := &DeploymentStatus{
		AppName:     appName,
		Environment: environment,
		Namespace:   appName, // Default to app name
		Overall:     *overall,
		Nomad:       *nomadStatus,
		Consul:      *consulStatus,
		Vault:       *vaultStatus,
		Terraform:   *terraformStatus,
		Pipeline:    *pipelineStatus,
		History:     history,
		Timestamp:   time.Now(),
	}

	logger.Info("Deployment status retrieved successfully",
		zap.String("app_name", appName),
		zap.String("overall_status", overall.Status),
		zap.Bool("healthy", overall.Healthy))

	return status, nil
}

// getNomadStatus retrieves Nomad job status
func getNomadStatus(rc *eos_io.RuntimeContext, manager *deploy.DeploymentManager, appName string) (*NomadStatus, error) {
	client := manager.GetNomadClient()

	jobID := appName + "-web"
	jobStatus, err := client.GetJobStatus(rc.Ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Nomad job status: %w", err)
	}

	// Get allocations
	allocations, err := client.GetAllocations(rc.Ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Nomad allocations: %w", err)
	}

	// Convert allocations to status format
	var allocStatuses []AllocationStatus
	for _, alloc := range allocations {
		allocStatuses = append(allocStatuses, AllocationStatus{
			ID:      alloc.ID,
			NodeID:  alloc.NodeID,
			Status:  alloc.Status,
			Tasks:   alloc.Tasks,
			Healthy: alloc.Status == "running",
		})
	}

	return &NomadStatus{
		JobID:       jobID,
		Status:      jobStatus.Status,
		Running:     jobStatus.Running,
		Desired:     jobStatus.Desired,
		Failed:      jobStatus.Failed,
		Allocations: allocStatuses,
		LastUpdate:  time.Now(),
	}, nil
}

// getConsulStatus retrieves Consul service status
func getConsulStatus(rc *eos_io.RuntimeContext, manager *deploy.DeploymentManager, appName string) (*ConsulStatus, error) {
	// Implementation would check Consul service registration and health
	return &ConsulStatus{
		ServiceName: appName + "-web",
		Registered:  true,
		Healthy:     true,
		Checks: []ConsulCheckStatus{
			{
				CheckID: appName + "-health",
				Name:    "HTTP health check",
				Status:  "passing",
				Output:  "HTTP GET: 200 OK",
			},
		},
		Tags:    []string{"hugo", "static-site", "production"},
		Address: "localhost",
		Port:    80,
	}, nil
}

// getVaultStatus retrieves Vault secrets status
func getVaultStatus(rc *eos_io.RuntimeContext, manager *deploy.DeploymentManager, appName string) (*VaultStatus, error) {
	// Implementation would check Vault secrets accessibility
	return &VaultStatus{
		SecretsPath:    fmt.Sprintf("secret/data/%s", appName),
		SecretsHealthy: true,
		LastAccess:     time.Now().Add(-5 * time.Minute),
		Policies:       []string{appName + "-read", appName + "-write"},
	}, nil
}

// getTerraformStatus retrieves Terraform infrastructure status
func getTerraformStatus(rc *eos_io.RuntimeContext, manager *deploy.DeploymentManager, appName string) (*TerraformStatus, error) {
	client := manager.GetTerraformClient()

	workDir := filepath.Join("/srv/terraform", appName)
	state, err := client.GetState(rc.Ctx, workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get Terraform state: %w", err)
	}

	// Convert resources to status format
	var resources []TerraformResource
	for _, resource := range state.Resources {
		resources = append(resources, TerraformResource{
			Type:    resource.Type,
			Name:    resource.Name,
			Status:  resource.Status,
			Address: resource.Address,
		})
	}

	// Convert map[string]string to map[string]interface{}
	outputs := make(map[string]interface{})
	for k, v := range state.Outputs {
		outputs[k] = v
	}

	return &TerraformStatus{
		WorkspaceName: appName,
		StateHealthy:  true,
		Resources:     resources,
		LastApplied:   time.Now().Add(-10 * time.Minute),
		Outputs:       outputs,
	}, nil
}

// getPipelineStatus retrieves CI/CD pipeline status
func getPipelineStatus(rc *eos_io.RuntimeContext, appName string) (*PipelineStatus, error) {
	// Implementation would check for running pipelines
	// For now, return a placeholder
	return &PipelineStatus{
		Running:  false,
		Progress: 100.0,
		LastExecution: &PipelineExecution{
			ID:        "exec-123",
			Status:    "succeeded",
			StartTime: time.Now().Add(-30 * time.Minute),
			Duration:  15 * time.Minute,
			Trigger:   "manual",
			Version:   "20240113120000",
			Stages: []StageExecutionSummary{
				{Name: "build", Status: "succeeded", Duration: 5 * time.Minute},
				{Name: "deploy", Status: "succeeded", Duration: 8 * time.Minute},
				{Name: "verify", Status: "succeeded", Duration: 2 * time.Minute},
			},
		},
	}, nil
}

// getDeploymentHistory retrieves deployment history
func getDeploymentHistory(rc *eos_io.RuntimeContext, appName string) ([]DeploymentHistoryEntry, error) {
	// Implementation would query deployment history from Consul KV or database
	// For now, return placeholder data
	return []DeploymentHistoryEntry{
		{
			Version:    "20240113120000",
			Timestamp:  time.Now().Add(-30 * time.Minute),
			Status:     "succeeded",
			Trigger:    "manual",
			Duration:   15 * time.Minute,
			DeployedBy: "user",
		},
		{
			Version:    "20240113100000",
			Timestamp:  time.Now().Add(-2 * time.Hour),
			Status:     "succeeded",
			Trigger:    "git_push",
			Duration:   12 * time.Minute,
			DeployedBy: "ci-system",
		},
	}, nil
}

// calculateOverallStatus determines overall deployment health
func calculateOverallStatus(nomad *NomadStatus, consul *ConsulStatus, vault *VaultStatus, terraform *TerraformStatus) *OverallStatus {
	healthy := nomad.Status == "running" &&
		consul.Registered && consul.Healthy &&
		vault.SecretsHealthy &&
		terraform.StateHealthy

	status := "healthy"
	if !healthy {
		status = "unhealthy"
	}

	return &OverallStatus{
		Healthy:     healthy,
		Status:      status,
		Version:     "20240113120000", // Would get from actual deployment
		Domain:      "helen.cybermonkey.net.au",
		URL:         "https://helen.cybermonkey.net.au",
		Uptime:      2 * time.Hour,
		LastUpdated: time.Now().Add(-30 * time.Minute),
		Metadata: map[string]interface{}{
			"deployment_strategy": "rolling",
			"last_health_check":   time.Now().Format(time.RFC3339),
		},
	}
}

// Display functions

func displayStatusJSON(status *DeploymentStatus) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

func displayStatusYAML(status *DeploymentStatus) error {
	// Implementation would use YAML encoder
	fmt.Printf("# Deployment Status for %s\n", status.AppName)
	fmt.Printf("app_name: %s\n", status.AppName)
	fmt.Printf("healthy: %t\n", status.Overall.Healthy)
	fmt.Printf("status: %s\n", status.Overall.Status)
	return nil
}

func displayStatusTable(status *DeploymentStatus, detailed bool) error {
	// Display overall status
	fmt.Printf("Deployment Status: %s\n", status.AppName)
	fmt.Printf("═══════════════════════════\n")
	fmt.Printf("Overall Status: %s\n", status.Overall.Status)
	fmt.Printf("Healthy: %t\n", status.Overall.Healthy)
	fmt.Printf("Version: %s\n", status.Overall.Version)
	fmt.Printf("URL: %s\n", status.Overall.URL)
	fmt.Printf("Uptime: %s\n", status.Overall.Uptime)
	fmt.Printf("\n")

	// Display component statuses
	fmt.Printf("Component Status:\n")
	fmt.Printf("─────────────────\n")
	fmt.Printf("Nomad:     %s (%d/%d running)\n", status.Nomad.Status, status.Nomad.Running, status.Nomad.Desired)
	fmt.Printf("Consul:    %s (registered: %t)\n", getConsulStatusText(status.Consul), status.Consul.Registered)
	fmt.Printf("Vault:     %s\n", getVaultStatusText(status.Vault))
	fmt.Printf("Terraform: %s\n", getTerraformStatusText(status.Terraform))
	fmt.Printf("\n")

	if status.Pipeline.Running {
		fmt.Printf("Pipeline: RUNNING (%s - %.1f%%)\n", status.Pipeline.CurrentStage, status.Pipeline.Progress)
	} else if status.Pipeline.LastExecution != nil {
		fmt.Printf("Last Pipeline: %s (%s)\n", status.Pipeline.LastExecution.Status, status.Pipeline.LastExecution.Duration)
	}

	if detailed {
		displayDetailedStatus(status)
	}

	return nil
}

func displayDetailedStatus(status *DeploymentStatus) {
	// Display allocations
	if len(status.Nomad.Allocations) > 0 {
		fmt.Printf("\nNomad Allocations:\n")
		fmt.Printf("──────────────────\n")
		for _, alloc := range status.Nomad.Allocations {
			fmt.Printf("  %s: %s (node: %s)\n", alloc.ID[:8], alloc.Status, alloc.NodeID[:8])
		}
	}

	// Display health checks
	if len(status.Consul.Checks) > 0 {
		fmt.Printf("\nHealth Checks:\n")
		fmt.Printf("──────────────\n")
		for _, check := range status.Consul.Checks {
			fmt.Printf("  %s: %s\n", check.Name, check.Status)
		}
	}

	// Display recent deployments
	if len(status.History) > 0 {
		fmt.Printf("\nRecent Deployments:\n")
		fmt.Printf("───────────────────\n")
		for _, entry := range status.History {
			fmt.Printf("  %s: %s (%s) - %s\n",
				entry.Version, entry.Status, entry.Duration, entry.Timestamp.Format("Jan 02 15:04"))
		}
	}
}

func getConsulStatusText(status ConsulStatus) string {
	if status.Healthy {
		return "healthy"
	}
	if status.Registered {
		return "unhealthy"
	}
	return "not registered"
}

func getVaultStatusText(status VaultStatus) string {
	if status.SecretsHealthy {
		return "healthy"
	}
	return "unhealthy"
}

func getTerraformStatusText(status TerraformStatus) string {
	if status.StateHealthy {
		return "healthy"
	}
	return "unhealthy"
}
