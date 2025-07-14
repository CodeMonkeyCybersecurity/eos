// pkg/orchestrator/nomad/client.go
package nomad

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator"
	"github.com/hashicorp/nomad/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Client provides Nomad orchestration capabilities
type Client struct {
	rc         *eos_io.RuntimeContext
	nomadClient *api.Client
	config      Config
}

// Config holds Nomad client configuration
type Config struct {
	Address    string
	Region     string
	Namespace  string
	AuthToken  string
	TLSConfig  *api.TLSConfig
	Timeout    time.Duration
}

// NewClient creates a new Nomad orchestration client
func NewClient(rc *eos_io.RuntimeContext, config Config) (*Client, error) {
	nomadConfig := api.DefaultConfig()
	nomadConfig.Address = config.Address
	
	if config.Region != "" {
		nomadConfig.Region = config.Region
	}
	
	if config.Namespace != "" {
		nomadConfig.Namespace = config.Namespace
	}
	
	if config.AuthToken != "" {
		nomadConfig.SecretID = config.AuthToken
	}
	
	if config.TLSConfig != nil {
		nomadConfig.TLSConfig = config.TLSConfig
	}
	
	nomadClient, err := api.NewClient(nomadConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}
	
	return &Client{
		rc:          rc,
		nomadClient: nomadClient,
		config:      config,
	}, nil
}

// WaitForJob waits for a Nomad job to reach a stable state
func (c *Client) WaitForJob(ctx context.Context, jobID string, timeout time.Duration) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Waiting for Nomad job to stabilize",
		zap.String("job_id", jobID),
		zap.Duration("timeout", timeout))
	
	deadline := time.Now().Add(timeout)
	
	for {
		// Check if context is cancelled or deadline exceeded
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for job")
		default:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for job to stabilize")
			}
		}
		
		// Get job status
		job, _, err := c.nomadClient.Jobs().Info(jobID, nil)
		if err != nil {
			return fmt.Errorf("failed to get job info: %w", err)
		}
		
		if job == nil {
			return fmt.Errorf("job not found: %s", jobID)
		}
		
		// Get job allocations
		allocs, _, err := c.nomadClient.Jobs().Allocations(jobID, false, nil)
		if err != nil {
			return fmt.Errorf("failed to get job allocations: %w", err)
		}
		
		// Check allocation statuses
		running := 0
		pending := 0
		failed := 0
		
		for _, alloc := range allocs {
			switch alloc.ClientStatus {
			case "running":
				running++
			case "pending":
				pending++
			case "failed", "lost":
				failed++
			}
		}
		
		logger.Debug("Job allocation status",
			zap.String("job_id", jobID),
			zap.Int("running", running),
			zap.Int("pending", pending),
			zap.Int("failed", failed))
		
		// Check if job is stable
		if failed > 0 {
			return fmt.Errorf("job has %d failed allocations", failed)
		}
		
		expectedCount := 1 // Default for service jobs
		if job.Type != nil && *job.Type == "batch" {
			expectedCount = 0 // Batch jobs complete
		}
		
		if pending == 0 && running >= expectedCount {
			logger.Info("Job is stable",
				zap.String("job_id", jobID),
				zap.Int("running_allocations", running))
			return nil
		}
		
		// Wait before checking again
		time.Sleep(5 * time.Second)
	}
}

// GetJobStatus returns the current status of a Nomad job
func (c *Client) GetJobStatus(ctx context.Context, jobID string) (interface{}, error) {
	job, _, err := c.nomadClient.Jobs().Info(jobID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get job info: %w", err)
	}
	
	if job == nil {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	
	// Get allocations
	allocs, _, err := c.nomadClient.Jobs().Allocations(jobID, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get job allocations: %w", err)
	}
	
	// Get deployment status
	deployments, _, err := c.nomadClient.Jobs().Deployments(jobID, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get job deployments: %w", err)
	}
	
	status := &JobStatus{
		ID:          *job.ID,
		Name:        *job.Name,
		Type:        *job.Type,
		Status:      *job.Status,
		Allocations: make([]AllocationStatus, 0, len(allocs)),
	}
	
	// Add allocation details
	for _, alloc := range allocs {
		allocStatus := AllocationStatus{
			ID:           alloc.ID,
			Name:         alloc.Name,
			NodeID:       alloc.NodeID,
			ClientStatus: alloc.ClientStatus,
			DesiredStatus: alloc.DesiredStatus,
		}
		
		// Get task states
		if alloc.TaskStates != nil {
			allocStatus.TaskStates = make(map[string]TaskState)
			for taskName, taskState := range alloc.TaskStates {
				allocStatus.TaskStates[taskName] = TaskState{
					State:      taskState.State,
					Failed:     taskState.Failed,
					StartedAt:  &taskState.StartedAt,
					FinishedAt: &taskState.FinishedAt,
				}
			}
		}
		
		status.Allocations = append(status.Allocations, allocStatus)
	}
	
	// Add deployment details
	if len(deployments) > 0 {
		latest := deployments[0]
		status.Deployment = &DeploymentStatus{
			ID:                 latest.ID,
			Status:             latest.Status,
			StatusDescription:  latest.StatusDescription,
		}
	}
	
	// Determine overall health
	status.Healthy = c.isJobHealthy(status)
	
	return status, nil
}

// isJobHealthy determines if a job is healthy based on its status
func (c *Client) isJobHealthy(status *JobStatus) bool {
	if status.Status != "running" {
		return false
	}
	
	// Check allocations
	for _, alloc := range status.Allocations {
		if alloc.ClientStatus != "running" || alloc.DesiredStatus != "run" {
			return false
		}
		
		// Check task states
		for _, task := range alloc.TaskStates {
			if task.State != "running" || task.Failed {
				return false
			}
		}
	}
	
	// Check deployment
	if status.Deployment != nil && status.Deployment.Status != "successful" {
		return false
	}
	
	return true
}

// GetLogs retrieves logs for a job
func (c *Client) GetLogs(ctx context.Context, jobID string, options orchestrator.LogOptions) ([]orchestrator.LogEntry, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	// Get job allocations
	allocs, _, err := c.nomadClient.Jobs().Allocations(jobID, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get job allocations: %w", err)
	}
	
	if len(allocs) == 0 {
		return nil, fmt.Errorf("no allocations found for job: %s", jobID)
	}
	
	var logs []orchestrator.LogEntry
	
	// Get logs from the most recent allocation
	alloc := allocs[0]
	
	// Determine task name
	taskName := options.Container
	if taskName == "" {
		// Use the first task
		for name := range alloc.TaskStates {
			taskName = name
			break
		}
	}
	
	logger.Debug("Retrieving logs",
		zap.String("allocation_id", alloc.ID),
		zap.String("task", taskName))
	
	// TODO: Implement proper log streaming using Nomad API
	// For now, return a placeholder indicating logs are available via nomad CLI
	logs = append(logs, orchestrator.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   fmt.Sprintf("Logs available via: nomad alloc logs %s %s", alloc.ID, taskName),
		Source:    fmt.Sprintf("%s/%s", alloc.ID[:8], taskName),
	})
	
	return logs, nil
}

// StopJob stops a Nomad job
func (c *Client) StopJob(ctx context.Context, jobID string) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Stopping Nomad job", zap.String("job_id", jobID))
	
	_, _, err := c.nomadClient.Jobs().Deregister(jobID, false, nil)
	if err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
	}
	
	return nil
}

// JobStatus represents the status of a Nomad job
type JobStatus struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Type        string              `json:"type"`
	Status      string              `json:"status"`
	Healthy     bool                `json:"healthy"`
	Allocations []AllocationStatus  `json:"allocations"`
	Deployment  *DeploymentStatus   `json:"deployment,omitempty"`
}

// AllocationStatus represents the status of a job allocation
type AllocationStatus struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	NodeID        string               `json:"node_id"`
	ClientStatus  string               `json:"client_status"`
	DesiredStatus string               `json:"desired_status"`
	TaskStates    map[string]TaskState `json:"task_states"`
}

// TaskState represents the state of a task within an allocation
type TaskState struct {
	State      string     `json:"state"`
	Failed     bool       `json:"failed"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// DeploymentStatus represents the status of a job deployment
type DeploymentStatus struct {
	ID                string     `json:"id"`
	Status            string     `json:"status"`
	StatusDescription string     `json:"status_description"`
	RequireProgressBy *time.Time `json:"require_progress_by,omitempty"`
}

// VerifyHealth verifies that a job is healthy
func (c *Client) VerifyHealth(ctx context.Context, jobID string) error {
	status, err := c.GetJobStatus(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job status: %w", err)
	}
	
	// Check if job is healthy (assuming status is a map)
	if statusMap, ok := status.(map[string]interface{}); ok {
		if running, ok := statusMap["running"].(int); !ok || running == 0 {
			return fmt.Errorf("job is not running")
		}
		if failed, ok := statusMap["failed"].(int); ok && failed > 0 {
			return fmt.Errorf("job has failed allocations")
		}
	}
	
	return nil
}