// pkg/nomad/client.go - Nomad API client wrapper

package nomad

import (
	"context"
	"fmt"
	"time"

	nomadapi "github.com/hashicorp/nomad/api"
	"go.uber.org/zap"
)

// Client wraps the Nomad API client with convenience methods
type Client struct {
	api    *nomadapi.Client
	logger *zap.Logger
}

// NewClient creates a new Nomad client
// address should be in format "http://localhost:4646"
func NewClient(address string, logger *zap.Logger) (*Client, error) {
	config := nomadapi.DefaultConfig()
	config.Address = address

	client, err := nomadapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	return &Client{
		api:    client,
		logger: logger,
	}, nil
}

// ParseHCL parses a Nomad job HCL string into a Job struct
func (c *Client) ParseHCL(hcl string) (*nomadapi.Job, error) {
	jobs := c.api.Jobs()

	job, err := jobs.ParseHCL(hcl, true) // canonicalize=true
	if err != nil {
		return nil, fmt.Errorf("failed to parse HCL: %w", err)
	}

	return job, nil
}

// SubmitJob submits a Nomad job
func (c *Client) SubmitJob(ctx context.Context, job *nomadapi.Job) (*nomadapi.JobRegisterResponse, error) {
	jobs := c.api.Jobs()

	resp, _, err := jobs.Register(job, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to register job: %w", err)
	}

	c.logger.Info("Job submitted successfully",
		zap.String("job_id", *job.ID),
		zap.String("eval_id", resp.EvalID))

	return resp, nil
}

// GetJob retrieves a job by ID
func (c *Client) GetJob(ctx context.Context, jobID string) (*nomadapi.Job, error) {
	jobs := c.api.Jobs()

	job, _, err := jobs.Info(jobID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

	return job, nil
}

// GetJobStatus retrieves the status of a job
func (c *Client) GetJobStatus(ctx context.Context, jobID string) (string, error) {
	job, err := c.GetJob(ctx, jobID)
	if err != nil {
		return "", err
	}

	if job.Status == nil {
		return "unknown", nil
	}

	return *job.Status, nil
}

// StopJob stops a running job
func (c *Client) StopJob(ctx context.Context, jobID string, purge bool) error {
	jobs := c.api.Jobs()

	_, _, err := jobs.Deregister(jobID, purge, nil)
	if err != nil {
		return fmt.Errorf("failed to stop job: %w", err)
	}

	c.logger.Info("Job stopped successfully",
		zap.String("job_id", jobID),
		zap.Bool("purged", purge))

	return nil
}

// ListJobs lists all jobs
func (c *Client) ListJobs(ctx context.Context) ([]*nomadapi.JobListStub, error) {
	jobs := c.api.Jobs()

	jobList, _, err := jobs.List(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	return jobList, nil
}

// GetAllocations retrieves all allocations for a job
func (c *Client) GetAllocations(ctx context.Context, jobID string) ([]*nomadapi.AllocationListStub, error) {
	jobs := c.api.Jobs()

	allocs, _, err := jobs.Allocations(jobID, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocations: %w", err)
	}

	return allocs, nil
}

// GetAllocation retrieves a specific allocation
func (c *Client) GetAllocation(ctx context.Context, allocID string) (*nomadapi.Allocation, error) {
	allocs := c.api.Allocations()

	alloc, _, err := allocs.Info(allocID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get allocation: %w", err)
	}

	return alloc, nil
}

// WaitForJobRunning waits for a job to reach "running" status
func (c *Client) WaitForJobRunning(ctx context.Context, jobID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Get job allocations
		allocs, err := c.GetAllocations(ctx, jobID)
		if err != nil {
			return err
		}

		if len(allocs) == 0 {
			c.logger.Debug("No allocations yet, waiting",
				zap.String("job_id", jobID))
			time.Sleep(2 * time.Second)
			continue
		}

		// Check if all allocations are running
		allRunning := true
		for _, alloc := range allocs {
			if alloc.ClientStatus != "running" {
				allRunning = false
				c.logger.Debug("Allocation not running yet",
					zap.String("job_id", jobID),
					zap.String("alloc_id", alloc.ID),
					zap.String("status", alloc.ClientStatus))
				break
			}
		}

		if allRunning {
			c.logger.Info("All allocations running",
				zap.String("job_id", jobID),
				zap.Int("count", len(allocs)))
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for job to reach running status: %s", jobID)
}

// JobExists checks if a job exists
func (c *Client) JobExists(ctx context.Context, jobID string) (bool, error) {
	_, err := c.GetJob(ctx, jobID)
	if err != nil {
		// Check if it's a "not found" error by checking the error message
		// Nomad API returns an error for non-existent jobs
		if err.Error() == "Unexpected response code: 404" ||
			err.Error() == "job not found" {
			return false, nil
		}
		// For other errors, return them
		return false, err
	}
	return true, nil
}

// GetNodeStatus gets the status of Nomad nodes
func (c *Client) GetNodeStatus(ctx context.Context) ([]*nomadapi.NodeListStub, error) {
	nodes := c.api.Nodes()

	nodeList, _, err := nodes.List(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	return nodeList, nil
}

// CheckHealth checks if Nomad is healthy
func (c *Client) CheckHealth(ctx context.Context) error {
	// Try to get the leader
	status := c.api.Status()
	leader, err := status.Leader()
	if err != nil {
		return fmt.Errorf("failed to get leader: %w", err)
	}

	if leader == "" {
		return fmt.Errorf("no leader elected")
	}

	c.logger.Debug("Nomad health check passed",
		zap.String("leader", leader))

	return nil
}
