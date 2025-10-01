package orchestration

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	nomad "github.com/hashicorp/nomad/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NomadOrchestrator manages VM workloads through Nomad
type NomadOrchestrator struct {
	client *nomad.Client
	logger otelzap.LoggerWithCtx
	rc     *eos_io.RuntimeContext
}

// NewNomadOrchestrator creates a new Nomad orchestrator
func NewNomadOrchestrator(rc *eos_io.RuntimeContext, nomadAddr string) (*NomadOrchestrator, error) {
	logger := otelzap.Ctx(rc.Ctx)

	config := nomad.DefaultConfig()
	if nomadAddr != "" {
		config.Address = nomadAddr
	}

	client, err := nomad.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Test connection
	self, err := client.Agent().Self()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Nomad: %w", err)
	}

	logger.Info("Connected to Nomad cluster",
		zap.String("node_name", self.Member.Name),
		zap.String("address", config.Address))

	return &NomadOrchestrator{
		client: client,
		logger: logger,
		rc:     rc,
	}, nil
}

// CreateVMJob creates a Nomad job for a VM workload
func (no *NomadOrchestrator) CreateVMJob(vmJob *NomadVMJob) error {
	no.logger.Info("Creating Nomad job for VM",
		zap.String("job_id", vmJob.ID),
		zap.String("vm_name", vmJob.VMName))

	// Create Nomad job specification
	job := &nomad.Job{
		ID:          &vmJob.ID,
		Name:        &vmJob.Name,
		Type:        &vmJob.Type,
		Priority:    &vmJob.Priority,
		Datacenters: vmJob.Datacenters,
		Meta:        vmJob.Meta,
	}

	// Add task group for VM management
	taskGroupName := "vm-management"
	taskGroup := &nomad.TaskGroup{
		Name: &taskGroupName,
		Tasks: []*nomad.Task{
			{
				Name:   "vm-monitor",
				Driver: "raw_exec",
				Config: map[string]interface{}{
					"command": "/usr/bin/bash",
					"args": []string{
						"-c",
						fmt.Sprintf(`while true; do
							virsh dominfo %s > /tmp/%s-status.txt 2>&1
							sleep 30
						done`, vmJob.VMName, vmJob.VMName),
					},
				},
				Resources: &nomad.Resources{
					CPU:      intPtr(100),
					MemoryMB: intPtr(64),
				},
				Meta: map[string]string{
					"vm_name": vmJob.VMName,
				},
			},
		},
		Meta: vmJob.Meta,
	}

	// Add constraints if specified
	if len(vmJob.Constraints) > 0 {
		taskGroup.Constraints = make([]*nomad.Constraint, 0, len(vmJob.Constraints))
		for _, c := range vmJob.Constraints {
			constraint := &nomad.Constraint{
				LTarget: c.Attribute,
				RTarget: c.Value,
				Operand: c.Operator,
			}
			taskGroup.Constraints = append(taskGroup.Constraints, constraint)
		}
	}

	job.TaskGroups = []*nomad.TaskGroup{taskGroup}

	// Register the job
	resp, _, err := no.client.Jobs().Register(job, nil)
	if err != nil {
		return fmt.Errorf("failed to register Nomad job: %w", err)
	}

	no.logger.Info("Nomad job created successfully",
		zap.String("job_id", vmJob.ID),
		zap.String("eval_id", resp.EvalID))

	// Store job metadata in Nomad variables (if available)
	// This is for tracking purposes
	if err := no.storeJobMetadata(vmJob); err != nil {
		no.logger.Warn("Failed to store job metadata",
			zap.String("job_id", vmJob.ID),
			zap.Error(err))
	}

	return nil
}

// DeleteVMJob removes a Nomad job
func (no *NomadOrchestrator) DeleteVMJob(jobID string) error {
	no.logger.Info("Deleting Nomad job", zap.String("job_id", jobID))

	// Deregister the job
	resp, _, err := no.client.Jobs().Deregister(jobID, true, nil)
	if err != nil {
		return fmt.Errorf("failed to deregister Nomad job: %w", err)
	}

	no.logger.Info("Nomad job deleted successfully",
		zap.String("job_id", jobID),
		zap.String("eval_id", resp))

	return nil
}

// GetJobStatus retrieves the status of a Nomad job
func (no *NomadOrchestrator) GetJobStatus(jobID string) (string, error) {
	job, _, err := no.client.Jobs().Info(jobID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get job info: %w", err)
	}

	if job == nil {
		return "not_found", nil
	}

	return *job.Status, nil
}

// ListVMJobs lists all VM-related Nomad jobs
func (no *NomadOrchestrator) ListVMJobs() ([]*NomadVMJob, error) {
	jobs, _, err := no.client.Jobs().List(&nomad.QueryOptions{
		Prefix: "vm-",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	var vmJobs []*NomadVMJob
	for _, jobStub := range jobs {
		// Get full job details
		job, _, err := no.client.Jobs().Info(jobStub.ID, nil)
		if err != nil {
			no.logger.Warn("Failed to get job details",
				zap.String("job_id", jobStub.ID),
				zap.Error(err))
			continue
		}

		// Extract VM name from job meta
		vmName := ""
		if job.Meta != nil {
			vmName = job.Meta["vm_name"]
		}

		vmJob := &NomadVMJob{
			ID:          jobStub.ID,
			Name:        jobStub.Name,
			VMName:      vmName,
			Type:        jobStub.Type,
			Priority:    jobStub.Priority,
			Datacenters: job.Datacenters,
			Meta:        job.Meta,
		}

		vmJobs = append(vmJobs, vmJob)
	}

	return vmJobs, nil
}

// ScaleVMPool scales a pool of VMs managed by Nomad
func (no *NomadOrchestrator) ScaleVMPool(poolName string, targetCount int) error {
	no.logger.Info("Scaling VM pool",
		zap.String("pool_name", poolName),
		zap.Int("target_count", targetCount))

	// Find the system job managing the pool
	jobID := fmt.Sprintf("vm-pool-%s", poolName)
	job, _, err := no.client.Jobs().Info(jobID, nil)
	if err != nil {
		return fmt.Errorf("failed to get pool job: %w", err)
	}

	if job == nil {
		return fmt.Errorf("VM pool job not found: %s", poolName)
	}

	// Update the job count
	if len(job.TaskGroups) > 0 {
		job.TaskGroups[0].Count = &targetCount

		// Update the job
		resp, _, err := no.client.Jobs().Register(job, nil)
		if err != nil {
			return fmt.Errorf("failed to scale VM pool: %w", err)
		}

		no.logger.Info("VM pool scaled successfully",
			zap.String("pool_name", poolName),
			zap.Int("new_count", targetCount),
			zap.String("eval_id", resp.EvalID))
	}

	return nil
}

// CreateVMPoolJob creates a Nomad system job to manage a VM pool
func (no *NomadOrchestrator) CreateVMPoolJob(pool *VMPool) error {
	no.logger.Info("Creating VM pool job",
		zap.String("pool_name", pool.Name),
		zap.Int("min_size", pool.MinSize),
		zap.Int("max_size", pool.MaxSize))

	jobID := fmt.Sprintf("vm-pool-%s", pool.Name)
	jobName := fmt.Sprintf("VM Pool: %s", pool.Name)
	jobType := "system"

	job := &nomad.Job{
		ID:          &jobID,
		Name:        &jobName,
		Type:        &jobType,
		Priority:    intPtr(50),
		Datacenters: []string{"dc1"},
		Meta: map[string]string{
			"pool_name":    pool.Name,
			"min_size":     fmt.Sprintf("%d", pool.MinSize),
			"max_size":     fmt.Sprintf("%d", pool.MaxSize),
			"vm_template":  pool.VMTemplate,
		},
	}

	// Create task group for pool management
	taskGroupName := "pool-manager"
	taskGroup := &nomad.TaskGroup{
		Name:  &taskGroupName,
		Count: &pool.CurrentSize,
		Tasks: []*nomad.Task{
			{
				Name:   "pool-controller",
				Driver: "raw_exec",
				Config: map[string]interface{}{
					"command": "/usr/bin/bash",
					"args": []string{
						"-c",
						fmt.Sprintf(`
							# Pool management script
							POOL_NAME="%s"
							MIN_SIZE=%d
							MAX_SIZE=%d

							while true; do
								# Check current VM count
								CURRENT=$(virsh list --all | grep "vm-pool-$POOL_NAME" | wc -l)

								# Log status
								echo "$(date): Pool $POOL_NAME has $CURRENT VMs (min: $MIN_SIZE, max: $MAX_SIZE)"

								# Auto-scaling logic would go here
								# This is a simplified monitoring loop

								sleep 60
							done
						`, pool.Name, pool.MinSize, pool.MaxSize),
					},
				},
				Resources: &nomad.Resources{
					CPU:      intPtr(100),
					MemoryMB: intPtr(128),
				},
			},
		},
		Meta: map[string]string{
			"pool_name": pool.Name,
		},
	}

	// Add scaling rules as meta if provided
	if pool.ScalingRules != nil {
		taskGroup.Meta["cpu_threshold_up"] = fmt.Sprintf("%f", pool.ScalingRules.CPUThresholdUp)
		taskGroup.Meta["cpu_threshold_down"] = fmt.Sprintf("%f", pool.ScalingRules.CPUThresholdDown)
		taskGroup.Meta["mem_threshold_up"] = fmt.Sprintf("%f", pool.ScalingRules.MemThresholdUp)
		taskGroup.Meta["mem_threshold_down"] = fmt.Sprintf("%f", pool.ScalingRules.MemThresholdDown)
		taskGroup.Meta["scale_up_increment"] = fmt.Sprintf("%d", pool.ScalingRules.ScaleUpIncrement)
		taskGroup.Meta["scale_down_decrement"] = fmt.Sprintf("%d", pool.ScalingRules.ScaleDownDecrement)
		taskGroup.Meta["cooldown_period"] = pool.ScalingRules.CooldownPeriod.String()
	}

	job.TaskGroups = []*nomad.TaskGroup{taskGroup}

	// Register the job
	resp, _, err := no.client.Jobs().Register(job, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM pool job: %w", err)
	}

	no.logger.Info("VM pool job created successfully",
		zap.String("pool_name", pool.Name),
		zap.String("eval_id", resp.EvalID))

	return nil
}

// storeJobMetadata stores job metadata for tracking
func (no *NomadOrchestrator) storeJobMetadata(vmJob *NomadVMJob) error {
	// This would typically store metadata in Nomad's variable store
	// or another persistent storage backend

	metadata := map[string]interface{}{
		"job_id":      vmJob.ID,
		"vm_name":     vmJob.VMName,
		"created_at":  time.Now().Unix(),
		"type":        vmJob.Type,
		"datacenters": vmJob.Datacenters,
		"meta":        vmJob.Meta,
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal job metadata: %w", err)
	}

	// Log the metadata for now
	no.logger.Debug("Job metadata stored",
		zap.String("job_id", vmJob.ID),
		zap.ByteString("metadata", data))

	return nil
}

// GetAllocationStatus gets the allocation status for a job
func (no *NomadOrchestrator) GetAllocationStatus(jobID string) (string, error) {
	allocs, _, err := no.client.Jobs().Allocations(jobID, false, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get allocations: %w", err)
	}

	if len(allocs) == 0 {
		return "pending", nil
	}

	// Return the status of the most recent allocation
	latestAlloc := allocs[0]
	for _, alloc := range allocs {
		if alloc.CreateIndex > latestAlloc.CreateIndex {
			latestAlloc = alloc
		}
	}

	return latestAlloc.ClientStatus, nil
}

// Helper function to create int pointer
func intPtr(i int) *int {
	return &i
}