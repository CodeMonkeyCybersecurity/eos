// pkg/salt/orchestrator/enhancer.go
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt/client"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OrchestrationMode defines how commands should be executed
type OrchestrationMode string

const (
	OrchestrationModeDirect OrchestrationMode = "direct"
	OrchestrationModeSalt   OrchestrationMode = "salt"
)

// OrchestrationOptions contains configuration for Salt orchestration
type OrchestrationOptions struct {
	Mode          OrchestrationMode `json:"mode"`
	Target        string            `json:"target"`
	BatchSize     int               `json:"batch_size"`
	Pillar        map[string]string `json:"pillar"`
	Grains        map[string]string `json:"grains"`
	Async         bool              `json:"async"`
	StateTest     bool              `json:"state_test"`
	Timeout       time.Duration     `json:"timeout"`
	Environment   string            `json:"environment"`
	TargetType    string            `json:"target_type"`
	Concurrent    bool              `json:"concurrent"`
}

// OrchestrationResult contains the result of an orchestrated operation
type OrchestrationResult struct {
	Mode      OrchestrationMode `json:"mode"`
	JobID     string            `json:"job_id,omitempty"`
	Success   bool              `json:"success"`
	Duration  time.Duration     `json:"duration"`
	Message   string            `json:"message"`
	Details   interface{}       `json:"details,omitempty"`
	Minions   []string          `json:"minions,omitempty"`
	Failed    []string          `json:"failed,omitempty"`
}

// DirectExecutor represents a function that executes commands directly
type DirectExecutor func(rc *eos_io.RuntimeContext) error

// SaltOperation represents a Salt state or command to execute
type SaltOperation struct {
	Type     string                 `json:"type"`     // state, command, orchestrate
	Module   string                 `json:"module"`   // Salt module/state name
	Function string                 `json:"function"` // Function within module
	Args     []string               `json:"args"`
	Kwargs   map[string]interface{} `json:"kwargs"`
	Pillar   map[string]interface{} `json:"pillar"`
}

// Enhancer provides orchestration capabilities to existing commands
type Enhancer struct {
	saltClient client.SaltClient
	rc         *eos_io.RuntimeContext
}

// NewEnhancer creates a new orchestration enhancer
func NewEnhancer(rc *eos_io.RuntimeContext, saltClient client.SaltClient) *Enhancer {
	return &Enhancer{
		saltClient: saltClient,
		rc:         rc,
	}
}

// AddOrchestrationFlags adds Salt orchestration flags to a command
func AddOrchestrationFlags(cmd *cobra.Command) {
	cmd.Flags().String("orchestrator", "direct", "Execution orchestrator (direct|salt)")
	cmd.Flags().String("salt-target", "*", "Salt targeting expression when using Salt orchestrator")
	cmd.Flags().Int("salt-batch", 0, "Salt batch size (0 = all at once)")
	cmd.Flags().StringToString("salt-pillar", nil, "Salt pillar data")
	cmd.Flags().StringToString("salt-grains", nil, "Salt grain matching")
	cmd.Flags().Bool("salt-async", false, "Run Salt command asynchronously")
	cmd.Flags().Bool("salt-test", false, "Run Salt state in test mode")
	cmd.Flags().Duration("salt-timeout", 5*time.Minute, "Salt operation timeout")
	cmd.Flags().String("salt-env", "base", "Salt environment")
	cmd.Flags().String("salt-target-type", "glob", "Salt target type")
	cmd.Flags().Bool("salt-concurrent", false, "Enable concurrent execution")
}

// GetOrchestrationOptions extracts orchestration options from command flags
func GetOrchestrationOptions(cmd *cobra.Command) (*OrchestrationOptions, error) {
	orchestrator, _ := cmd.Flags().GetString("orchestrator")
	target, _ := cmd.Flags().GetString("salt-target")
	batchSize, _ := cmd.Flags().GetInt("salt-batch")
	pillar, _ := cmd.Flags().GetStringToString("salt-pillar")
	grains, _ := cmd.Flags().GetStringToString("salt-grains")
	async, _ := cmd.Flags().GetBool("salt-async")
	stateTest, _ := cmd.Flags().GetBool("salt-test")
	timeout, _ := cmd.Flags().GetDuration("salt-timeout")
	environment, _ := cmd.Flags().GetString("salt-env")
	targetType, _ := cmd.Flags().GetString("salt-target-type")
	concurrent, _ := cmd.Flags().GetBool("salt-concurrent")

	mode := OrchestrationModeDirect
	if orchestrator == "salt" {
		mode = OrchestrationModeSalt
	}

	return &OrchestrationOptions{
		Mode:        mode,
		Target:      target,
		BatchSize:   batchSize,
		Pillar:      pillar,
		Grains:      grains,
		Async:       async,
		StateTest:   stateTest,
		Timeout:     timeout,
		Environment: environment,
		TargetType:  targetType,
		Concurrent:  concurrent,
	}, nil
}

// ExecuteWithOrchestration executes a command with orchestration support
func (e *Enhancer) ExecuteWithOrchestration(
	ctx context.Context,
	options *OrchestrationOptions,
	directExec DirectExecutor,
	saltOp *SaltOperation,
) (*OrchestrationResult, error) {
	logger := otelzap.Ctx(ctx)
	
	startTime := time.Now()
	
	logger.Info("Executing with orchestration",
		zap.String("mode", string(options.Mode)),
		zap.String("target", options.Target))

	switch options.Mode {
	case OrchestrationModeSalt:
		return e.executeSaltOperation(ctx, options, saltOp)
	case OrchestrationModeDirect:
		return e.executeDirectOperation(ctx, options, directExec, startTime)
	default:
		return nil, fmt.Errorf("unsupported orchestration mode: %s", options.Mode)
	}
}

// executeSaltOperation executes an operation through Salt
func (e *Enhancer) executeSaltOperation(ctx context.Context, options *OrchestrationOptions, saltOp *SaltOperation) (*OrchestrationResult, error) {
	logger := otelzap.Ctx(ctx)
	
	if e.saltClient == nil {
		return nil, fmt.Errorf("Salt client not configured")
	}

	logger.Info("Executing Salt operation",
		zap.String("type", saltOp.Type),
		zap.String("module", saltOp.Module),
		zap.String("function", saltOp.Function))

	startTime := time.Now()
	
	// Create context with timeout
	opCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	var jobID string
	var err error

	switch saltOp.Type {
	case "state":
		jobID, err = e.executeSaltState(opCtx, options, saltOp)
	case "command":
		jobID, err = e.executeSaltCommand(opCtx, options, saltOp)
	case "orchestrate":
		jobID, err = e.executeSaltOrchestrate(opCtx, options, saltOp)
	default:
		return nil, fmt.Errorf("unsupported Salt operation type: %s", saltOp.Type)
	}

	duration := time.Since(startTime)

	if err != nil {
		return &OrchestrationResult{
			Mode:     OrchestrationModeSalt,
			Success:  false,
			Duration: duration,
			Message:  fmt.Sprintf("Salt operation failed: %v", err),
		}, err
	}

	result := &OrchestrationResult{
		Mode:     OrchestrationModeSalt,
		JobID:    jobID,
		Success:  true,
		Duration: duration,
		Message:  "Salt operation completed successfully",
	}

	// If not async, wait for completion and get results
	if !options.Async && jobID != "" {
		return e.waitForSaltJob(opCtx, result, jobID)
	}

	return result, nil
}

// executeDirectOperation executes an operation directly
func (e *Enhancer) executeDirectOperation(ctx context.Context, options *OrchestrationOptions, directExec DirectExecutor, startTime time.Time) (*OrchestrationResult, error) {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Executing direct operation")

	err := directExec(e.rc)
	duration := time.Since(startTime)

	result := &OrchestrationResult{
		Mode:     OrchestrationModeDirect,
		Duration: duration,
		Success:  err == nil,
	}

	if err != nil {
		result.Message = fmt.Sprintf("Direct operation failed: %v", err)
		return result, err
	}

	result.Message = "Direct operation completed successfully"
	return result, nil
}

// executeSaltState executes a Salt state
func (e *Enhancer) executeSaltState(ctx context.Context, options *OrchestrationOptions, saltOp *SaltOperation) (string, error) {
	// Combine pillar data
	pillar := make(map[string]interface{})
	for k, v := range options.Pillar {
		pillar[k] = v
	}
	for k, v := range saltOp.Pillar {
		pillar[k] = v
	}

	req := &client.StateRequest{
		Client:     client.ClientTypeLocal,
		Target:     options.Target,
		Function:   fmt.Sprintf("%s.%s", saltOp.Module, saltOp.Function),
		Args:       saltOp.Args,
		TargetType: options.TargetType,
		Pillar:     pillar,
		Test:       options.StateTest,
		Concurrent: options.Concurrent,
	}

	response, err := e.saltClient.RunState(ctx, req)
	if err != nil {
		return "", err
	}

	return response.JobID, nil
}

// executeSaltCommand executes a Salt command
func (e *Enhancer) executeSaltCommand(ctx context.Context, options *OrchestrationOptions, saltOp *SaltOperation) (string, error) {
	req := &client.CommandRequest{
		Client:     client.ClientTypeLocal,
		Target:     options.Target,
		Function:   fmt.Sprintf("%s.%s", saltOp.Module, saltOp.Function),
		Args:       saltOp.Args,
		Kwargs:     saltOp.Kwargs,
		TargetType: options.TargetType,
	}

	if options.BatchSize > 0 {
		req.BatchSize = fmt.Sprintf("%d", options.BatchSize)
	}

	response, err := e.saltClient.RunCommand(ctx, req)
	if err != nil {
		return "", err
	}

	return response.JobID, nil
}

// executeSaltOrchestrate executes Salt orchestration
func (e *Enhancer) executeSaltOrchestrate(ctx context.Context, options *OrchestrationOptions, saltOp *SaltOperation) (string, error) {
	// Combine pillar data
	pillar := make(map[string]interface{})
	for k, v := range options.Pillar {
		pillar[k] = v
	}
	for k, v := range saltOp.Pillar {
		pillar[k] = v
	}

	req := &client.OrchestrationRequest{
		Client:   client.ClientTypeRunner,
		Function: "state.orchestrate",
		Mods:     []string{saltOp.Module},
		Pillar:   pillar,
		Kwargs:   saltOp.Kwargs,
	}

	response, err := e.saltClient.RunOrchestrate(ctx, req)
	if err != nil {
		return "", err
	}

	return response.JobID, nil
}

// waitForSaltJob waits for a Salt job to complete and updates the result
func (e *Enhancer) waitForSaltJob(ctx context.Context, result *OrchestrationResult, jobID string) (*OrchestrationResult, error) {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Waiting for Salt job completion", zap.String("job_id", jobID))

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			result.Success = false
			result.Message = "Operation timed out"
			return result, ctx.Err()
		case <-ticker.C:
			job, err := e.saltClient.GetJob(ctx, jobID)
			if err != nil {
				logger.Warn("Failed to get job status", zap.Error(err))
				continue
			}

			// Check if job is complete
			totalMinions := len(job.Minions)
			missingMinions := len(job.Missing)
			expectedMinions := totalMinions - missingMinions

			if job.Result != nil && len(job.Result) >= expectedMinions {
				// Job completed, analyze results
				result.Minions = job.Minions
				result.Details = job.Result

				// Check for failures
				hasFailures := false
				failedMinions := []string{}

				for minionID, minionResult := range job.Result {
					if retcode, ok := minionResult["retcode"].(float64); ok && retcode != 0 {
						hasFailures = true
						failedMinions = append(failedMinions, minionID)
					}
				}

				result.Failed = failedMinions
				result.Success = !hasFailures

				if hasFailures {
					result.Message = fmt.Sprintf("Operation completed with failures on %d minions", len(failedMinions))
				} else {
					result.Message = fmt.Sprintf("Operation completed successfully on %d minions", len(job.Result))
				}

				return result, nil
			}
		}
	}
}

// CreateSaltOperation creates a Salt operation for common EOS tasks
func CreateSaltOperation(operationType, module, function string, args []string) *SaltOperation {
	return &SaltOperation{
		Type:     operationType,
		Module:   module,
		Function: function,
		Args:     args,
		Kwargs:   make(map[string]interface{}),
		Pillar:   make(map[string]interface{}),
	}
}

// CreateStateOperation creates a Salt state operation
func CreateStateOperation(stateName string, pillar map[string]interface{}) *SaltOperation {
	return &SaltOperation{
		Type:   "state",
		Module: stateName,
		Function: "apply",
		Pillar: pillar,
	}
}

// CreateCommandOperation creates a Salt command operation
func CreateCommandOperation(module, function string, args []string) *SaltOperation {
	return &SaltOperation{
		Type:     "command",
		Module:   module,
		Function: function,
		Args:     args,
		Kwargs:   make(map[string]interface{}),
	}
}

// CreateOrchestrationOperation creates a Salt orchestration operation
func CreateOrchestrationOperation(orchestrationName string, pillar map[string]interface{}) *SaltOperation {
	return &SaltOperation{
		Type:   "orchestrate",
		Module: orchestrationName,
		Pillar: pillar,
	}
}