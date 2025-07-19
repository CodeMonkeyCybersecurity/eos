// Package terraform provides infrastructure deployment runner
package terraform

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InfrastructureRunner orchestrates infrastructure deployments
type InfrastructureRunner struct {
	executor  *Executor
	saltPath  string
}

// NewInfrastructureRunner creates a new infrastructure runner
func NewInfrastructureRunner(workspaceDir, saltPath string) (*InfrastructureRunner, error) {
	executor, err := NewExecutor(workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create executor: %w", err)
	}

	return &InfrastructureRunner{
		executor: executor,
		saltPath: saltPath,
	}, nil
}

// DeploymentRequest represents a deployment request
type DeploymentRequest struct {
	Component    string
	Environment  string
	Services     []string
	Variables    map[string]any
	AutoApprove  bool
	DryRun       bool
}

// DeploymentResult represents the result of a deployment
type DeploymentResult struct {
	Success      bool
	Component    string
	Environment  string
	Outputs      map[string]Output
	Services     []ServiceDeploymentResult
	Duration     time.Duration
	Error        string
}

// ServiceDeploymentResult represents the result of a service deployment
type ServiceDeploymentResult struct {
	Name     string
	Success  bool
	Endpoint string
	Error    string
}

// Deploy orchestrates a complete infrastructure deployment
func (r *InfrastructureRunner) Deploy(rc *eos_io.RuntimeContext, req DeploymentRequest) (*DeploymentResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting infrastructure deployment",
		zap.String("component", req.Component),
		zap.String("environment", req.Environment),
		zap.Strings("services", req.Services))

	result := &DeploymentResult{
		Component:   req.Component,
		Environment: req.Environment,
		Services:    []ServiceDeploymentResult{},
	}

	// Run Salt orchestration
	if err := r.runSaltOrchestration(rc, req); err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, err
	}

	// Get outputs from Terraform
	outputs, err := r.executor.GetOutputs(rc, req.Component, req.Environment)
	if err != nil {
		logger.Warn("Failed to get Terraform outputs", zap.Error(err))
	} else {
		result.Outputs = outputs
	}

	// Deploy services if requested
	if len(req.Services) > 0 {
		serviceResults := r.deployServices(rc, req)
		result.Services = serviceResults
	}

	result.Success = true
	result.Duration = time.Since(startTime)

	logger.Info("Infrastructure deployment completed",
		zap.String("component", req.Component),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// runSaltOrchestration runs the Salt orchestration state for the component
func (r *InfrastructureRunner) runSaltOrchestration(rc *eos_io.RuntimeContext, req DeploymentRequest) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build Salt command
	orchState := fmt.Sprintf("orch.%s.deploy", req.Component)
	
	args := []string{
		"salt-run",
		"state.orchestrate",
		orchState,
	}

	// Add pillar data for services
	if len(req.Services) > 0 {
		pillarData := fmt.Sprintf("%s:services=[%s]", req.Component, strings.Join(req.Services, ","))
		args = append(args, "pillar="+pillarData)
	}

	// Add variables as pillar data
	for key, value := range req.Variables {
		pillarData := fmt.Sprintf("infrastructure:%s:%s=%v", req.Component, key, value)
		args = append(args, "pillar="+pillarData)
	}

	if req.DryRun {
		args = append(args, "test=True")
	}

	logger.Info("Running Salt orchestration",
		zap.String("state", orchState),
		zap.Strings("args", args))

	// Execute Salt orchestration
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: args[0],
		Args:    args[1:],
		Capture: true,
		Timeout: 30 * time.Minute,
	})

	if err != nil {
		return fmt.Errorf("Salt orchestration failed: %w\nOutput: %s", err, output)
	}

	// Check for failures in output
	if strings.Contains(output, "Failed:") && !strings.Contains(output, "Failed:     0") {
		return fmt.Errorf("Salt orchestration reported failures:\n%s", output)
	}

	logger.Info("Salt orchestration completed successfully")
	return nil
}

// deployServices deploys the requested services
func (r *InfrastructureRunner) deployServices(rc *eos_io.RuntimeContext, req DeploymentRequest) []ServiceDeploymentResult {
	logger := otelzap.Ctx(rc.Ctx)
	results := []ServiceDeploymentResult{}

	for _, service := range req.Services {
		logger.Info("Deploying service",
			zap.String("service", service))

		result := ServiceDeploymentResult{
			Name: service,
		}

		// Deploy via Nomad
		if err := r.deployServiceWithNomad(rc, service); err != nil {
			result.Success = false
			result.Error = err.Error()
			logger.Error("Failed to deploy service",
				zap.String("service", service),
				zap.Error(err))
		} else {
			result.Success = true
			// Get service endpoint
			endpoint, err := r.getServiceEndpoint(rc, service)
			if err == nil {
				result.Endpoint = endpoint
			}
		}

		results = append(results, result)
	}

	return results
}

// deployServiceWithNomad deploys a service using Nomad
func (r *InfrastructureRunner) deployServiceWithNomad(rc *eos_io.RuntimeContext, service string) error {
	jobPath := fmt.Sprintf("/opt/eos/assets/nomad/%s.nomad", service)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "run", jobPath},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to deploy %s: %w\nOutput: %s", service, err, output)
	}

	return nil
}

// getServiceEndpoint gets the endpoint for a deployed service
func (r *InfrastructureRunner) getServiceEndpoint(rc *eos_io.RuntimeContext, service string) (string, error) {
	// Query Consul for service endpoint
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"catalog", "services", "-service", service, "-format", "json"},
		Capture: true,
	})

	if err != nil {
		return "", err
	}

	// Parse and return endpoint
	// TODO: Properly parse JSON output and extract endpoint
	return fmt.Sprintf("http://%s.service.consul", service), nil
}

// Destroy destroys infrastructure
func (r *InfrastructureRunner) Destroy(rc *eos_io.RuntimeContext, component, environment string, autoApprove bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Destroying infrastructure",
		zap.String("component", component),
		zap.String("environment", environment))

	// Run destroy orchestration
	args := []string{
		"salt-run",
		"state.orchestrate",
		fmt.Sprintf("orch.%s.destroy", component),
		fmt.Sprintf("pillar=environment:%s", environment),
	}

	if !autoApprove {
		return eos_err.NewUserError("destroy requires auto_approve=true for safety")
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: args[0],
		Args:    args[1:],
		Capture: true,
		Timeout: 30 * time.Minute,
	})

	if err != nil {
		return fmt.Errorf("destroy orchestration failed: %w\nOutput: %s", err, output)
	}

	// Also run Terraform destroy
	return r.executor.Destroy(rc, component, environment, autoApprove)
}

// Status gets the status of deployed infrastructure
func (r *InfrastructureRunner) Status(rc *eos_io.RuntimeContext, component, environment string) (*InfrastructureStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Getting infrastructure status",
		zap.String("component", component),
		zap.String("environment", environment))

	status := &InfrastructureStatus{
		Component:   component,
		Environment: environment,
	}

	// Check Terraform state
	resources, err := r.executor.GetResources(rc, component, environment)
	if err != nil {
		status.Deployed = false
		return status, nil
	}

	status.Deployed = len(resources.Resources) > 0
	status.Resources = resources.Resources

	// Get outputs
	outputs, err := r.executor.GetOutputs(rc, component, environment)
	if err == nil {
		status.Outputs = outputs
	}

	// Check health via Consul
	healthy, err := r.checkComponentHealth(rc, component, environment)
	if err == nil {
		status.Healthy = healthy
	}

	return status, nil
}

// InfrastructureStatus represents the status of infrastructure
type InfrastructureStatus struct {
	Component   string
	Environment string
	Deployed    bool
	Healthy     bool
	Resources   []string
	Outputs     map[string]Output
}

// checkComponentHealth checks if a component is healthy
func (r *InfrastructureRunner) checkComponentHealth(rc *eos_io.RuntimeContext, component, environment string) (bool, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args: []string{
			"kv", "get",
			fmt.Sprintf("terraform/%s/%s/health", environment, component),
		},
		Capture: true,
	})

	if err != nil {
		return false, err
	}

	return strings.TrimSpace(output) == "healthy", nil
}

// GetResources wrapper for executor
func (r *InfrastructureRunner) GetResources(rc *eos_io.RuntimeContext, component, environment string) (*ResourceList, error) {
	return r.executor.GetResources(rc, component, environment)
}