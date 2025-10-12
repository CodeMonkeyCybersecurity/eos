package nomad_orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewOrchestrator creates a new Nomad orchestrator instance
func NewOrchestrator(rc *eos_io.RuntimeContext) *NomadOrchestrator {
	return &NomadOrchestrator{
		rc:          rc,
		nomadAddr:   "http://127.0.0.1:4646", // Default Nomad address
		consulAddr:  fmt.Sprintf("http://127.0.0.1:%d", shared.PortConsul),
		templateDir: "/opt/eos/nomad/jobs",
	}
}

// DeployJob deploys a Nomad job from template with configuration
func (no *NomadOrchestrator) DeployJob(config *JobConfig) (*DeploymentResult, error) {
	logger := otelzap.Ctx(no.rc.Ctx)
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing deployment prerequisites",
		zap.String("service", config.ServiceName))
	
	if err := no.checkPrerequisites(); err != nil {
		return nil, fmt.Errorf("prerequisite check failed: %w", err)
	}
	
	// INTERVENE - Deploy the job
	logger.Info("Deploying Nomad job",
		zap.String("service", config.ServiceName),
		zap.String("template", config.JobTemplate))
	
	// Generate job file from template
	jobFile, err := no.generateJobFile(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate job file: %w", err)
	}
	defer os.Remove(jobFile) // Cleanup temporary file
	
	// Deploy job
	if err := no.deployJobFile(jobFile); err != nil {
		return nil, fmt.Errorf("failed to deploy job: %w", err)
	}
	
	// EVALUATE - Verify deployment
	logger.Info("Verifying deployment success")
	
	result, err := no.verifyDeployment(config)
	if err != nil {
		return nil, fmt.Errorf("deployment verification failed: %w", err)
	}
	
	logger.Info("Job deployed successfully",
		zap.String("service", result.ServiceName),
		zap.String("status", result.Status),
		zap.String("url", result.URL))
	
	return result, nil
}

// checkPrerequisites ensures Nomad and Consul are running
func (no *NomadOrchestrator) checkPrerequisites() error {
	logger := otelzap.Ctx(no.rc.Ctx)
	
	// Check if Nomad is available
	if _, err := exec.LookPath("nomad"); err != nil {
		return fmt.Errorf("nomad binary not found - please install Nomad first using 'eos create nomad'")
	}
	
	// Check if Nomad is running
	cmd := exec.Command("nomad", "node", "status")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nomad is not running - please start Nomad first using 'eos create nomad'")
	}
	
	// Check if Consul is running (for service discovery)
	cmd = exec.Command("consul", "members")
	if err := cmd.Run(); err != nil {
		logger.Warn("Consul is not running - service discovery may not work properly")
		// Don't fail - Nomad can work without Consul for basic deployments
	}
	
	logger.Info("Prerequisites check passed")
	return nil
}

// generateJobFile creates a Nomad job file from template and configuration
func (no *NomadOrchestrator) generateJobFile(config *JobConfig) (string, error) {
	logger := otelzap.Ctx(no.rc.Ctx)
	
	// Load template file
	templatePath := filepath.Join(no.templateDir, config.JobTemplate)
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template %s: %w", templatePath, err)
	}
	
	// Create template
	tmpl, err := template.New(config.ServiceName).Parse(string(templateContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	
	// Prepare template variables
	variables := map[string]interface{}{
		"ServiceName": config.ServiceName,
		"Datacenter":  config.Datacenter,
		"Port":        config.Port,
		"DataPath":    config.DataPath,
		"CPU":         config.CPU,
		"Memory":      config.Memory,
	}
	
	// Add custom variables
	for k, v := range config.Variables {
		variables[k] = v
	}
	
	// Create temporary job file
	jobFile := filepath.Join("/tmp", fmt.Sprintf("%s.nomad", config.ServiceName))
	file, err := os.Create(jobFile)
	if err != nil {
		return "", fmt.Errorf("failed to create job file: %w", err)
	}
	defer func() { _ = file.Close() }()
	
	// Execute template
	if err := tmpl.Execute(file, variables); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	
	logger.Info("Job file generated",
		zap.String("template", config.JobTemplate),
		zap.String("job_file", jobFile))
	
	return jobFile, nil
}

// deployJobFile deploys a Nomad job file
func (no *NomadOrchestrator) deployJobFile(jobFile string) error {
	logger := otelzap.Ctx(no.rc.Ctx)
	
	// Run nomad job run
	cmd := exec.Command("nomad", "job", "run", jobFile)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		logger.Error("Job deployment failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("nomad job run failed: %w", err)
	}
	
	logger.Info("Job deployment command executed",
		zap.String("output", string(output)))
	
	return nil
}

// verifyDeployment checks if the job is running and healthy
func (no *NomadOrchestrator) verifyDeployment(config *JobConfig) (*DeploymentResult, error) {
	logger := otelzap.Ctx(no.rc.Ctx)
	
	// Wait for job to be running (with timeout)
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Check job status
		cmd := exec.Command("nomad", "job", "status", config.ServiceName)
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "running") {
			break
		}
		time.Sleep(2 * time.Second)
	}
	
	// Get job status details
	cmd := exec.Command("nomad", "job", "status", "-json", config.ServiceName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get job status: %w", err)
	}
	
	// Parse status (simplified - would need proper JSON parsing for production)
	status := "running"
	if !strings.Contains(string(output), "running") {
		status = "failed"
	}
	
	// Build result
	result := &DeploymentResult{
		JobID:       config.ServiceName,
		ServiceName: config.ServiceName,
		Port:        config.Port,
		URL:         fmt.Sprintf("http://localhost:%d", config.Port),
		Status:      status,
		ConsulURL:   fmt.Sprintf("%s/ui/dc1/services", no.consulAddr),
	}
	
	logger.Info("Deployment verification completed",
		zap.String("status", result.Status),
		zap.String("url", result.URL))
	
	return result, nil
}

// ListJobs returns all running Nomad jobs managed by Eos
func (no *NomadOrchestrator) ListJobs() ([]string, error) {
	cmd := exec.Command("nomad", "job", "status", "-json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}
	
	// Parse JSON output (simplified)
	var jobs []map[string]interface{}
	if err := json.Unmarshal(output, &jobs); err != nil {
		return nil, fmt.Errorf("failed to parse job list: %w", err)
	}
	
	var jobNames []string
	for _, job := range jobs {
		if name, ok := job["ID"].(string); ok {
			jobNames = append(jobNames, name)
		}
	}
	
	return jobNames, nil
}

// StopJob stops a running Nomad job
func (no *NomadOrchestrator) StopJob(jobName string) error {
	logger := otelzap.Ctx(no.rc.Ctx)
	
	cmd := exec.Command("nomad", "job", "stop", jobName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to stop job",
			zap.String("job", jobName),
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("failed to stop job %s: %w", jobName, err)
	}
	
	logger.Info("Job stopped successfully",
		zap.String("job", jobName))
	
	return nil
}

// GetJobStatus returns the status of a specific job
func (no *NomadOrchestrator) GetJobStatus(jobName string) (string, error) {
	cmd := exec.Command("nomad", "job", "status", jobName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get job status: %w", err)
	}
	
	// Simple status parsing
	if strings.Contains(string(output), "running") {
		return "running", nil
	} else if strings.Contains(string(output), "dead") {
		return "stopped", nil
	}
	
	return "unknown", nil
}