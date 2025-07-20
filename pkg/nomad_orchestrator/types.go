// Package nomad_orchestrator provides utilities for deploying applications via Nomad jobs
package nomad_orchestrator

import (
	"time"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// JobConfig represents configuration for a Nomad job deployment
type JobConfig struct {
	// Service identification
	ServiceName string
	JobTemplate string
	
	// Common configuration
	Datacenter string
	Port       int
	DataPath   string
	
	// Service-specific variables
	Variables map[string]interface{}
	
	// Resource allocation
	CPU    int
	Memory int
	
	// Deployment options
	Timeout time.Duration
}

// DeploymentResult represents the result of a job deployment
type DeploymentResult struct {
	JobID       string
	ServiceName string
	Port        int
	URL         string
	Status      string
	ConsulURL   string
}

// JobTemplateInfo contains metadata about available job templates
type JobTemplateInfo struct {
	Name        string
	Description string
	Variables   []VariableInfo
	Ports       []PortInfo
	Tags        []string
}

// VariableInfo describes a job template variable
type VariableInfo struct {
	Name        string
	Type        string
	Default     interface{}
	Description string
	Required    bool
}

// PortInfo describes a service port
type PortInfo struct {
	Name        string
	Port        int
	Description string
}

// NomadOrchestrator manages Nomad job deployments
type NomadOrchestrator struct {
	rc          *eos_io.RuntimeContext
	nomadAddr   string
	consulAddr  string
	templateDir string
}