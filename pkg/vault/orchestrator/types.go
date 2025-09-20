// Package orchestrator provides Vault orchestration types and utilities
package orchestrator

import (
	"time"
)

// OrchestrationMode represents the mode of orchestration
type OrchestrationMode string

const (
	// ModeNomad represents Nomad-based orchestration
	ModeNomad OrchestrationMode = "nomad"
	// ModeDirect represents direct installation
	ModeDirect OrchestrationMode = "direct"
)

// OrchestrationResult represents the result of an orchestration operation
type OrchestrationResult struct {
	Mode     OrchestrationMode `json:"mode"`
	Success  bool              `json:"success"`
	Duration time.Duration     `json:"duration"`
	Message  string            `json:"message,omitempty"`
	Error    error             `json:"error,omitempty"`
}

// OrchestrationOptions represents options for orchestration
type OrchestrationOptions struct {
	Mode    OrchestrationMode `json:"mode"`
	Target  string            `json:"target"`
	Config  map[string]interface{} `json:"config,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// DirectExecutor represents a direct execution interface
type DirectExecutor interface {
	Execute(target string, command string) error
}



// NomadOperation represents a Nomad operation
type NomadOperation struct {
	Target  string
	Job     string
	Config  map[string]interface{}
}
