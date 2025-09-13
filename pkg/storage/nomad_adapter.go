package storage

import (
	"context"
	"fmt"
)

// NomadResult represents the result of a Nomad operation
// This replaces SaltResult as part of the SaltStack → HashiCorp migration
type NomadResult struct {
	Success bool
	Message string
	Data    map[string]interface{}
}

// NomadClient wraps the actual Nomad client for storage operations
// This replaces SaltClient as part of the SaltStack → HashiCorp migration
type NomadClient interface {
	ApplyJob(ctx context.Context, target, jobSpec string, vars map[string]interface{}) (*NomadResult, error)
}

// nomadClientAdapter adapts the real Nomad client to our simplified interface
type nomadClientAdapter struct {
	// TODO: Add Nomad client field when implemented
}

// NewNomadClientAdapter creates a new Nomad client adapter
func NewNomadClientAdapter() NomadClient {
	return &nomadClientAdapter{}
}

// ApplyJob applies a Nomad job specification
func (a *nomadClientAdapter) ApplyJob(ctx context.Context, target, jobSpec string, vars map[string]interface{}) (*NomadResult, error) {
	// TODO: Implement Nomad job deployment
	return nil, fmt.Errorf("Nomad job deployment not yet implemented")
}
