package storage

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/client"
)

// SaltResult represents the result of a Salt operation
// This is a simplified wrapper around the actual Salt client types
type SaltResult struct {
	Success bool
	Message string
	Data    map[string]interface{}
}

// SaltClient wraps the actual Salt client for storage operations
// This allows us to simplify the interface for storage-specific needs
type SaltClient interface {
	ApplyState(ctx context.Context, target, state string, pillar map[string]interface{}) (*SaltResult, error)
}

// saltClientAdapter adapts the real Salt client to our simplified interface
type saltClientAdapter struct {
	client client.SaltClient
}

// NewSaltClientAdapter creates a new Salt client adapter
func NewSaltClientAdapter(saltClient client.SaltClient) SaltClient {
	return &saltClientAdapter{
		client: saltClient,
	}
}

// ApplyState applies a Salt state
func (a *saltClientAdapter) ApplyState(ctx context.Context, target, state string, pillar map[string]interface{}) (*SaltResult, error) {
	req := &client.StateRequest{
		Client:     client.ClientTypeLocal,
		Target:     target,
		Function:   client.FunctionState,
		Args:       []string{state},
		TargetType: client.TargetTypeGlob,
		Pillar:     pillar,
	}

	resp, err := a.client.RunState(ctx, req)
	if err != nil {
		return nil, err
	}

	// Simplify the response
	result := &SaltResult{
		Success: true,
		Data:    make(map[string]interface{}),
	}

	// Check if any states failed
	if len(resp.Return) > 0 {
		for minion, stateResult := range resp.Return[0] {
			result.Data[minion] = stateResult
			// StateResult is a single result, not a map
			if stateResult != nil && stateResult.Result != nil && !*stateResult.Result {
				result.Success = false
				if result.Message == "" {
					result.Message = stateResult.Comment
				}
			}
		}
	}

	return result, nil
}