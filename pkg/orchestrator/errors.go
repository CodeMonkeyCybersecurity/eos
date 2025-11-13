// pkg/orchestrator/errors.go
package orchestrator

import (
	"fmt"
	"strings"
)

// Layer represents the orchestration layer where an error occurred
type Layer string

const (
	LayerUnknown   Layer = ""
	LayerTerraform Layer = "terraform"
	LayerNomad     Layer = "nomad"
	LayerEos       Layer = "eos"
)

// Phase represents the phase of orchestration where an error occurred
type Phase string

const (
	PhaseValidation   Phase = "validation"
	PhasePreparation  Phase = "preparation"
	PhaseApplication  Phase = "application"
	PhaseVerification Phase = "verification"
	PhaseRollback     Phase = "rollback"
)

// OrchestrationError provides detailed error information with remediation suggestions
type OrchestrationError struct {
	Layer       Layer                  `json:"layer"`
	Phase       Phase                  `json:"phase"`
	Component   string                 `json:"component"`
	Message     string                 `json:"message"`
	Original    error                  `json:"-"`
	Remediation string                 `json:"remediation"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Error implements the error interface
func (e *OrchestrationError) Error() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s error during %s", e.Layer, e.Phase))

	if e.Component != "" {
		sb.WriteString(fmt.Sprintf(" for component '%s'", e.Component))
	}

	sb.WriteString(fmt.Sprintf(": %s", e.Message))

	if e.Original != nil {
		sb.WriteString(fmt.Sprintf("\nCaused by: %v", e.Original))
	}

	if e.Remediation != "" {
		sb.WriteString(fmt.Sprintf("\nSuggested fix: %s", e.Remediation))
	}

	return sb.String()
}

// Unwrap returns the wrapped error
func (e *OrchestrationError) Unwrap() error {
	return e.Original
}

// NewOrchestrationError creates a new orchestration error
func NewOrchestrationError(layer Layer, phase Phase, component, message string, original error) *OrchestrationError {
	err := &OrchestrationError{
		Layer:     layer,
		Phase:     phase,
		Component: component,
		Message:   message,
		Original:  original,
		Details:   make(map[string]interface{}),
	}

	// Add automatic remediation suggestions based on layer and phase
	err.Remediation = getSuggestedRemediation(string(layer), string(phase), message)

	return err
}

// getSuggestedRemediation provides automatic remediation suggestions based on error context
func getSuggestedRemediation(layer, phase, message string) string {
	// Simple remediation suggestions based on common patterns
	switch {
	case strings.Contains(message, "connection refused"):
		return "Check if the service is running and network connectivity is available"
	case strings.Contains(message, "permission denied"):
		return "Verify user permissions and run with appropriate privileges"
	case strings.Contains(message, "not found"):
		return "Ensure the required resource or service is properly installed and configured"
	case strings.Contains(message, "timeout"):
		return "Check network connectivity and increase timeout values if necessary"
	default:
		return fmt.Sprintf("Review %s configuration in %s phase", layer, phase)
	}
}

// ErrorChain represents a chain of errors that occurred during orchestration
type ErrorChain struct {
	Errors []*OrchestrationError `json:"errors"`
}

// Error implements the error interface
func (ec *ErrorChain) Error() string {
	if len(ec.Errors) == 0 {
		return "no errors"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Orchestration failed with %d error(s):\n", len(ec.Errors)))

	for i, err := range ec.Errors {
		sb.WriteString(fmt.Sprintf("\n%d. %s", i+1, err.Error()))
	}

	return sb.String()
}

// Add adds an error to the chain
func (ec *ErrorChain) Add(err *OrchestrationError) {
	ec.Errors = append(ec.Errors, err)
}

// HasErrors returns true if the chain contains any errors
func (ec *ErrorChain) HasErrors() bool {
	return len(ec.Errors) > 0
}

// GetByLayer returns all errors for a specific layer
func (ec *ErrorChain) GetByLayer(layer Layer) []*OrchestrationError {
	var errors []*OrchestrationError
	for _, err := range ec.Errors {
		if err.Layer == layer {
			errors = append(errors, err)
		}
	}
	return errors
}

// GetByPhase returns all errors for a specific phase
func (ec *ErrorChain) GetByPhase(phase Phase) []*OrchestrationError {
	var errors []*OrchestrationError
	for _, err := range ec.Errors {
		if err.Phase == phase {
			errors = append(errors, err)
		}
	}
	return errors
}

// ValidationError represents a validation failure
type ValidationError struct {
	Field   string      `json:"field"`
	Value   interface{} `json:"value"`
	Message string      `json:"message"`
}

// Error implements the error interface
func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s (value: %v)", ve.Field, ve.Message, ve.Value)
}

// ValidationErrors represents multiple validation failures
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// Error implements the error interface
func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "no validation errors"
	}

	var messages []string
	for _, err := range ve.Errors {
		messages = append(messages, err.Error())
	}

	return fmt.Sprintf("validation failed: %s", strings.Join(messages, "; "))
}

// Add adds a validation error
func (ve *ValidationErrors) Add(field string, value interface{}, message string) {
	ve.Errors = append(ve.Errors, ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	})
}

// HasErrors returns true if there are validation errors
func (ve *ValidationErrors) HasErrors() bool {
	return len(ve.Errors) > 0
}
