// pkg/orchestrator/errors.go
package orchestrator

import (
	"fmt"
	"strings"
)

// Layer represents the orchestration layer where an error occurred
type Layer string

const (
	LayerSalt      Layer = "salt"
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
	Layer       Layer  `json:"layer"`
	Phase       Phase  `json:"phase"`
	Component   string `json:"component"`
	Message     string `json:"message"`
	Original    error  `json:"-"`
	Remediation string `json:"remediation"`
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
	err.Remediation = getSuggestedRemediation(layer, phase, message)
	
	return err
}

// getSuggestedRemediation provides context-aware remediation suggestions
func getSuggestedRemediation(layer Layer, phase Phase, message string) string {
	// Salt-specific remediations
	if layer == LayerSalt {
		switch phase {
		case PhaseValidation:
			return "Run 'eos debug salt-states <component>' to validate generated states"
		case PhaseApplication:
			if strings.Contains(message, "minion") {
				return "Check Salt minion connectivity with 'salt-key -L' and 'salt '*' test.ping'"
			}
			return "Check Salt master logs at /var/log/salt/master and run 'salt-run jobs.active'"
		case PhaseVerification:
			return "Run 'salt '*' state.show_sls <component>' to debug state compilation"
		}
	}
	
	// Terraform-specific remediations
	if layer == LayerTerraform {
		switch phase {
		case PhaseValidation:
			return "Run 'eos create <component> --dry-run --show-terraform' to see generated config"
		case PhaseApplication:
			if strings.Contains(message, "lock") {
				return "Another operation may be in progress. Check with 'terraform show' or force unlock"
			}
			return "Check Terraform state with 'terraform state list' and logs in .terraform/logs"
		case PhaseVerification:
			return "Run 'terraform plan' manually to see pending changes"
		}
	}
	
	// Nomad-specific remediations
	if layer == LayerNomad {
		switch phase {
		case PhaseValidation:
			return "Validate job spec with 'nomad job validate <jobfile>'"
		case PhaseApplication:
			if strings.Contains(message, "allocation") {
				return "Check allocations with 'nomad job status <job>' and 'nomad alloc logs <alloc-id>'"
			}
			return "Check Nomad server status with 'nomad server members'"
		case PhaseVerification:
			return "Monitor job health with 'nomad job status -verbose <job>'"
		}
	}
	
	return "Run 'eos debug orchestration --component <name>' for detailed diagnostics"
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
	Field   string `json:"field"`
	Value   interface{} `json:"value"`
	Message string `json:"message"`
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