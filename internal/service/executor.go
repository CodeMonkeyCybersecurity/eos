package service

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// ExecutionResult summarizes the outcome from running a service definition.
type ExecutionResult struct {
	TotalSteps     int
	CompletedSteps int
	FailedStep     int
	Duration       time.Duration
}

// Executor coordinates the execution flow for a service definition.
type Executor struct {
	rc  *eos_io.RuntimeContext
	def *ServiceDefinition
}

// NewExecutor constructs an executor for a service definition.
func NewExecutor(rc *eos_io.RuntimeContext, def *ServiceDefinition) *Executor {
	return &Executor{
		rc:  rc,
		def: def,
	}
}

// PreflightChecks validates whether execution prerequisites are met.
func (e *Executor) PreflightChecks() error {
	return fmt.Errorf("preflight checks not implemented yet for service %q", e.def.Name)
}

// Execute runs the definition.
func (e *Executor) Execute(resume bool) (*ExecutionResult, error) {
	return nil, fmt.Errorf("service execution not implemented yet for %q (resume=%t)", e.def.Name, resume)
}
