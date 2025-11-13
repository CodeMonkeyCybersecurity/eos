package nuke

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
)

// Config holds the configuration for nuke operations
type Config struct {
	RemoveAll   bool
	Force       bool
	KeepData    bool
	ExcludeList []string
	DevMode     bool
}

// NukeResult contains the results of a nuke operation
type NukeResult struct {
	InitialComponents   int
	RemovedComponents   int
	RemainingComponents int
	SuccessRate         float64
	RemainingItems      []string
}

// PhaseResult contains the result of a single nuke phase
type PhaseResult struct {
	Phase       int
	Description string
	Success     bool
	Error       error
	Details     map[string]interface{}
}

// ServiceConfig represents a service that can be removed
type ServiceConfig struct {
	Name      string
	Component string
	IsData    bool
	Required  bool
}

// DirectoryConfig represents a directory that can be removed
type DirectoryConfig struct {
	Path        string
	Component   string
	IsData      bool
	Description string
}

// RemovalPlan contains the plan for what will be removed
type RemovalPlan struct {
	Components    []state.Component
	Services      []ServiceConfig
	Directories   []DirectoryConfig
	ExcludedItems []string
	DevModeActive bool
	DataPreserved bool
}
