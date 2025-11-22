// pkg/bootstrap/debug/types.go
package debug

import "time"

// CheckResult represents the result of a single diagnostic check
type CheckResult struct {
	Name    string
	Status  string // "PASS", "WARN", "FAIL"
	Message string
	Details []string
	Error   error
}

// BootstrapDebugResult holds all diagnostic check results
type BootstrapDebugResult struct {
	Timestamp             time.Time
	SystemCheck           CheckResult
	PrerequisitesCheck    CheckResult
	StateCheck            CheckResult
	ServicesCheck         CheckResult
	PortsCheck            CheckResult
	LockCheck             CheckResult
	PhaseCheck            CheckResult
	NetworkCheck          CheckResult
	ResourcesCheck        CheckResult
	PreviousAttemptsCheck CheckResult
	Summary               string
}

// DiagnosticConfig holds configuration for bootstrap diagnostics
type DiagnosticConfig struct {
	Verbose    bool
	JSONOutput bool
}
