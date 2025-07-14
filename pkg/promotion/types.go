package promotion

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
)

// PromotionManager handles cross-environment deployment promotions
type PromotionManager struct {
	environmentManager *environments.EnvironmentManager
	approvalConfig     *ApprovalConfig
}

// PromotionRequest represents a promotion request between environments
type PromotionRequest struct {
	ID              string                 `json:"id"`
	Component       string                 `json:"component"`
	FromEnvironment string                 `json:"from_environment"`
	ToEnvironment   string                 `json:"to_environment"`
	Version         string                 `json:"version"`
	Reason          string                 `json:"reason"`
	RequesterID     string                 `json:"requester_id"`
	ApprovalPolicy  ApprovalPolicy         `json:"approval_policy"`
	Status          PromotionStatus        `json:"status"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	PromotedAt      *time.Time             `json:"promoted_at,omitempty"`
}

// PromotionStatus represents the status of a promotion
type PromotionStatus string

const (
	PromotionStatusPending   PromotionStatus = "pending"
	PromotionStatusApproved  PromotionStatus = "approved"
	PromotionStatusRejected  PromotionStatus = "rejected"
	PromotionStatusExecuting PromotionStatus = "executing"
	PromotionStatusCompleted PromotionStatus = "completed"
	PromotionStatusFailed    PromotionStatus = "failed"
	PromotionStatusCancelled PromotionStatus = "cancelled"
)

// PromotionResult represents the result of a promotion operation
type PromotionResult struct {
	Request         *PromotionRequest     `json:"request"`
	Success         bool                  `json:"success"`
	DeploymentID    string                `json:"deployment_id"`
	Duration        time.Duration         `json:"duration"`
	StepsExecuted   []PromotionStep       `json:"steps_executed"`
	ArtifactsPromoted []PromotedArtifact  `json:"artifacts_promoted"`
	ValidationResults []ValidationResult  `json:"validation_results"`
	RollbackPlan    *RollbackPlan         `json:"rollback_plan,omitempty"`
	Error           string                `json:"error,omitempty"`
}

// PromotionStep represents a step in the promotion process
type PromotionStep struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Status      StepStatus    `json:"status"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     *time.Time    `json:"end_time,omitempty"`
	Duration    time.Duration `json:"duration"`
	Output      string        `json:"output,omitempty"`
	Error       string        `json:"error,omitempty"`
}

// StepStatus represents the status of a promotion step
type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusSkipped   StepStatus = "skipped"
)

// PromotedArtifact represents an artifact that was promoted
type PromotedArtifact struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	SourceLocation  string            `json:"source_location"`
	TargetLocation  string            `json:"target_location"`
	Version         string            `json:"version"`
	Checksum        string            `json:"checksum"`
	Size            int64             `json:"size"`
	Metadata        map[string]string `json:"metadata"`
}

// ValidationResult represents the result of promotion validation
type ValidationResult struct {
	Check   string `json:"check"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
	Level   string `json:"level"` // info, warning, error
}

// RollbackPlan represents a plan for rolling back a promotion
type RollbackPlan struct {
	PreviousVersion string                 `json:"previous_version"`
	RollbackSteps   []RollbackStep         `json:"rollback_steps"`
	EstimatedTime   time.Duration          `json:"estimated_time"`
	Dependencies    []string               `json:"dependencies"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// RollbackStep represents a step in a rollback plan
type RollbackStep struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Command     string        `json:"command"`
	Args        []string      `json:"args"`
	Timeout     time.Duration `json:"timeout"`
	Required    bool          `json:"required"`
}

// ApprovalConfig holds approval-related configuration
type ApprovalConfig struct {
	Required      bool          `json:"required"`
	MinApprovers  int           `json:"min_approvers"`
	Approvers     []string      `json:"approvers"`
	Timeout       time.Duration `json:"timeout"`
	AutoApprove   bool          `json:"auto_approve"`
	BypassUsers   []string      `json:"bypass_users"`
}

// ApprovalPolicy defines the approval policy for a promotion
type ApprovalPolicy struct {
	Required        bool          `json:"required"`
	MinApprovals    int           `json:"min_approvals"`
	ApprovalTimeout time.Duration `json:"approval_timeout"`
	Approvers       []string      `json:"approvers"`
	AutoApprove     bool          `json:"auto_approve"`
}

// Approval represents an individual approval
type Approval struct {
	ID          string    `json:"id"`
	PromotionID string    `json:"promotion_id"`
	ApproverID  string    `json:"approver_id"`
	Status      string    `json:"status"` // approved, rejected
	Comment     string    `json:"comment"`
	Timestamp   time.Time `json:"timestamp"`
}

// PromotionConfig holds configuration for promotions
type PromotionConfig struct {
	DryRun              bool                              `json:"dry_run"`
	Force               bool                              `json:"force"`
	SkipValidation      bool                              `json:"skip_validation"`
	SkipApproval        bool                              `json:"skip_approval"`
	Timeout             time.Duration                     `json:"timeout"`
	ValidationRules     []string                          `json:"validation_rules"`
	EnvironmentPolicies map[string]EnvironmentPolicy      `json:"environment_policies"`
	ComponentPolicies   map[string]ComponentPolicy        `json:"component_policies"`
}

// EnvironmentPolicy defines promotion policies for specific environments
type EnvironmentPolicy struct {
	AllowedSources    []string      `json:"allowed_sources"`
	RequireApproval   bool          `json:"require_approval"`
	MinApprovals      int           `json:"min_approvals"`
	ValidationLevel   string        `json:"validation_level"` // basic, standard, strict
	DeploymentWindow  TimeWindow    `json:"deployment_window"`
	RollbackWindow    time.Duration `json:"rollback_window"`
	FreezeWindows     []TimeWindow  `json:"freeze_windows"`
}

// ComponentPolicy defines promotion policies for specific components
type ComponentPolicy struct {
	RequiredChecks    []string      `json:"required_checks"`
	AllowedTargets    []string      `json:"allowed_targets"`
	DeploymentDelay   time.Duration `json:"deployment_delay"`
	HealthCheckConfig HealthCheck   `json:"health_check"`
	RollbackTimeout   time.Duration `json:"rollback_timeout"`
}

// TimeWindow represents a time window for operations
type TimeWindow struct {
	Start    string `json:"start"`    // "Monday 09:00"
	End      string `json:"end"`      // "Friday 18:00"
	Timezone string `json:"timezone"` // "UTC", "America/New_York"
}

// HealthCheck defines health check configuration
type HealthCheck struct {
	Enabled         bool          `json:"enabled"`
	Endpoint        string        `json:"endpoint"`
	ExpectedStatus  int           `json:"expected_status"`
	Timeout         time.Duration `json:"timeout"`
	Retries         int           `json:"retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	SuccessThreshold int          `json:"success_threshold"`
}

// PromotionError represents an error during promotion operations
type PromotionError struct {
	Type        string                 `json:"type"`
	Component   string                 `json:"component"`
	Operation   string                 `json:"operation"`
	Message     string                 `json:"message"`
	Cause       error                  `json:"cause,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	Retryable   bool                   `json:"retryable"`
}

func (e *PromotionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s/%s/%s] %s: %v", e.Type, e.Component, e.Operation, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s/%s/%s] %s", e.Type, e.Component, e.Operation, e.Message)
}

// StackPromotionRequest represents a batch promotion request for multiple components
type StackPromotionRequest struct {
	ID              string                 `json:"id"`
	StackName       string                 `json:"stack_name"`
	Components      []string               `json:"components"`
	FromEnvironment string                 `json:"from_environment"`
	ToEnvironment   string                 `json:"to_environment"`
	Version         string                 `json:"version"`
	Strategy        StackPromotionStrategy `json:"strategy"`
	DependencyOrder []string               `json:"dependency_order"`
	Parallel        bool                   `json:"parallel"`
	ContinueOnError bool                   `json:"continue_on_error"`
	Status          PromotionStatus        `json:"status"`
	Results         []PromotionResult      `json:"results"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// StackPromotionStrategy defines how to promote a stack
type StackPromotionStrategy string

const (
	StackPromotionStrategySequential StackPromotionStrategy = "sequential"
	StackPromotionStrategyParallel    StackPromotionStrategy = "parallel"
	StackPromotionStrategyDependency  StackPromotionStrategy = "dependency-order"
)

// PromotionHistory represents the promotion history for tracking
type PromotionHistory struct {
	Component     string              `json:"component"`
	Environment   string              `json:"environment"`
	Promotions    []PromotionRecord   `json:"promotions"`
	LastPromoted  *time.Time          `json:"last_promoted,omitempty"`
	CurrentVersion string             `json:"current_version"`
}

// PromotionRecord represents a single promotion record
type PromotionRecord struct {
	ID            string    `json:"id"`
	Version       string    `json:"version"`
	FromEnv       string    `json:"from_env"`
	ToEnv         string    `json:"to_env"`
	PromotedBy    string    `json:"promoted_by"`
	PromotedAt    time.Time `json:"promoted_at"`
	Duration      time.Duration `json:"duration"`
	Success       bool      `json:"success"`
	RolledBack    bool      `json:"rolled_back"`
	RollbackAt    *time.Time `json:"rollback_at,omitempty"`
}

// StackPromotionResult represents the result of a stack promotion
type StackPromotionResult struct {
	Request           *StackPromotionRequest `json:"request"`
	Success           bool                   `json:"success"`
	ComponentsPromoted int                   `json:"components_promoted"`
	ComponentsFailed  int                    `json:"components_failed"`
	Results           []PromotionResult      `json:"results"`
	StartTime         time.Time              `json:"start_time"`
	EndTime           time.Time              `json:"end_time"`
	Duration          time.Duration          `json:"duration"`
	Error             string                 `json:"error,omitempty"`
}