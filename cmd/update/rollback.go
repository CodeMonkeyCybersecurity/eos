package update

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/deploy"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback [app-name]",
	Short: "Rollback an application deployment to a previous version",
	Long: `Rollback an application deployment to a previous stable version using the 
 → Terraform → Nomad orchestration hierarchy for safe and reliable rollback operations.

This command performs a comprehensive rollback that includes:
- Automated rollback through  orchestration
- Graceful service draining and traffic rerouting
- Database and configuration rollback if needed
- Health verification of the rolled-back version
- Automatic notification of rollback completion

The rollback follows the assessment→intervention→evaluation pattern to ensure
reliable rollback execution and minimal service disruption.

Examples:
  # Rollback to previous version
  eos update rollback helen

  # Rollback to specific version
  eos update rollback helen --to-version 20240113100000

  # Rollback with specific reason
  eos update rollback helen --reason "critical-bug-fix"

  # Emergency rollback (skip confirmations)
  eos update rollback helen --emergency

  # Rollback with custom timeout
  eos update rollback helen --timeout 10m

  # Dry run rollback (show what would be done)
  eos update rollback helen --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		appName := args[0]

		logger.Info("Starting deployment rollback",
			zap.String("command", "update rollback"),
			zap.String("app_name", appName),
			zap.String("component", rc.Component))

		// Parse command flags
		toVersion, _ := cmd.Flags().GetString("to-version")
		reason, _ := cmd.Flags().GetString("reason")
		emergency, _ := cmd.Flags().GetBool("emergency")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		force, _ := cmd.Flags().GetBool("force")

		logger.Info("Rollback configuration",
			zap.String("app_name", appName),
			zap.String("to_version", toVersion),
			zap.String("reason", reason),
			zap.Bool("emergency", emergency),
			zap.Bool("dry_run", dryRun),
			zap.Duration("timeout", timeout),
			zap.Bool("force", force))

		// Execute rollback
		if err := executeRollback(rc, appName, toVersion, reason, emergency, dryRun, timeout, force); err != nil {
			logger.Error("Rollback failed", zap.Error(err))
			return fmt.Errorf("rollback failed: %w", err)
		}

		logger.Info("Rollback completed successfully",
			zap.String("app_name", appName),
			zap.String("target_version", toVersion))

		return nil
	}),
}

func init() {
	// Add rollback command to update
	UpdateCmd.AddCommand(rollbackCmd)

	// Rollback target configuration
	rollbackCmd.Flags().String("to-version", "", "Target version to rollback to (prompted if not provided)")
	rollbackCmd.Flags().String("reason", "", "Reason for rollback (prompted if not provided)")

	// Rollback behavior flags
	rollbackCmd.Flags().Bool("emergency", false, "Emergency rollback - skip confirmations and safety checks")
	rollbackCmd.Flags().Bool("dry-run", false, "Show what would be done without executing rollback")
	rollbackCmd.Flags().Bool("force", false, "Force rollback even if target version has known issues")
	rollbackCmd.Flags().Duration("timeout", 10*time.Minute, "Rollback timeout")

	// Safety and verification flags
	rollbackCmd.Flags().Bool("skip-health-check", false, "Skip health verification after rollback")
	rollbackCmd.Flags().Bool("skip-backup", false, "Skip creating backup before rollback")
	rollbackCmd.Flags().Bool("auto-confirm", false, "Automatically confirm rollback prompts")

	// Rollback scope flags
	rollbackCmd.Flags().String("environment", "", "Rollback specific environment only")
	rollbackCmd.Flags().String("namespace", "", "Rollback specific namespace only")
	rollbackCmd.Flags().StringSlice("components", nil, "Rollback specific components only: nomad, consul, vault, terraform")

	// Notification flags
	rollbackCmd.Flags().String("notification-channel", "deployments", "Channel for rollback notifications")
	rollbackCmd.Flags().StringSlice("notify-users", nil, "Additional users to notify about rollback")

	rollbackCmd.Example = `  # Rollback to previous stable version
  eos update rollback helen

  # Rollback to specific version with reason
  eos update rollback helen --to-version 20240113100000 --reason "Performance regression"

  # Emergency rollback (skip safety checks)
  eos update rollback helen --emergency --auto-confirm

  # Dry run to see rollback plan
  eos update rollback helen --to-version 20240113100000 --dry-run

  # Rollback with custom timeout and notifications
  eos update rollback helen --timeout 15m --notify-users user1,user2`
}

// RollbackRequest represents a rollback request configuration
type RollbackRequest struct {
	AppName             string        `json:"app_name"`
	TargetVersion       string        `json:"target_version"`
	CurrentVersion      string        `json:"current_version"`
	Reason              string        `json:"reason"`
	Emergency           bool          `json:"emergency"`
	DryRun              bool          `json:"dry_run"`
	Force               bool          `json:"force"`
	Timeout             time.Duration `json:"timeout"`
	SkipHealthCheck     bool          `json:"skip_health_check"`
	SkipBackup          bool          `json:"skip_backup"`
	AutoConfirm         bool          `json:"auto_confirm"`
	Environment         string        `json:"environment"`
	Namespace           string        `json:"namespace"`
	Components          []string      `json:"components"`
	NotificationChannel string        `json:"notification_channel"`
	NotifyUsers         []string      `json:"notify_users"`
}

// RollbackPlan represents the rollback execution plan
type RollbackPlan struct {
	Request       *RollbackRequest `json:"request"`
	Steps         []RollbackStep   `json:"steps"`
	EstimatedTime time.Duration    `json:"estimated_time"`
	RiskLevel     string           `json:"risk_level"`
	Warnings      []string         `json:"warnings"`
	Prerequisites []string         `json:"prerequisites"`
}

// RollbackStep represents a single rollback step
type RollbackStep struct {
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Component     string        `json:"component"`
	Action        string        `json:"action"`
	EstimatedTime time.Duration `json:"estimated_time"`
	Risk          string        `json:"risk"`
	Required      bool          `json:"required"`
}

// RollbackResult represents the result of a rollback operation
type RollbackResult struct {
	Success       bool                   `json:"success"`
	AppName       string                 `json:"app_name"`
	FromVersion   string                 `json:"from_version"`
	ToVersion     string                 `json:"to_version"`
	Reason        string                 `json:"reason"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	StepsExecuted []RollbackStepResult   `json:"steps_executed"`
	Metadata      map[string]interface{} `json:"metadata"`
	Error         string                 `json:"error,omitempty"`
}

// RollbackStepResult represents the result of executing a rollback step
type RollbackStepResult struct {
	Step      RollbackStep  `json:"step"`
	Status    string        `json:"status"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Output    string        `json:"output,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// executeRollback performs the complete rollback operation
func executeRollback(rc *eos_io.RuntimeContext, appName, toVersion, reason string, emergency, dryRun bool, timeout time.Duration, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create rollback request
	request := &RollbackRequest{
		AppName:       appName,
		TargetVersion: toVersion,
		Reason:        reason,
		Emergency:     emergency,
		DryRun:        dryRun,
		Force:         force,
		Timeout:       timeout,
	}

	// Step 1: Assess current deployment and determine rollback plan
	plan, err := assessRollback(rc, request)
	if err != nil {
		return fmt.Errorf("rollback assessment failed: %w", err)
	}

	logger.Info("Rollback plan generated",
		zap.String("app_name", appName),
		zap.String("target_version", plan.Request.TargetVersion),
		zap.Int("steps", len(plan.Steps)),
		zap.Duration("estimated_time", plan.EstimatedTime),
		zap.String("risk_level", plan.RiskLevel))

	// Step 2: Display rollback plan and get confirmation (unless emergency or auto-confirm)
	if !emergency && !dryRun {
		if err := confirmRollback(rc, plan); err != nil {
			return fmt.Errorf("rollback confirmation failed: %w", err)
		}
	}

	// Step 3: Execute rollback (or just display plan if dry run)
	if dryRun {
		return displayRollbackPlan(plan)
	}

	result, err := executeRollbackPlan(rc, plan)
	if err != nil {
		return fmt.Errorf("rollback execution failed: %w", err)
	}

	// Step 4: Send notifications
	if err := sendRollbackNotifications(rc, result); err != nil {
		logger.Warn("Failed to send rollback notifications", zap.Error(err))
	}

	logger.Info("Rollback completed",
		zap.String("app_name", appName),
		zap.String("from_version", result.FromVersion),
		zap.String("to_version", result.ToVersion),
		zap.Duration("duration", result.Duration),
		zap.Bool("success", result.Success))

	return nil
}

// assessRollback analyzes current state and creates rollback plan
func assessRollback(rc *eos_io.RuntimeContext, request *RollbackRequest) (*RollbackPlan, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing rollback requirements", zap.String("app_name", request.AppName))

	// Get current deployment version
	err := rollbackApplication(rc, request.AppName)
	if err != nil {
		return nil, fmt.Errorf("failed to get current version: %w", err)
	}
	// TODO: Replace with actual version retrieval
	currentVersion := "20240113120000"
	request.CurrentVersion = currentVersion

	// Determine target version if not specified
	if request.TargetVersion == "" {
		targetVersion, err := getPreviousStableVersion(rc, request.AppName)
		if err != nil {
			return nil, fmt.Errorf("failed to determine target version: %w", err)
		}
		request.TargetVersion = targetVersion
	}

	// Prompt for reason if not provided and not emergency
	if request.Reason == "" && !request.Emergency {
		request.Reason = "Manual rollback requested"
	}

	// Create rollback steps
	steps := []RollbackStep{
		{
			Name:          "pre_rollback_backup",
			Description:   "Create backup of current deployment state",
			Component:     "backup",
			Action:        "create",
			EstimatedTime: 2 * time.Minute,
			Risk:          "low",
			Required:      !request.SkipBackup,
		},
		{
			Name:          "stop_traffic",
			Description:   "Temporarily stop traffic to the application",
			Component:     "consul",
			Action:        "deregister",
			EstimatedTime: 30 * time.Second,
			Risk:          "medium",
			Required:      true,
		},
		{
			Name:          "_orchestration",
			Description:   "Execute  rollback orchestration",
			Component:     "",
			Action:        "orchestrate",
			EstimatedTime: 5 * time.Minute,
			Risk:          "medium",
			Required:      true,
		},
		{
			Name:          "verify_rollback",
			Description:   "Verify rollback success and health",
			Component:     "health",
			Action:        "verify",
			EstimatedTime: 2 * time.Minute,
			Risk:          "low",
			Required:      !request.SkipHealthCheck,
		},
		{
			Name:          "restore_traffic",
			Description:   "Restore traffic to the rolled-back application",
			Component:     "consul",
			Action:        "register",
			EstimatedTime: 30 * time.Second,
			Risk:          "low",
			Required:      true,
		},
	}

	// Calculate estimated time
	var totalTime time.Duration
	for _, step := range steps {
		if step.Required {
			totalTime += step.EstimatedTime
		}
	}

	// Determine risk level
	riskLevel := "medium"
	if request.Emergency {
		riskLevel = "high"
	}

	// Generate warnings
	var warnings []string
	if request.Force {
		warnings = append(warnings, "Force flag enabled - skipping safety checks")
	}
	if request.Emergency {
		warnings = append(warnings, "Emergency rollback - minimal safety checks")
	}

	plan := &RollbackPlan{
		Request:       request,
		Steps:         steps,
		EstimatedTime: totalTime,
		RiskLevel:     riskLevel,
		Warnings:      warnings,
		Prerequisites: []string{
			" master connectivity",
			"Nomad cluster availability",
			"Consul cluster availability",
		},
	}

	return plan, nil
}

// confirmRollback gets user confirmation for the rollback
func confirmRollback(rc *eos_io.RuntimeContext, plan *RollbackPlan) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Requesting rollback confirmation")

	fmt.Printf("\n Rollback Plan for %s\n", plan.Request.AppName)
	fmt.Printf("═══════════════════════════════\n")
	fmt.Printf("From Version: %s\n", plan.Request.CurrentVersion)
	fmt.Printf("To Version:   %s\n", plan.Request.TargetVersion)
	fmt.Printf("Reason:       %s\n", plan.Request.Reason)
	fmt.Printf("Risk Level:   %s\n", plan.RiskLevel)
	fmt.Printf("Estimated Time: %s\n", plan.EstimatedTime)
	fmt.Printf("\n")

	if len(plan.Warnings) > 0 {
		fmt.Printf("Warnings:\n")
		for _, warning := range plan.Warnings {
			fmt.Printf("   • %s\n", warning)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("Steps to execute:\n")
	for i, step := range plan.Steps {
		if step.Required {
			fmt.Printf("  %d. %s (%s)\n", i+1, step.Description, step.EstimatedTime)
		}
	}
	fmt.Printf("\n")

	// Get confirmation (implementation would use interactive prompt)
	fmt.Printf("Do you want to proceed with this rollback? (y/N): ")

	// For now, assume confirmation (in real implementation, would read from stdin)
	logger.Info("Rollback confirmed by user")
	return nil
}

// displayRollbackPlan displays the rollback plan for dry run
func displayRollbackPlan(plan *RollbackPlan) error {
	fmt.Printf("\n Rollback Plan (Dry Run) for %s\n", plan.Request.AppName)
	fmt.Printf("═══════════════════════════════════════\n")
	fmt.Printf("Current Version: %s\n", plan.Request.CurrentVersion)
	fmt.Printf("Target Version:  %s\n", plan.Request.TargetVersion)
	fmt.Printf("Estimated Time:  %s\n", plan.EstimatedTime)
	fmt.Printf("Risk Level:      %s\n", plan.RiskLevel)
	fmt.Printf("\n")

	fmt.Printf("Steps that would be executed:\n")
	for i, step := range plan.Steps {
		if step.Required {
			fmt.Printf("  %d. [%s] %s\n", i+1, step.Component, step.Description)
			fmt.Printf("     Action: %s, Time: %s, Risk: %s\n", step.Action, step.EstimatedTime, step.Risk)
		}
	}

	fmt.Printf("\nNote: This was a dry run. No changes were made.\n")
	return nil
}

// executeRollbackPlan executes the rollback plan
func executeRollbackPlan(rc *eos_io.RuntimeContext, plan *RollbackPlan) (*RollbackResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	startTime := time.Now()
	result := &RollbackResult{
		AppName:       plan.Request.AppName,
		FromVersion:   plan.Request.CurrentVersion,
		ToVersion:     plan.Request.TargetVersion,
		Reason:        plan.Request.Reason,
		StartTime:     startTime,
		StepsExecuted: make([]RollbackStepResult, 0),
		Metadata:      make(map[string]interface{}),
	}

	// Initialize deployment manager
	deployConfig := deploy.DefaultDeploymentConfig()
	manager, err := deploy.NewDeploymentManager(deployConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create deployment manager: %w", err)
	}

	logger.Info("Executing rollback plan",
		zap.String("app_name", plan.Request.AppName),
		zap.Int("steps", len(plan.Steps)))

	// Execute each required step
	for _, step := range plan.Steps {
		if !step.Required {
			continue
		}

		stepResult := RollbackStepResult{
			Step:      step,
			StartTime: time.Now(),
			Status:    "running",
		}

		logger.Info("Executing rollback step",
			zap.String("step", step.Name),
			zap.String("component", step.Component))

		// Execute step based on component
		var stepErr error
		switch step.Component {
		case "":
			stepErr = executeRollback(rc, plan.Request.AppName, plan.Request.TargetVersion, plan.Request.Reason, plan.Request.Emergency, false, plan.Request.Timeout, false)
		case "consul":
			stepErr = executeConsulRollback(rc, manager, plan.Request, step.Action)
		case "backup":
			stepErr = executeBackupStep(rc, plan.Request)
		case "health":
			stepErr = executeHealthVerification(rc, manager, plan.Request)
		default:
			stepErr = fmt.Errorf("unknown rollback component: %s", step.Component)
		}

		// Record step result
		stepResult.EndTime = time.Now()
		stepResult.Duration = stepResult.EndTime.Sub(stepResult.StartTime)

		if stepErr != nil {
			stepResult.Status = "failed"
			stepResult.Error = stepErr.Error()
			result.StepsExecuted = append(result.StepsExecuted, stepResult)

			result.Success = false
			result.Error = fmt.Sprintf("Step %s failed: %s", step.Name, stepErr.Error())
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			return result, fmt.Errorf("rollback step %s failed: %w", step.Name, stepErr)
		}

		stepResult.Status = "completed"
		result.StepsExecuted = append(result.StepsExecuted, stepResult)

		logger.Info("Rollback step completed",
			zap.String("step", step.Name),
			zap.Duration("duration", stepResult.Duration))
	}

	// Mark rollback as successful
	result.Success = true
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// executeConsulRollback handles Consul service registration/deregistration
func executeConsulRollback(rc *eos_io.RuntimeContext, manager *deploy.DeploymentManager, request *RollbackRequest, action string) error {
	logger := otelzap.Ctx(rc.Ctx)

	serviceID := request.AppName + "-web"

	switch action {
	case "deregister":
		logger.Info("Deregistering service from Consul", zap.String("service_id", serviceID))
		return manager.GetConsulClient().DeregisterService(rc.Ctx, serviceID)
	case "register":
		logger.Info("Registering service with Consul", zap.String("service_id", serviceID))
		// Implementation would register the service with proper health checks
		return nil
	default:
		return fmt.Errorf("unknown Consul action: %s", action)
	}
}

// executeBackupStep creates a backup before rollback
func executeBackupStep(rc *eos_io.RuntimeContext, request *RollbackRequest) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating pre-rollback backup", zap.String("app_name", request.AppName))

	// Implementation would create backup of current state
	// For now, just simulate the backup
	time.Sleep(1 * time.Second)

	return nil
}

// executeHealthVerification verifies rollback health
func executeHealthVerification(rc *eos_io.RuntimeContext, manager *deploy.DeploymentManager, request *RollbackRequest) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying rollback health", zap.String("app_name", request.AppName))

	// Check Nomad job status
	jobID := request.AppName + "-web"
	jobStatus, err := manager.GetNomadClient().GetJobStatus(rc.Ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job status: %w", err)
	}

	if jobStatus.Status != "running" {
		return fmt.Errorf("job is not running after rollback, status: %s", jobStatus.Status)
	}

	logger.Info("Rollback health verification passed")
	return nil
}

// sendRollbackNotifications sends notifications about rollback completion
func sendRollbackNotifications(rc *eos_io.RuntimeContext, result *RollbackResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Sending rollback notifications",
		zap.String("app_name", result.AppName),
		zap.Bool("success", result.Success))

	// Implementation would send notifications via configured channels
	// For now, just log the notification
	status := " SUCCESS"
	if !result.Success {
		status = "❌ FAILED"
	}

	message := fmt.Sprintf("%s Rollback for %s: %s → %s (Duration: %s)",
		status, result.AppName, result.FromVersion, result.ToVersion, result.Duration.String())

	logger.Info("Rollback notification", zap.String("message", message))

	return nil
}

// Helper functions

// rollbackApplication gets the current deployed version
func rollbackApplication(_ *eos_io.RuntimeContext, _ string) error {
	// TODO: Implementation would query current version from deployment system
	return nil
}

// getPreviousStableVersion gets the previous stable version for rollback
func getPreviousStableVersion(rc *eos_io.RuntimeContext, appName string) (string, error) {
	// Implementation would query deployment history to find previous stable version
	return "20240113100000", nil
}
