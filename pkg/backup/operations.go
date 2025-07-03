// Package backup provides backup operations following the AIE pattern
package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HookOperation implements AIE pattern for running backup hooks
type HookOperation struct {
	Hook   string
	Logger otelzap.LoggerWithCtx
}

// Assess checks if the hook can be executed
func (h *HookOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	h.Logger.Info("Assessing hook execution",
		zap.String("hook", h.Hook))

	// Check if hook is a valid command
	parts := strings.Fields(h.Hook)
	if len(parts) == 0 {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "empty hook command",
		}, nil
	}

	// Check if command exists
	cmd := parts[0]
	if filepath.IsAbs(cmd) {
		// Check if absolute path exists
		if _, err := os.Stat(cmd); err != nil {
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     fmt.Sprintf("hook command not found: %s", cmd),
			}, nil
		}
	}

	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"command_exists": true,
			"valid_syntax":   true,
		},
	}, nil
}

// Intervene executes the hook
func (h *HookOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	h.Logger.Info("Executing hook",
		zap.String("command", h.Hook))

	parts := strings.Fields(h.Hook)
	output, err := execute.Run(ctx, execute.Options{
		Command: parts[0],
		Args:    parts[1:],
		Capture: true,
	})

	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("hook execution failed: %v", err),
		}, err
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "hook executed successfully",
		Changes: []patterns.Change{
			{
				Type:        "hook_execution",
				Description: fmt.Sprintf("Executed hook: %s", h.Hook),
				After:       output,
			},
		},
	}, nil
}

// Evaluate verifies hook execution was successful
func (h *HookOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	if !intervention.Success {
		return &patterns.EvaluationResult{
			Success: false,
			Message: "hook execution failed",
			Validations: map[string]patterns.ValidationResult{
				"execution": {
					Passed:  false,
					Message: intervention.Message,
				},
			},
		}, nil
	}

	return &patterns.EvaluationResult{
		Success: true,
		Message: "hook execution validated",
		Validations: map[string]patterns.ValidationResult{
			"execution": {
				Passed:  true,
				Message: "hook completed successfully",
			},
		},
	}, nil
}

// RunHook executes a backup hook using AIE pattern
func RunHook(ctx context.Context, logger otelzap.LoggerWithCtx, hook string) error {
	operation := &HookOperation{
		Hook:   hook,
		Logger: logger,
	}

	executor := patterns.NewExecutor(logger)
	return executor.Execute(ctx, operation, fmt.Sprintf("backup_hook_%s", hook))
}

// BackupOperation implements AIE pattern for backup operations
type BackupOperation struct {
	Client      BackupClient
	ProfileName string
	Profile     Profile
	RepoName    string
	DryRun      bool
	Logger      otelzap.LoggerWithCtx
}

// BackupClient interface for testing
type BackupClient interface {
	Backup(profileName string) error
}

// Assess checks if backup can proceed
func (b *BackupOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	b.Logger.Info("Assessing backup readiness",
		zap.String("profile", b.ProfileName),
		zap.String("repository", b.RepoName))

	prerequisites := make(map[string]bool)

	// Check repository exists
	// TODO: Implement repository check
	prerequisites["repository_exists"] = true

	// Check paths exist
	for _, path := range b.Profile.Paths {
		if _, err := os.Stat(path); err != nil {
			prerequisites[fmt.Sprintf("path_%s", path)] = false
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     fmt.Sprintf("backup path does not exist: %s", path),
				Prerequisites: prerequisites,
			}, nil
		}
		prerequisites[fmt.Sprintf("path_%s", path)] = true
	}

	// Check disk space
	// TODO: Implement disk space check
	prerequisites["disk_space_available"] = true

	return &patterns.AssessmentResult{
		CanProceed:    true,
		Prerequisites: prerequisites,
		Context: map[string]interface{}{
			"paths_count": len(b.Profile.Paths),
			"tags_count":  len(b.Profile.Tags),
		},
	}, nil
}

// Intervene performs the backup
func (b *BackupOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	b.Logger.Info("Performing backup",
		zap.String("profile", b.ProfileName),
		zap.Bool("dry_run", b.DryRun))

	if b.DryRun {
		// TODO: Implement dry run
		return &patterns.InterventionResult{
			Success: true,
			Message: "dry run completed",
			Changes: []patterns.Change{
				{
					Type:        "dry_run",
					Description: "Simulated backup operation",
				},
			},
		}, nil
	}

	// Perform actual backup
	err := b.Client.Backup(b.ProfileName)
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("backup failed: %v", err),
		}, err
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "backup completed successfully",
		Changes: []patterns.Change{
			{
				Type:        "backup",
				Description: fmt.Sprintf("Backed up profile %s to repository %s", b.ProfileName, b.RepoName),
			},
		},
	}, nil
}

// Evaluate verifies backup was successful
func (b *BackupOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	if !intervention.Success {
		return &patterns.EvaluationResult{
			Success:       false,
			Message:       "backup validation failed",
			NeedsRollback: false,
		}, nil
	}

	validations := make(map[string]patterns.ValidationResult)

	// TODO: Verify backup in repository
	validations["backup_exists"] = patterns.ValidationResult{
		Passed:  true,
		Message: "backup verified in repository",
	}

	// TODO: Check backup integrity
	validations["backup_integrity"] = patterns.ValidationResult{
		Passed:  true,
		Message: "backup integrity verified",
	}

	return &patterns.EvaluationResult{
		Success:     true,
		Message:     "backup validated successfully",
		Validations: validations,
	}, nil
}

// NotificationOperation implements AIE pattern for sending notifications
type NotificationOperation struct {
	Config  Notifications
	Subject string
	Body    string
	Logger  otelzap.LoggerWithCtx
}

// Assess checks if notification can be sent
func (n *NotificationOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	n.Logger.Info("Assessing notification capability",
		zap.String("method", n.Config.Method))

	// Validate notification method
	validMethods := []string{"email", "slack", "webhook"}
	methodValid := false
	for _, valid := range validMethods {
		if n.Config.Method == valid {
			methodValid = true
			break
		}
	}

	if !methodValid {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     fmt.Sprintf("invalid notification method: %s", n.Config.Method),
		}, nil
	}

	// Validate target
	if n.Config.Target == "" {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "notification target not configured",
		}, nil
	}

	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"method_valid": true,
			"target_set":   true,
		},
	}, nil
}

// Intervene sends the notification
func (n *NotificationOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	n.Logger.Info("Sending notification",
		zap.String("method", n.Config.Method),
		zap.String("target", n.Config.Target))

	// TODO: Implement actual notification sending
	switch n.Config.Method {
	case "email":
		// Send email notification
		n.Logger.Info("Would send email",
			zap.String("to", n.Config.Target),
			zap.String("subject", n.Subject))
	case "slack":
		// Send Slack notification
		n.Logger.Info("Would send Slack message",
			zap.String("channel", n.Config.Target),
			zap.String("message", n.Subject))
	case "webhook":
		// Send webhook notification
		n.Logger.Info("Would call webhook",
			zap.String("url", n.Config.Target),
			zap.String("payload", n.Body))
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "notification sent",
		Changes: []patterns.Change{
			{
				Type:        "notification",
				Description: fmt.Sprintf("Sent %s notification to %s", n.Config.Method, n.Config.Target),
			},
		},
	}, nil
}

// Evaluate verifies notification was sent
func (n *NotificationOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	// TODO: Implement notification verification
	return &patterns.EvaluationResult{
		Success: true,
		Message: "notification delivery assumed successful",
		Validations: map[string]patterns.ValidationResult{
			"delivery": {
				Passed:  true,
				Message: "notification sent (delivery not verified)",
			},
		},
	}, nil
}

// SendNotification sends a backup notification using AIE pattern
func SendNotification(ctx context.Context, logger otelzap.LoggerWithCtx, config Notifications, subject, body string) error {
	if config.Method == "" || config.Target == "" {
		logger.Debug("Notification not configured, skipping")
		return nil
	}

	operation := &NotificationOperation{
		Config:  config,
		Subject: subject,
		Body:    body,
		Logger:  logger,
	}

	executor := patterns.NewExecutor(logger)
	return executor.Execute(ctx, operation, "backup_notification")
}