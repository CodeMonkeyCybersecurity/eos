// Package backup provides backup operations following the AIE pattern
package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HookOperation implements AIE pattern for running backup hooks
type HookOperation struct {
	Hook            string
	Logger          otelzap.LoggerWithCtx
	AllowedCommands map[string]struct{}
	HooksEnabled    bool
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
// SECURITY: Validates hook command against whitelist to prevent RCE
func (h *HookOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	h.Logger.Info("Executing hook",
		zap.String("command", h.Hook))

	if !h.HooksEnabled {
		recordHookDecision("disabled", false)
		return &patterns.InterventionResult{
			Success: false,
			Message: "hooks are disabled by policy",
		}, fmt.Errorf("hooks are disabled by policy")
	}

	parts := strings.Fields(h.Hook)
	if len(parts) == 0 {
		recordHookDecision("empty_command", false)
		return &patterns.InterventionResult{
			Success: false,
			Message: "hook command is empty",
		}, fmt.Errorf("empty hook command")
	}

	cmd := parts[0]

	// Command must be absolute path
	if !filepath.IsAbs(cmd) {
		recordHookDecision("non_absolute_command", false)
		return &patterns.InterventionResult{
			Success: false,
			Message: "hook command must be absolute path",
		}, fmt.Errorf("hook command must be absolute path: %s", cmd)
	}

	// Clean path to prevent traversal
	cleanCmd := filepath.Clean(cmd)

	// Check allowlist
	if _, exists := h.AllowedCommands[cleanCmd]; !exists {
		recordHookDecision("deny_not_allowlisted", false)
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("command not whitelisted: %s", cleanCmd),
		}, fmt.Errorf("command not whitelisted: %s", cleanCmd)
	}

	if err := validateHookArgs(parts[1:]); err != nil {
		recordHookDecision("deny_bad_arguments", false)
		return &patterns.InterventionResult{
			Success: false,
			Message: err.Error(),
		}, err
	}

	output, err := execute.Run(ctx, execute.Options{
		Command: cleanCmd, // Use cleaned path
		Args:    parts[1:],
		Capture: true,
	})

	if err != nil {
		recordHookDecision("execution_error", false)
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("hook execution failed: %v", err),
		}, err
	}
	recordHookDecision("allowlist_execute", true)

	return &patterns.InterventionResult{
		Success: true,
		Message: "hook executed successfully",
		Changes: []patterns.Change{
			{
				Type:        "hook_execution",
				Description: fmt.Sprintf("Executed hook: %s", cleanCmd),
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
	return RunHookWithSettings(ctx, logger, hook, Settings{})
}

// RunHookWithSettings executes a backup hook using settings-based policy.
func RunHookWithSettings(ctx context.Context, logger otelzap.LoggerWithCtx, hook string, settings Settings) error {
	operation := &HookOperation{
		Hook:            hook,
		Logger:          logger,
		AllowedCommands: buildAllowedHookCommands(settings),
		HooksEnabled:    hooksEnabled(settings),
	}

	executor := patterns.NewExecutor(logger)
	return executor.Execute(ctx, operation, fmt.Sprintf("backup_hook_%s", hook))
}

func hooksEnabled(settings Settings) bool {
	if settings.HooksPolicy.Enabled == nil {
		return true
	}
	return *settings.HooksPolicy.Enabled
}

func buildAllowedHookCommands(settings Settings) map[string]struct{} {
	allowed := make(map[string]struct{}, len(DefaultAllowedHookCommands)+len(settings.HooksPolicy.AllowedCommands))
	for _, cmd := range DefaultAllowedHookCommands {
		clean := strings.TrimSpace(cmd)
		if clean == "" || !filepath.IsAbs(clean) {
			continue
		}
		allowed[filepath.Clean(clean)] = struct{}{}
	}

	for _, cmd := range settings.HooksPolicy.AllowedCommands {
		clean := strings.TrimSpace(cmd)
		if clean == "" || !filepath.IsAbs(clean) {
			continue
		}
		allowed[filepath.Clean(clean)] = struct{}{}
	}

	return allowed
}

func validateHookArgs(args []string) error {
	for i, arg := range args {
		if strings.ContainsAny(arg, ";|&$`<>(){}[]'\"\\") {
			return fmt.Errorf("invalid characters in hook argument %d", i+1)
		}

		if strings.Contains(arg, "..") {
			return fmt.Errorf("path traversal detected in argument %d", i+1)
		}
	}

	return nil
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
	ListSnapshots() ([]Snapshot, error)
}

// Assess checks if backup can proceed
func (b *BackupOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	b.Logger.Info("Assessing backup readiness",
		zap.String("profile", b.ProfileName),
		zap.String("repository", b.RepoName))

	prerequisites := make(map[string]bool)

	// Check repository selection
	prerequisites["repository_exists"] = strings.TrimSpace(b.RepoName) != ""
	if !prerequisites["repository_exists"] {
		return &patterns.AssessmentResult{
			CanProceed:    false,
			Reason:        "repository is required",
			Prerequisites: prerequisites,
		}, nil
	}

	// Check paths exist
	for _, path := range b.Profile.Paths {
		if _, err := os.Stat(path); err != nil {
			prerequisites[fmt.Sprintf("path_%s", path)] = false
			return &patterns.AssessmentResult{
				CanProceed:    false,
				Reason:        fmt.Sprintf("backup path does not exist: %s", path),
				Prerequisites: prerequisites,
			}, nil
		}
		prerequisites[fmt.Sprintf("path_%s", path)] = true
	}

	availableBytes, err := availableDiskBytes(b.Profile.Paths[0])
	if err != nil {
		prerequisites["disk_space_available"] = false
		return &patterns.AssessmentResult{
			CanProceed:    false,
			Reason:        fmt.Sprintf("failed to assess disk space: %v", err),
			Prerequisites: prerequisites,
		}, nil
	}

	prerequisites["disk_space_available"] = availableBytes > 0
	if !prerequisites["disk_space_available"] {
		return &patterns.AssessmentResult{
			CanProceed:    false,
			Reason:        "insufficient disk space available for backup",
			Prerequisites: prerequisites,
		}, nil
	}

	return &patterns.AssessmentResult{
		CanProceed:    true,
		Prerequisites: prerequisites,
		Context: map[string]interface{}{
			"paths_count":       len(b.Profile.Paths),
			"tags_count":        len(b.Profile.Tags),
			"available_bytes":   availableBytes,
			"repository_name":   b.RepoName,
			"profile_name":      b.ProfileName,
			"profile_has_hooks": b.Profile.Hooks != nil,
		},
	}, nil
}

// Intervene performs the backup
func (b *BackupOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	b.Logger.Info("Performing backup",
		zap.String("profile", b.ProfileName),
		zap.Bool("dry_run", b.DryRun))

	if b.DryRun {
		changes := make([]patterns.Change, 0, len(b.Profile.Paths))
		for _, path := range b.Profile.Paths {
			changes = append(changes, patterns.Change{
				Type:        "dry_run_path",
				Description: fmt.Sprintf("Would back up path %s", path),
			})
		}

		return &patterns.InterventionResult{
			Success: true,
			Message: "dry run completed",
			Changes: changes,
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

	if b.DryRun {
		validations["backup_exists"] = patterns.ValidationResult{
			Passed:  true,
			Message: "dry run: backup execution intentionally skipped",
		}
		validations["backup_integrity"] = patterns.ValidationResult{
			Passed:  true,
			Message: "dry run: integrity verification intentionally skipped",
		}

		return &patterns.EvaluationResult{
			Success:     true,
			Message:     "backup dry run validated successfully",
			Validations: validations,
		}, nil
	}

	snapshots, err := b.Client.ListSnapshots()
	if err != nil {
		return &patterns.EvaluationResult{
			Success: false,
			Message: "backup validation failed",
			Validations: map[string]patterns.ValidationResult{
				"backup_exists": {
					Passed:  false,
					Message: fmt.Sprintf("failed to list snapshots: %v", err),
				},
			},
		}, nil
	}

	hasSnapshot := len(snapshots) > 0
	validations["backup_exists"] = patterns.ValidationResult{
		Passed:  hasSnapshot,
		Message: fmt.Sprintf("found %d snapshots in repository", len(snapshots)),
	}

	recentSnapshot := false
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, snapshot := range snapshots {
		if snapshot.Time.After(cutoff) {
			recentSnapshot = true
			break
		}
	}
	validations["backup_integrity"] = patterns.ValidationResult{
		Passed:  hasSnapshot && recentSnapshot,
		Message: "at least one recent snapshot exists",
	}

	if !validations["backup_exists"].Passed || !validations["backup_integrity"].Passed {
		return &patterns.EvaluationResult{
			Success:     false,
			Message:     "backup validation failed",
			Validations: validations,
		}, nil
	}

	return &patterns.EvaluationResult{
		Success:     true,
		Message:     "backup validated successfully",
		Validations: validations,
	}, nil
}

func availableDiskBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}

	return stat.Bavail * uint64(stat.Bsize), nil
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
