// pkg/ai/actions.go

package ai

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ActionExecutor executes AI-suggested actions
type ActionExecutor struct {
	workingDir string
	backupDir  string
	dryRun     bool
}

// Action represents an action that can be executed
type Action struct {
	Type        ActionType            `json:"type"`
	Description string               `json:"description"`
	Target      string               `json:"target"`
	Content     string               `json:"content"`
	Command     string               `json:"command"`
	Arguments   []string             `json:"arguments"`
	Environment map[string]string    `json:"environment"`
	Metadata    map[string]any       `json:"metadata"`
	Validation  *ActionValidation    `json:"validation,omitempty"`
}

// ActionType represents the type of action
type ActionType string

const (
	ActionTypeFileCreate   ActionType = "file_create"
	ActionTypeFileModify   ActionType = "file_modify"
	ActionTypeFileDelete   ActionType = "file_delete"
	ActionTypeCommand      ActionType = "command"
	ActionTypeService      ActionType = "service"
	ActionTypeContainer    ActionType = "container"
	ActionTypeTerraform    ActionType = "terraform"
	ActionTypeVault        ActionType = "vault"
	ActionTypeConsul       ActionType = "consul"
)

// ActionValidation represents validation rules for actions
type ActionValidation struct {
	RequireConfirmation bool     `json:"require_confirmation"`
	RestrictedPaths     []string `json:"restricted_paths"`
	AllowedCommands     []string `json:"allowed_commands"`
	MaxFileSize         int64    `json:"max_file_size"`
}

// ActionResult represents the result of an action execution
type ActionResult struct {
	Success     bool      `json:"success"`
	Message     string    `json:"message"`
	Output      string    `json:"output"`
	Error       string    `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	BackupPath  string    `json:"backup_path,omitempty"`
	ChangedFiles []string `json:"changed_files,omitempty"`
}

// NewActionExecutor creates a new action executor
func NewActionExecutor(workingDir string, dryRun bool) *ActionExecutor {
	if workingDir == "" {
		workingDir, _ = os.Getwd()
	}

	backupDir := filepath.Join(workingDir, ".eos-ai-backups", time.Now().Format("20060102-150405"))
	
	return &ActionExecutor{
		workingDir: workingDir,
		backupDir:  backupDir,
		dryRun:     dryRun,
	}
}

// ExecuteAction executes a single action
func (ae *ActionExecutor) ExecuteAction(rc *eos_io.RuntimeContext, action *Action) (*ActionResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	start := time.Now()

	logger.Info("Executing action",
		zap.String("type", string(action.Type)),
		zap.String("description", action.Description),
		zap.Bool("dry_run", ae.dryRun))

	result := &ActionResult{
		Success: false,
		Message: action.Description,
	}

	// Validate action
	if err := ae.validateAction(action); err != nil {
		result.Error = fmt.Sprintf("Action validation failed: %v", err)
		result.Duration = time.Since(start)
		return result, err
	}

	// Execute based on action type
	var err error
	switch action.Type {
	case ActionTypeFileCreate, ActionTypeFileModify:
		err = ae.executeFileAction(rc, action, result)
	case ActionTypeFileDelete:
		err = ae.executeFileDelete(rc, action, result)
	case ActionTypeCommand:
		err = ae.executeCommand(rc, action, result)
	case ActionTypeService:
		err = ae.executeServiceAction(rc, action, result)
	case ActionTypeContainer:
		err = ae.executeContainerAction(rc, action, result)
	case ActionTypeTerraform:
		err = ae.executeTerraformAction(rc, action, result)
	case ActionTypeVault:
		err = ae.executeVaultAction(rc, action, result)
	case ActionTypeConsul:
		err = ae.executeConsulAction(rc, action, result)
	default:
		err = fmt.Errorf("unsupported action type: %s", action.Type)
	}

	if err != nil {
		result.Error = err.Error()
		logger.Error("Action execution failed", zap.Error(err))
	} else {
		result.Success = true
		logger.Info("Action executed successfully")
	}

	result.Duration = time.Since(start)
	return result, err
}

// validateAction validates an action before execution
func (ae *ActionExecutor) validateAction(action *Action) error {
	if action.Validation == nil {
		return nil
	}

	// Check restricted paths
	if action.Target != "" {
		targetPath := filepath.Join(ae.workingDir, action.Target)
		for _, restricted := range action.Validation.RestrictedPaths {
			if strings.HasPrefix(targetPath, restricted) {
				return fmt.Errorf("action targets restricted path: %s", restricted)
			}
		}
	}

	// Check allowed commands
	if action.Type == ActionTypeCommand && len(action.Validation.AllowedCommands) > 0 {
		allowed := false
		for _, allowedCmd := range action.Validation.AllowedCommands {
			if action.Command == allowedCmd {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("command not in allowed list: %s", action.Command)
		}
	}

	// Check file size limits
	if (action.Type == ActionTypeFileCreate || action.Type == ActionTypeFileModify) && 
		action.Validation.MaxFileSize > 0 {
		if int64(len(action.Content)) > action.Validation.MaxFileSize {
			return fmt.Errorf("content exceeds maximum file size: %d bytes", action.Validation.MaxFileSize)
		}
	}

	return nil
}

// executeFileAction executes file creation or modification
func (ae *ActionExecutor) executeFileAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	targetPath := filepath.Join(ae.workingDir, action.Target)
	
	// Create backup if file exists
	if _, err := os.Stat(targetPath); err == nil {
		if err := ae.createBackup(targetPath); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		result.BackupPath = filepath.Join(ae.backupDir, action.Target)
	}

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would write %d bytes to %s", len(action.Content), targetPath)
		return nil
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(targetPath, []byte(action.Content), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	result.ChangedFiles = []string{targetPath}
	result.Output = fmt.Sprintf("Successfully wrote %d bytes to %s", len(action.Content), targetPath)
	return nil
}

// executeFileDelete executes file deletion
func (ae *ActionExecutor) executeFileDelete(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	targetPath := filepath.Join(ae.workingDir, action.Target)
	
	// Create backup before deletion
	if err := ae.createBackup(targetPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	result.BackupPath = filepath.Join(ae.backupDir, action.Target)

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would delete %s", targetPath)
		return nil
	}

	if err := os.Remove(targetPath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	result.ChangedFiles = []string{targetPath}
	result.Output = fmt.Sprintf("Successfully deleted %s", targetPath)
	return nil
}

// executeCommand executes a system command
func (ae *ActionExecutor) executeCommand(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would execute: %s %s", action.Command, strings.Join(action.Arguments, " "))
		return nil
	}

	cmd := exec.CommandContext(rc.Ctx, action.Command, action.Arguments...)
	cmd.Dir = ae.workingDir

	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range action.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}

// executeServiceAction executes systemd service actions
func (ae *ActionExecutor) executeServiceAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	serviceName := action.Target
	serviceAction := action.Command // start, stop, restart, enable, disable

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would execute: systemctl %s %s", serviceAction, serviceName)
		return nil
	}

	cmd := exec.CommandContext(rc.Ctx, "systemctl", serviceAction, serviceName)
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		return fmt.Errorf("service action failed: %w", err)
	}

	return nil
}

// executeContainerAction executes Docker container actions
func (ae *ActionExecutor) executeContainerAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	containerName := action.Target
	containerAction := action.Command // start, stop, restart, remove

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would execute: docker %s %s", containerAction, containerName)
		return nil
	}

	cmd := exec.CommandContext(rc.Ctx, "docker", containerAction, containerName)
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		return fmt.Errorf("container action failed: %w", err)
	}

	return nil
}

// executeTerraformAction executes Terraform actions
func (ae *ActionExecutor) executeTerraformAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	terraformAction := action.Command // init, plan, apply, destroy

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would execute: terraform %s", terraformAction)
		return nil
	}

	args := []string{terraformAction}
	args = append(args, action.Arguments...)

	cmd := exec.CommandContext(rc.Ctx, "terraform", args...)
	cmd.Dir = ae.workingDir
	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		return fmt.Errorf("terraform action failed: %w", err)
	}

	return nil
}

// executeVaultAction executes Vault actions
func (ae *ActionExecutor) executeVaultAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	vaultAction := action.Command // read, write, delete, etc.

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would execute: vault %s %s", vaultAction, action.Target)
		return nil
	}

	args := []string{vaultAction}
	if action.Target != "" {
		args = append(args, action.Target)
	}
	args = append(args, action.Arguments...)

	cmd := exec.CommandContext(rc.Ctx, "vault", args...)
	cmd.Dir = ae.workingDir

	// Set Vault environment
	cmd.Env = os.Environ()
	for key, value := range action.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		return fmt.Errorf("vault action failed: %w", err)
	}

	return nil
}

// executeConsulAction executes Consul actions
func (ae *ActionExecutor) executeConsulAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	consulAction := action.Command // kv put, kv get, services register, etc.

	if ae.dryRun {
		result.Output = fmt.Sprintf("DRY RUN: Would execute: consul %s %s", consulAction, action.Target)
		return nil
	}

	args := strings.Split(consulAction, " ") // Handle multi-word commands like "kv put"
	if action.Target != "" {
		args = append(args, action.Target)
	}
	args = append(args, action.Arguments...)

	cmd := exec.CommandContext(rc.Ctx, "consul", args...)
	cmd.Dir = ae.workingDir

	// Set Consul environment
	cmd.Env = os.Environ()
	for key, value := range action.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		return fmt.Errorf("consul action failed: %w", err)
	}

	return nil
}

// createBackup creates a backup of a file
func (ae *ActionExecutor) createBackup(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // File doesn't exist, no backup needed
	}

	// Create backup directory
	if err := os.MkdirAll(ae.backupDir, 0755); err != nil {
		return err
	}

	// Read original file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Create backup file path
	relPath, err := filepath.Rel(ae.workingDir, filePath)
	if err != nil {
		relPath = filepath.Base(filePath)
	}
	backupPath := filepath.Join(ae.backupDir, relPath)

	// Ensure backup directory exists
	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		return err
	}

	// Write backup file
	return os.WriteFile(backupPath, content, 0644)
}

// ParseActionsFromResponse parses actions from AI response text
func ParseActionsFromResponse(response string) ([]*Action, error) {
	var actions []*Action

	// Look for action blocks in the response
	actionRegex := regexp.MustCompile("(?s)```(action|json)\\s*\\n(.*?)\\n```")
	matches := actionRegex.FindAllStringSubmatch(response, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			actionText := strings.TrimSpace(match[2])
			
			// Try to parse as JSON action
			action, err := parseJSONAction(actionText)
			if err == nil {
				actions = append(actions, action)
				continue
			}

			// Try to parse as structured text action
			action, err = parseTextAction(actionText)
			if err == nil {
				actions = append(actions, action)
			}
		}
	}

	// If no explicit actions found, try to infer actions from the response
	if len(actions) == 0 {
		inferredActions := inferActionsFromText(response)
		actions = append(actions, inferredActions...)
	}

	return actions, nil
}

// parseJSONAction parses a JSON-formatted action
func parseJSONAction(text string) (*Action, error) {
	// This would use json.Unmarshal to parse JSON actions
	// For now, return a simple implementation
	return &Action{
		Type:        ActionTypeCommand,
		Description: "Parsed action from JSON",
		Command:     "echo",
		Arguments:   []string{"JSON action parsed"},
	}, nil
}

// parseTextAction parses a text-formatted action
func parseTextAction(text string) (*Action, error) {
	lines := strings.Split(text, "\n")
	action := &Action{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Type:") {
			action.Type = ActionType(strings.TrimSpace(strings.TrimPrefix(line, "Type:")))
		} else if strings.HasPrefix(line, "Description:") {
			action.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
		} else if strings.HasPrefix(line, "Target:") {
			action.Target = strings.TrimSpace(strings.TrimPrefix(line, "Target:"))
		} else if strings.HasPrefix(line, "Command:") {
			action.Command = strings.TrimSpace(strings.TrimPrefix(line, "Command:"))
		}
	}

	if action.Type == "" {
		return nil, fmt.Errorf("action type not specified")
	}

	return action, nil
}

// inferActionsFromText infers actions from natural language text
func inferActionsFromText(text string) []*Action {
	var actions []*Action

	// Look for file modification suggestions
	if strings.Contains(strings.ToLower(text), "modify") && strings.Contains(strings.ToLower(text), "file") {
		action := &Action{
			Type:        ActionTypeFileModify,
			Description: "Inferred file modification from AI response",
		}
		actions = append(actions, action)
	}

	// Look for command suggestions
	if strings.Contains(strings.ToLower(text), "run") || strings.Contains(strings.ToLower(text), "execute") {
		action := &Action{
			Type:        ActionTypeCommand,
			Description: "Inferred command execution from AI response",
		}
		actions = append(actions, action)
	}

	return actions
}