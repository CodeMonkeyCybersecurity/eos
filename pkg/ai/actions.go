// pkg/ai/actions.go

package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ActionExecutor executes AI-suggested actions
type ActionExecutor struct {
	workingDir   string
	workspaceDir string
	backupDir    string
	dryRun       bool
	policy       *ActionExecutionPolicy
	auditPath    string
	auditOnce    sync.Once
	auditMu      sync.Mutex
}

// Action represents an action that can be executed
type Action struct {
	Type        ActionType        `json:"type"`
	Description string            `json:"description"`
	Target      string            `json:"target"`
	Content     string            `json:"content"`
	Command     string            `json:"command"`
	Arguments   []string          `json:"arguments"`
	Environment map[string]string `json:"environment"`
	Metadata    map[string]any    `json:"metadata"`
	Validation  *ActionValidation `json:"validation,omitempty"`
}

func (a *Action) ensureMetadata() {
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}
}

func (a *Action) setResolvedTarget(path string) {
	a.ensureMetadata()
	a.Metadata[metadataResolvedTargetKey] = path
}

func (a *Action) resolvedTarget() string {
	if a == nil || a.Metadata == nil {
		return ""
	}
	if v, ok := a.Metadata[metadataResolvedTargetKey]; ok {
		if resolved, ok := v.(string); ok {
			return resolved
		}
	}
	return ""
}

// ActionExecutionPolicy enforces guardrails on AI-generated actions
type ActionExecutionPolicy struct {
	WorkspaceAllowlist []string
	AllowedCommands    []string
	DeniedArguments    []string
	MaxArguments       int
	MaxCommandLength   int
}

// ActionAuditEntry captures each executed action for forensic review
type ActionAuditEntry struct {
	Timestamp         time.Time      `json:"timestamp"`
	Type              ActionType     `json:"type"`
	Description       string         `json:"description"`
	Target            string         `json:"target"`
	Command           string         `json:"command"`
	Arguments         []string       `json:"arguments"`
	Success           bool           `json:"success"`
	Error             string         `json:"error,omitempty"`
	ValidationProfile string         `json:"validation_profile,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

func (policy *ActionExecutionPolicy) ResolveTarget(baseDir, target string) (string, error) {
	if policy == nil {
		return "", fmt.Errorf("execution policy not configured")
	}
	cleaned := filepath.Clean(target)
	var candidate string
	if filepath.IsAbs(cleaned) {
		candidate = cleaned
	} else {
		candidate = filepath.Join(baseDir, cleaned)
	}
	absCandidate := candidate
	if abs, err := filepath.Abs(candidate); err == nil {
		absCandidate = abs
	}
	if err := ensureWithinAllowlist(absCandidate, policy.WorkspaceAllowlist); err != nil {
		return "", err
	}
	if err := rejectSymlinkTraversal(baseDir, absCandidate); err != nil {
		return "", err
	}
	return absCandidate, nil
}

func ensureWithinAllowlist(target string, allowlist []string) error {
	if len(allowlist) == 0 {
		return fmt.Errorf("no workspace allowlist configured")
	}
	for _, allowed := range allowlist {
		if allowed == "" {
			continue
		}
		normalized := filepath.Clean(allowed)
		if abs, err := filepath.Abs(normalized); err == nil {
			normalized = abs
		}
		rel, err := filepath.Rel(normalized, target)
		if err != nil {
			continue
		}
		if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !strings.HasPrefix(rel, "../")) {
			return nil
		}
	}
	return fmt.Errorf("target %s outside authorized workspace", target)
}

func rejectSymlinkTraversal(baseDir, target string) error {
	rel, err := filepath.Rel(baseDir, target)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	sep := string(filepath.Separator)
	current := baseDir
	segments := strings.Split(rel, sep)
	for _, segment := range segments {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink traversal detected at %s", current)
		}
	}
	return nil
}

// ActionType represents the type of action
type ActionType string

const (
	ActionTypeFileCreate ActionType = "file_create"
	ActionTypeFileModify ActionType = "file_modify"
	ActionTypeFileDelete ActionType = "file_delete"
	ActionTypeCommand    ActionType = "command"
	ActionTypeService    ActionType = "service"
	ActionTypeContainer  ActionType = "container"
	ActionTypeTerraform  ActionType = "terraform"
	ActionTypeVault      ActionType = "vault"
	ActionTypeConsul     ActionType = "consul"
)

var (
	defaultAllowedCommands = []string{
		"bash", "sh", "cat", "cp", "mv", "chmod", "chown", "ls", "grep", "sed", "tee", "make",
		"go", "git", "terraform", "vault", "consul", "docker", "kubectl", "helm", "systemctl",
		"journalctl", "netstat", "ss", "openssl", "env",
	}
	defaultDeniedArguments = []string{"--force", "--delete", "--remove", "--recursive", "-rf", "rm", "mkfs", "dd", "poweroff", "shutdown", "reboot", "halt"}
)

const (
	metadataValidationProfileKey = "validation_profile"
	metadataResolvedTargetKey    = "__resolved_target"
)

// ActionValidation represents validation rules for actions
type ActionValidation struct {
	RequireConfirmation bool     `json:"require_confirmation"`
	RestrictedPaths     []string `json:"restricted_paths"`
	AllowedCommands     []string `json:"allowed_commands"`
	MaxFileSize         int64    `json:"max_file_size"`
	MaxArguments        int      `json:"max_arguments"`
	MaxCommandLength    int      `json:"max_command_length"`
	ValidationProfile   string   `json:"validation_profile"`
}

// ActionResult represents the result of an action execution
type ActionResult struct {
	Success      bool          `json:"success"`
	Message      string        `json:"message"`
	Output       string        `json:"output"`
	Error        string        `json:"error,omitempty"`
	Duration     time.Duration `json:"duration"`
	BackupPath   string        `json:"backup_path,omitempty"`
	ChangedFiles []string      `json:"changed_files,omitempty"`
}

// NewActionExecutor creates a new action executor
func NewActionExecutor(workingDir string, dryRun bool, policy *ActionExecutionPolicy) *ActionExecutor {
	if workingDir == "" {
		workingDir, _ = os.Getwd()
	}
	cleanWorkingDir := filepath.Clean(workingDir)
	if abs, err := filepath.Abs(cleanWorkingDir); err == nil {
		cleanWorkingDir = abs
	}

	backupDir := filepath.Join(cleanWorkingDir, ".eos-ai-backups", time.Now().Format("20060102-150405"))
	auditDir := filepath.Join(cleanWorkingDir, ".eos-ai-audit")
	_ = os.MkdirAll(auditDir, shared.ServiceDirPerm)
	auditPath := filepath.Join(auditDir, "actions.log")

	return &ActionExecutor{
		workingDir:   cleanWorkingDir,
		workspaceDir: cleanWorkingDir,
		backupDir:    backupDir,
		dryRun:       dryRun,
		policy:       policy,
		auditPath:    auditPath,
	}
}

// ExecuteAction executes a single action
func (ae *ActionExecutor) ExecuteAction(rc *eos_io.RuntimeContext, action *Action) (*ActionResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	start := time.Now()
	ae.ensurePolicy()

	logger.Info("Executing action",
		zap.String("type", string(action.Type)),
		zap.String("description", action.Description),
		zap.Bool("dry_run", ae.dryRun))

	result := &ActionResult{
		Success: false,
		Message: action.Description,
	}
	defer func() {
		result.Duration = time.Since(start)
		ae.recordAudit(action, result)
	}()

	// Validate action
	if err := ae.validateAction(action); err != nil {
		result.Error = fmt.Sprintf("Action validation failed: %v", err)
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

	return result, err
}

func (ae *ActionExecutor) ensurePolicy() *ActionExecutionPolicy {
	if ae.policy == nil {
		ae.policy = &ActionExecutionPolicy{
			WorkspaceAllowlist: []string{ae.workspaceDir},
			AllowedCommands:    append([]string{}, defaultAllowedCommands...),
			DeniedArguments:    append([]string{}, defaultDeniedArguments...),
			MaxArguments:       defaultMaxArguments,
			MaxCommandLength:   defaultMaxCommandLength,
		}
	}
	return ae.policy
}

// validateAction validates an action before execution
func (ae *ActionExecutor) validateAction(action *Action) error {
	if action == nil {
		return errors.New("action cannot be nil")
	}
	action.ensureMetadata()
	if action.Validation == nil {
		return fmt.Errorf("action %q missing validation metadata", action.Description)
	}
	if action.Validation.ValidationProfile == "" {
		if profile, ok := action.Metadata[metadataValidationProfileKey].(string); ok && profile != "" {
			action.Validation.ValidationProfile = profile
		}
	}
	if action.Validation.ValidationProfile == "" {
		return fmt.Errorf("action %q missing validation profile", action.Description)
	}

	if err := ae.validateTargetPath(action); err != nil {
		return err
	}
	if err := ae.validateCommand(action); err != nil {
		return err
	}

	if (action.Type == ActionTypeFileCreate || action.Type == ActionTypeFileModify) &&
		action.Validation.MaxFileSize > 0 {
		if int64(len(action.Content)) > action.Validation.MaxFileSize {
			return fmt.Errorf("content exceeds maximum file size: %d bytes", action.Validation.MaxFileSize)
		}
	}

	return nil
}

func (ae *ActionExecutor) validateTargetPath(action *Action) error {
	if action.Target == "" {
		return nil
	}
	policy := ae.ensurePolicy()
	resolved, err := policy.ResolveTarget(ae.workspaceDir, action.Target)
	if err != nil {
		return err
	}
	for _, restricted := range action.Validation.RestrictedPaths {
		if strings.HasPrefix(resolved, restricted) {
			return fmt.Errorf("action targets restricted path: %s", restricted)
		}
	}
	action.setResolvedTarget(resolved)
	return nil
}

func (ae *ActionExecutor) validateCommand(action *Action) error {
	if action.Type != ActionTypeCommand {
		return nil
	}
	policy := ae.ensurePolicy()
	allowed := policy.AllowedCommands
	if len(action.Validation.AllowedCommands) > 0 {
		allowed = action.Validation.AllowedCommands
	}
	if len(allowed) > 0 {
		allowedMatch := false
		for _, cmd := range allowed {
			if action.Command == cmd {
				allowedMatch = true
				break
			}
		}
		if !allowedMatch {
			return fmt.Errorf("command not in allowed list: %s", action.Command)
		}
	}

	maxArgs := action.Validation.MaxArguments
	if maxArgs == 0 {
		maxArgs = policy.MaxArguments
	}
	if maxArgs > 0 && len(action.Arguments) > maxArgs {
		return fmt.Errorf("command exceeds maximum allowed arguments (%d)", maxArgs)
	}

	maxLen := action.Validation.MaxCommandLength
	if maxLen == 0 {
		maxLen = policy.MaxCommandLength
	}
	commandLine := strings.TrimSpace(strings.Join(append([]string{action.Command}, action.Arguments...), " "))
	if maxLen > 0 && len(commandLine) > maxLen {
		return fmt.Errorf("command exceeds maximum allowed length (%d)", maxLen)
	}

	denied := policy.DeniedArguments
	for _, arg := range append([]string{action.Command}, action.Arguments...) {
		lowerArg := strings.ToLower(arg)
		for _, banned := range denied {
			if strings.Contains(lowerArg, strings.ToLower(banned)) {
				return fmt.Errorf("argument '%s' violates execution policy", arg)
			}
		}
	}
	return nil
}

func (ae *ActionExecutor) resolvedPathForAction(action *Action) (string, error) {
	if resolved := action.resolvedTarget(); resolved != "" {
		return resolved, nil
	}
	if action.Target == "" {
		return ae.workspaceDir, nil
	}
	policy := ae.ensurePolicy()
	resolved, err := policy.ResolveTarget(ae.workspaceDir, action.Target)
	if err != nil {
		return "", err
	}
	action.setResolvedTarget(resolved)
	return resolved, nil
}

// executeFileAction executes file creation or modification
func (ae *ActionExecutor) executeFileAction(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	targetPath, err := ae.resolvedPathForAction(action)
	if err != nil {
		return err
	}

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
	if err := os.MkdirAll(filepath.Dir(targetPath), shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(targetPath, []byte(action.Content), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	result.ChangedFiles = []string{targetPath}
	result.Output = fmt.Sprintf("Successfully wrote %d bytes to %s", len(action.Content), targetPath)
	return nil
}

// executeFileDelete executes file deletion
func (ae *ActionExecutor) executeFileDelete(rc *eos_io.RuntimeContext, action *Action, result *ActionResult) error {
	targetPath, err := ae.resolvedPathForAction(action)
	if err != nil {
		return err
	}

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
	if err := os.MkdirAll(ae.backupDir, shared.ServiceDirPerm); err != nil {
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
	if err := os.MkdirAll(filepath.Dir(backupPath), shared.ServiceDirPerm); err != nil {
		return err
	}

	// Write backup file
	return os.WriteFile(backupPath, content, shared.ConfigFilePerm)
}

func (ae *ActionExecutor) recordAudit(action *Action, result *ActionResult) {
	if action == nil || result == nil || ae.auditPath == "" {
		return
	}
	target := action.Target
	if resolved := action.resolvedTarget(); resolved != "" {
		if rel, err := filepath.Rel(ae.workspaceDir, resolved); err == nil {
			target = rel
		} else {
			target = resolved
		}
	}
	entry := ActionAuditEntry{
		Timestamp:   time.Now().UTC(),
		Type:        action.Type,
		Description: action.Description,
		Target:      target,
		Command:     action.Command,
		Arguments:   append([]string{}, action.Arguments...),
		Success:     result.Success,
		Error:       result.Error,
		Metadata:    map[string]any{},
	}
	if action.Validation != nil {
		entry.ValidationProfile = action.Validation.ValidationProfile
	}
	for key, value := range action.Metadata {
		if key == metadataResolvedTargetKey {
			continue
		}
		entry.Metadata[key] = value
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	ae.auditMu.Lock()
	defer ae.auditMu.Unlock()
	file, err := os.OpenFile(ae.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, shared.SecretFilePerm)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(data, '\n'))
}

// ParseActionsFromResponse parses actions from AI response text
func ParseActionsFromResponse(response string) ([]*Action, error) {
	var actions []*Action

	actionRegex := regexp.MustCompile("(?s)```(action|json)\\s*\\n(.*?)\\n```")
	matches := actionRegex.FindAllStringSubmatch(response, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		chunk := strings.TrimSpace(match[2])
		parsed, err := parseJSONActions(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse action block: %w", err)
		}
		actions = append(actions, parsed...)
	}

	if len(actions) == 0 {
		if parsed, err := parseJSONActions(strings.TrimSpace(response)); err == nil {
			actions = append(actions, parsed...)
		}
	}

	if len(actions) == 0 {
		return nil, fmt.Errorf("response missing structured action metadata")
	}

	for _, action := range actions {
		if err := ensureValidationMetadata(action); err != nil {
			return nil, err
		}
	}

	return actions, nil
}

func parseJSONActions(text string) ([]*Action, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, fmt.Errorf("empty action payload")
	}
	var actions []*Action
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &actions); err != nil {
			return nil, err
		}
	} else {
		var action Action
		if err := json.Unmarshal([]byte(trimmed), &action); err != nil {
			return nil, err
		}
		actions = []*Action{&action}
	}
	for _, action := range actions {
		if action.Metadata == nil {
			action.Metadata = map[string]any{}
		}
	}
	return actions, nil
}

func ensureValidationMetadata(action *Action) error {
	if action.Validation == nil {
		return fmt.Errorf("action %q missing validation section", action.Description)
	}
	if action.Validation.ValidationProfile == "" {
		if profile, ok := action.Metadata[metadataValidationProfileKey].(string); ok && profile != "" {
			action.Validation.ValidationProfile = profile
		}
	}
	if action.Validation.ValidationProfile == "" {
		return fmt.Errorf("action %q missing validation profile metadata", action.Description)
	}
	return nil
}

// InjectValidationProfile enforces a local validation profile before execution
func InjectValidationProfile(actions []*Action, profileName string, policy *ActionExecutionPolicy) {
	if policy == nil {
		return
	}
	for _, action := range actions {
		if action == nil {
			continue
		}
		if action.Validation == nil {
			action.Validation = &ActionValidation{}
		}
		action.Validation.ValidationProfile = profileName
		action.Validation.AllowedCommands = append([]string{}, policy.AllowedCommands...)
		action.Validation.MaxArguments = policy.MaxArguments
		action.Validation.MaxCommandLength = policy.MaxCommandLength
	}
}
