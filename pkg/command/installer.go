// pkg/command/installer.go
package command

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CommandInstaller manages custom command installation
type CommandInstaller struct {
	rc        *eos_io.RuntimeContext
	logger    otelzap.LoggerWithCtx
	targetDir string
}

// CommandDefinition defines a custom command
type CommandDefinition struct {
	Name        string
	Content     string
	Description string
	TargetDir   string
	Executable  bool
}

// CommandInfo contains information about a custom command
type CommandInfo struct {
	Name           string
	Path           string
	Description    string
	CreatedAt      time.Time
	IsEosGenerated bool
}

// NewCommandInstaller creates a new command installer
func NewCommandInstaller(rc *eos_io.RuntimeContext) *CommandInstaller {
	return &CommandInstaller{
		rc:        rc,
		targetDir: "/usr/local/bin",
		logger:    otelzap.Ctx(rc.Ctx),
	}
}

// InstallInteractive installs a command interactively
func (ci *CommandInstaller) InstallInteractive() error {
	ctx, span := telemetry.Start(ci.rc.Ctx, "command.InstallInteractive")
	defer span.End()

	ci.logger.Info("Starting interactive command installation")

	// Get command name
	name, err := ci.promptForName()
	if err != nil {
		return fmt.Errorf("failed to get command name: %w", err)
	}

	// Check if command already exists
	if ci.CommandExists(name) {
		return eos_err.NewExpectedError(ctx,
			fmt.Errorf("command '%s' already exists", name))
	}

	// Get command content
	content, err := ci.promptForContent()
	if err != nil {
		return fmt.Errorf("failed to get command content: %w", err)
	}

	// Get optional description
	description, _ := ci.promptForDescription()

	// Create command definition
	def := &CommandDefinition{
		Name:        name,
		Content:     content,
		Description: description,
		TargetDir:   ci.targetDir,
		Executable:  true,
	}

	// Install the command
	return ci.Install(def)
}

// promptForName prompts for and validates command name
func (ci *CommandInstaller) promptForName() (string, error) {
	ci.logger.Info("terminal prompt: Enter the name you want to use to call the command")
	name, err := eos_io.PromptInput(ci.rc.Ctx, "Enter the name you want to use to call the command")
	if err != nil {
		return "", err
	}

	name = strings.TrimSpace(name)
	if err := ci.validateCommandName(name); err != nil {
		return "", err
	}

	return name, nil
}

// promptForContent prompts for command content
func (ci *CommandInstaller) promptForContent() (string, error) {
	ci.logger.Info("terminal prompt: Enter the command or script you want to execute")
	content, err := eos_io.PromptInput(ci.rc.Ctx, "Enter the command or script you want to execute")
	if err != nil {
		return "", err
	}

	content = strings.TrimSpace(content)
	if content == "" {
		return "", fmt.Errorf("command content cannot be empty")
	}

	return content, nil
}

// promptForDescription prompts for optional description
func (ci *CommandInstaller) promptForDescription() (string, error) {
	ci.logger.Info("terminal prompt: Enter a description for this command (optional)")
	description, err := eos_io.PromptInput(ci.rc.Ctx, "Enter a description for this command (optional)")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(description), nil
}

// Install installs a command based on definition
func (ci *CommandInstaller) Install(def *CommandDefinition) error {
	ctx, span := telemetry.Start(ci.rc.Ctx, "command.Install")
	defer span.End()

	ci.logger.Info("Installing command",
		zap.String("name", def.Name),
		zap.String("target_dir", def.TargetDir))

	// Validate command definition
	if err := ci.ValidateDefinition(def); err != nil {
		return err
	}

	// Generate script content
	scriptContent := ci.GenerateScript(def)

	// Write script file
	scriptPath := filepath.Join(def.TargetDir, def.Name)

	// Use sudo if needed for system directories
	if err := ci.writeScriptFile(ctx, scriptPath, scriptContent, def.Executable); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}

	ci.logger.Info("Command installed successfully",
		zap.String("name", def.Name),
		zap.String("path", scriptPath),
		zap.String("target_dir", def.TargetDir),
		zap.String("content", def.Content))

	return nil
}

// ValidateDefinition validates a command definition
func (ci *CommandInstaller) ValidateDefinition(def *CommandDefinition) error {
	if def.Name == "" {
		return fmt.Errorf("command name is required")
	}

	if def.Content == "" {
		return fmt.Errorf("command content is required")
	}

	// Use the same validation as validateCommandName
	if err := ci.validateCommandName(def.Name); err != nil {
		return err
	}

	return nil
}

// GenerateScript generates the script content
func (ci *CommandInstaller) GenerateScript(def *CommandDefinition) string {
	var script strings.Builder

	script.WriteString("#!/bin/bash\n")

	if def.Description != "" {
		script.WriteString(fmt.Sprintf("# %s\n", def.Description))
	}

	script.WriteString("# Generated by Eos command installer\n")
	script.WriteString(fmt.Sprintf("# Command: %s\n", def.Name))
	script.WriteString(fmt.Sprintf("# Created: %s\n\n", time.Now().Format(time.RFC3339)))

	script.WriteString(def.Content)
	script.WriteString("\n")

	return script.String()
}

// writeScriptFile writes the script file with appropriate permissions
func (ci *CommandInstaller) writeScriptFile(ctx context.Context, path, content string, executable bool) error {
	// For system directories, we need elevated permissions
	if strings.HasPrefix(path, "/usr") || strings.HasPrefix(path, "/opt") {
		return ci.writeWithSudo(ctx, path, content, executable)
	}

	// Regular write for user directories
	perm := os.FileMode(0644)
	if executable {
		perm = 0755
	}

	return os.WriteFile(path, []byte(content), perm)
}

// writeWithSudo writes file with sudo permissions
func (ci *CommandInstaller) writeWithSudo(ctx context.Context, path, content string, executable bool) error {
	// Create temporary file
	tmpFile, err := os.CreateTemp("", "eos-cmd-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write content to temp file
	if _, err := tmpFile.WriteString(content); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	tmpFile.Close()

	// Copy with sudo
	copyCmd := exec.CommandContext(ctx, "sudo", "cp", tmpFile.Name(), path)
	if err := copyCmd.Run(); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Set permissions
	if executable {
		chmodCmd := exec.CommandContext(ctx, "sudo", "chmod", "755", path)
		if err := chmodCmd.Run(); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	return nil
}

// CommandExists checks if a command already exists
func (ci *CommandInstaller) CommandExists(name string) bool {
	path := filepath.Join(ci.targetDir, name)
	_, err := os.Stat(path)
	return err == nil
}

// ListCustomCommands lists all custom commands
func (ci *CommandInstaller) ListCustomCommands() ([]CommandInfo, error) {
	_, span := telemetry.Start(ci.rc.Ctx, "command.ListCustomCommands")
	defer span.End()

	var commands []CommandInfo

	entries, err := os.ReadDir(ci.targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(ci.targetDir, entry.Name())

		// Get file info
		info, err := entry.Info()
		if err != nil {
			continue
		}

		cmdInfo := CommandInfo{
			Name:      entry.Name(),
			Path:      path,
			CreatedAt: info.ModTime(),
		}

		// Check if it's an Eos-generated command
		cmdInfo.IsEosGenerated = ci.isEosCommand(path)

		// Try to extract description
		if desc, err := ci.extractDescription(path); err == nil {
			cmdInfo.Description = desc
		}

		commands = append(commands, cmdInfo)
	}

	return commands, nil
}

// isEosCommand checks if a file is an Eos-generated command
func (ci *CommandInstaller) isEosCommand(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() {
		if err := file.Close(); err != nil {
			ci.logger.Warn("Failed to close file", zap.Error(err), zap.String("path", path))
		}
	}()

	// Read first few lines
	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() && lineCount < 10 {
		line := scanner.Text()
		if strings.Contains(line, "Generated by Eos command installer") {
			return true
		}
		lineCount++
	}

	return false
}

// extractDescription extracts description from script comments
func (ci *CommandInstaller) extractDescription(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			ci.logger.Warn("Failed to close file", zap.Error(err), zap.String("path", path))
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#!/") {
			// Look for description comments
			if strings.Contains(line, "Description:") ||
				(!strings.Contains(line, "Generated by") &&
					!strings.Contains(line, "Command:") &&
					!strings.Contains(line, "Created:")) {
				return strings.TrimPrefix(line, "#"), nil
			}
		}
	}

	return "", fmt.Errorf("no description found")
}

// ValidateCommandName validates a command name (public function for external use)
func ValidateCommandName(name string) error {
	if name == "" {
		return fmt.Errorf("command name cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(name, "\x00") {
		return fmt.Errorf("command name cannot contain null bytes")
	}

	// Check for control characters (newlines, carriage returns, tabs)
	if strings.ContainsAny(name, "\n\r\t") {
		return fmt.Errorf("command name cannot contain control characters (newlines, tabs)")
	}

	// Check for shell metacharacters in name
	if strings.ContainsAny(name, ";&|<>(){}[]\\\"'*?~") {
		return fmt.Errorf("command name contains invalid characters")
	}

	// Check for spaces
	if strings.Contains(name, " ") {
		return fmt.Errorf("command name cannot contain spaces")
	}

	// Check for excessively long names (prevent DoS)
	if len(name) > 255 {
		return fmt.Errorf("command name too long (max 255 characters)")
	}

	return nil
}

// validateCommandName validates a command name
func (ci *CommandInstaller) validateCommandName(name string) error {
	return ValidateCommandName(name)
}

// RemoveCommand removes a custom command
func (ci *CommandInstaller) RemoveCommand(name string) error {
	ctx, span := telemetry.Start(ci.rc.Ctx, "command.RemoveCommand")
	defer span.End()

	path := filepath.Join(ci.targetDir, name)

	// Check if command exists
	if !ci.CommandExists(name) {
		return eos_err.NewExpectedError(ctx,
			fmt.Errorf("command '%s' does not exist", name))
	}

	// Check if it's an Eos command before removing
	if !ci.isEosCommand(path) {
		ci.logger.Warn("Attempting to remove non-Eos command",
			zap.String("command", name),
			zap.String("note", "This may not be an Eos-generated command"))
	}

	// Remove with sudo if needed
	if strings.HasPrefix(ci.targetDir, "/usr") || strings.HasPrefix(ci.targetDir, "/opt") {
		removeCmd := exec.CommandContext(ctx, "sudo", "rm", path)
		if err := removeCmd.Run(); err != nil {
			return fmt.Errorf("failed to remove command: %w", err)
		}
	} else {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove command: %w", err)
		}
	}

	ci.logger.Info("Command removed successfully",
		zap.String("command", name),
		zap.String("path", path))

	return nil
}
