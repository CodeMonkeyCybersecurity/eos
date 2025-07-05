package cron_management

import (
	"bufio"
	"crypto/md5"
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

// CronManager handles crontab operations
type CronManager struct {
	config *CronConfig
}

// NewCronManager creates a new cron manager
func NewCronManager(config *CronConfig) *CronManager {
	if config == nil {
		config = DefaultCronConfig()
	}
	
	return &CronManager{
		config: config,
	}
}

// ListJobs lists all cron jobs for the current or specified user
func (cm *CronManager) ListJobs(rc *eos_io.RuntimeContext) (*CronListResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing cron jobs", zap.String("user", cm.config.User))

	result := &CronListResult{
		Jobs:      make([]CronJob, 0),
		User:      cm.config.User,
		Timestamp: time.Now(),
		HasCrontab: false,
	}

	// Build crontab command
	var cmd *exec.Cmd
	if cm.config.User != "" {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-u", cm.config.User, "-l")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-l")
		result.User = "current"
	}

	output, err := cmd.Output()
	if err != nil {
		// Exit code 1 usually means no crontab exists
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			logger.Info("No crontab found for user")
			return result, nil
		}
		logger.Error("Failed to list cron jobs", zap.Error(err))
		return nil, fmt.Errorf("failed to list cron jobs: %w", err)
	}

	result.HasCrontab = true
	jobs, err := cm.parseCrontab(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse crontab: %w", err)
	}

	result.Jobs = jobs
	result.Count = len(jobs)

	logger.Info("Found cron jobs", zap.Int("count", len(jobs)))
	return result, nil
}

// AddJob adds a new cron job
func (cm *CronManager) AddJob(rc *eos_io.RuntimeContext, job *CronJob) (*CronOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Adding cron job", 
		zap.String("schedule", job.Schedule),
		zap.String("command", job.Command),
		zap.Bool("dry_run", cm.config.DryRun))

	operation := &CronOperation{
		Operation: "add",
		Job:       job,
		Timestamp: time.Now(),
		DryRun:    cm.config.DryRun,
		User:      cm.config.User,
	}

	// Validate cron expression
	if err := cm.validateCronExpression(job.Schedule); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Invalid cron expression: %v", err)
		return operation, fmt.Errorf("invalid cron expression: %w", err)
	}

	if cm.config.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would add cron job: %s %s", job.Schedule, job.Command)
		logger.Info("Dry run: would add cron job")
		return operation, nil
	}

	// Create backup if enabled
	if cm.config.CreateBackup {
		if err := cm.createBackup(rc); err != nil {
			logger.Warn("Failed to create backup", zap.Error(err))
		}
	}

	// Get current crontab
	currentJobs, err := cm.getCurrentCrontab(rc)
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to get current crontab: %v", err)
		return operation, err
	}

	// Generate job ID
	job.ID = cm.generateJobID(job)
	job.User = cm.config.User
	job.Enabled = true

	// Add the new job
	newCrontab := cm.buildCrontabContent(append(currentJobs, *job))

	// Write the new crontab
	if err := cm.writeCrontab(rc, newCrontab); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to write crontab: %v", err)
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully added cron job: %s", job.ID)

	logger.Info("Cron job added successfully", zap.String("job_id", job.ID))
	return operation, nil
}

// RemoveJob removes a cron job by ID or exact match
func (cm *CronManager) RemoveJob(rc *eos_io.RuntimeContext, jobIdentifier string) (*CronOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing cron job", 
		zap.String("identifier", jobIdentifier),
		zap.Bool("dry_run", cm.config.DryRun))

	operation := &CronOperation{
		Operation: "remove",
		Timestamp: time.Now(),
		DryRun:    cm.config.DryRun,
		User:      cm.config.User,
	}

	if cm.config.DryRun {
		operation.Success = true
		operation.Message = fmt.Sprintf("Would remove cron job: %s", jobIdentifier)
		logger.Info("Dry run: would remove cron job")
		return operation, nil
	}

	// Create backup if enabled
	if cm.config.CreateBackup {
		if err := cm.createBackup(rc); err != nil {
			logger.Warn("Failed to create backup", zap.Error(err))
		}
	}

	// Get current crontab
	currentJobs, err := cm.getCurrentCrontab(rc)
	if err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to get current crontab: %v", err)
		return operation, err
	}

	// Find and remove the job
	var newJobs []CronJob
	found := false
	for _, job := range currentJobs {
		// Match by ID or exact line match
		jobLine := fmt.Sprintf("%s %s", job.Schedule, job.Command)
		if job.ID == jobIdentifier || jobLine == jobIdentifier {
			found = true
			operation.Job = &job
			logger.Info("Found job to remove", zap.String("job_id", job.ID))
			continue
		}
		newJobs = append(newJobs, job)
	}

	if !found {
		operation.Success = false
		operation.Message = fmt.Sprintf("Cron job not found: %s", jobIdentifier)
		return operation, fmt.Errorf("cron job not found: %s", jobIdentifier)
	}

	// Write the updated crontab
	newCrontab := cm.buildCrontabContent(newJobs)
	if err := cm.writeCrontab(rc, newCrontab); err != nil {
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to write crontab: %v", err)
		return operation, err
	}

	operation.Success = true
	operation.Message = fmt.Sprintf("Successfully removed cron job: %s", jobIdentifier)

	logger.Info("Cron job removed successfully", zap.String("identifier", jobIdentifier))
	return operation, nil
}

// ClearAllJobs removes all cron jobs
func (cm *CronManager) ClearAllJobs(rc *eos_io.RuntimeContext) (*CronOperation, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Clearing all cron jobs", 
		zap.Bool("dry_run", cm.config.DryRun))

	operation := &CronOperation{
		Operation: "clear_all",
		Timestamp: time.Now(),
		DryRun:    cm.config.DryRun,
		User:      cm.config.User,
	}

	if cm.config.DryRun {
		operation.Success = true
		operation.Message = "Would clear all cron jobs"
		logger.Info("Dry run: would clear all cron jobs")
		return operation, nil
	}

	// Create backup if enabled
	if cm.config.CreateBackup {
		if err := cm.createBackup(rc); err != nil {
			logger.Warn("Failed to create backup", zap.Error(err))
		}
	}

	// Remove crontab
	var cmd *exec.Cmd
	if cm.config.User != "" {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-u", cm.config.User, "-r")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-r")
	}

	if err := cmd.Run(); err != nil {
		// Exit code 1 might mean no crontab exists
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			operation.Success = true
			operation.Message = "No crontab to clear"
			logger.Info("No crontab found to clear")
			return operation, nil
		}
		operation.Success = false
		operation.Message = fmt.Sprintf("Failed to clear crontab: %v", err)
		return operation, err
	}

	operation.Success = true
	operation.Message = "Successfully cleared all cron jobs"

	logger.Info("All cron jobs cleared successfully")
	return operation, nil
}

// ValidateExpression validates a cron expression
func (cm *CronManager) ValidateExpression(expression string) *CronValidationResult {
	result := &CronValidationResult{
		Expression: expression,
	}

	if err := cm.validateCronExpression(expression); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	result.Valid = true
	result.Description = cm.describeCronExpression(expression)
	
	// Generate next few runs (simplified - real implementation would use cron parser)
	// For now, just indicate it's valid
	return result
}

// Helper methods

func (cm *CronManager) getCurrentCrontab(rc *eos_io.RuntimeContext) ([]CronJob, error) {
	var cmd *exec.Cmd
	if cm.config.User != "" {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-u", cm.config.User, "-l")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-l")
	}

	output, err := cmd.Output()
	if err != nil {
		// Exit code 1 usually means no crontab exists
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return []CronJob{}, nil
		}
		return nil, err
	}

	return cm.parseCrontab(string(output))
}

func (cm *CronManager) parseCrontab(content string) ([]CronJob, error) {
	var jobs []CronJob
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse environment variables (VAR=value)
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue // Skip environment variables for now
		}

		// Parse cron job line
		job, err := cm.parseCronLine(line, lineNum)
		if err != nil {
			continue // Skip invalid lines
		}

		jobs = append(jobs, *job)
	}

	return jobs, nil
}

func (cm *CronManager) parseCronLine(line string, lineNum int) (*CronJob, error) {
	parts := strings.Fields(line)
	if len(parts) < 6 {
		return nil, fmt.Errorf("invalid cron line: %s", line)
	}

	job := &CronJob{
		Schedule: strings.Join(parts[:5], " "),
		Command:  strings.Join(parts[5:], " "),
		User:     cm.config.User,
		Enabled:  true,
	}

	job.ID = cm.generateJobID(job)
	return job, nil
}

func (cm *CronManager) buildCrontabContent(jobs []CronJob) string {
	var lines []string
	
	// Add header comment
	lines = append(lines, "# Crontab managed by EOS")
	lines = append(lines, fmt.Sprintf("# Generated on: %s", time.Now().Format("2006-01-02 15:04:05")))
	lines = append(lines, "")

	// Add jobs
	for _, job := range jobs {
		if job.Comment != "" {
			lines = append(lines, fmt.Sprintf("# %s", job.Comment))
		}
		lines = append(lines, fmt.Sprintf("%s %s", job.Schedule, job.Command))
	}

	return strings.Join(lines, "\n") + "\n"
}

func (cm *CronManager) writeCrontab(rc *eos_io.RuntimeContext, content string) error {
	var cmd *exec.Cmd
	if cm.config.User != "" {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-u", cm.config.User, "-")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-")
	}

	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}

func (cm *CronManager) generateJobID(job *CronJob) string {
	data := fmt.Sprintf("%s|%s", job.Schedule, job.Command)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)[:8]
}

func (cm *CronManager) validateCronExpression(expr string) error {
	// Basic validation for standard cron expressions
	parts := strings.Fields(expr)
	
	// Handle special expressions
	if strings.HasPrefix(expr, "@") {
		validSpecial := map[string]bool{
			"@reboot": true, "@yearly": true, "@annually": true,
			"@monthly": true, "@weekly": true, "@daily": true,
			"@midnight": true, "@hourly": true,
		}
		if !validSpecial[expr] {
			return fmt.Errorf("invalid special expression: %s", expr)
		}
		return nil
	}

	// Standard 5-field expression
	if len(parts) != 5 {
		return fmt.Errorf("cron expression must have 5 fields, got %d", len(parts))
	}

	// Basic field validation (simplified)
	for _, part := range parts {
		if part == "*" || strings.Contains(part, "/") || strings.Contains(part, "-") || strings.Contains(part, ",") {
			continue // Skip complex expressions for now
		}
		
		// Simple numeric validation
		if match, _ := regexp.MatchString(`^\d+$`, part); !match {
			continue // Skip for now
		}
	}

	return nil
}

func (cm *CronManager) describeCronExpression(expr string) string {
	// Simplified description generation
	if strings.HasPrefix(expr, "@") {
		descriptions := map[string]string{
			"@reboot":   "At system startup",
			"@yearly":   "Once a year (January 1st at midnight)",
			"@annually": "Once a year (January 1st at midnight)",
			"@monthly":  "Once a month (1st day at midnight)",
			"@weekly":   "Once a week (Sunday at midnight)",
			"@daily":    "Once a day (at midnight)",
			"@midnight": "Once a day (at midnight)",
			"@hourly":   "Once an hour (at the beginning of the hour)",
		}
		if desc, ok := descriptions[expr]; ok {
			return desc
		}
	}

	// For standard expressions, return a basic description
	return fmt.Sprintf("Custom schedule: %s", expr)
}

func (cm *CronManager) createBackup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create backup directory
	if err := os.MkdirAll(cm.config.BackupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	user := cm.config.User
	if user == "" {
		user = "current"
	}
	filename := fmt.Sprintf("crontab_%s_%s.bak", user, timestamp)
	backupPath := filepath.Join(cm.config.BackupDir, filename)

	// Get current crontab
	var cmd *exec.Cmd
	if cm.config.User != "" {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-u", cm.config.User, "-l")
	} else {
		cmd = exec.CommandContext(rc.Ctx, "crontab", "-l")
	}

	output, err := cmd.Output()
	if err != nil {
		// No crontab to backup
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			logger.Info("No crontab to backup")
			return nil
		}
		return err
	}

	// Write backup file
	if err := os.WriteFile(backupPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	logger.Info("Created crontab backup", zap.String("path", backupPath))
	return nil
}