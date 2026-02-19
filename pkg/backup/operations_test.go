package backup_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// MockClient implements backup.BackupClient for testing
type MockClient struct {
	BackupError      error
	BackupCalls      []string
	Snapshots        []backup.Snapshot
	ListSnapshotsErr error
}

func (m *MockClient) Backup(profileName string) error {
	m.BackupCalls = append(m.BackupCalls, profileName)
	return m.BackupError
}

func (m *MockClient) ListSnapshots() ([]backup.Snapshot, error) {
	if m.ListSnapshotsErr != nil {
		return nil, m.ListSnapshotsErr
	}
	return m.Snapshots, nil
}

func createTestLogger(t *testing.T) otelzap.LoggerWithCtx {
	logger := zaptest.NewLogger(t)
	return otelzap.New(logger).Ctx(context.Background())
}

func TestHookOperation_Assess_ValidCommand(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "echo 'test hook'",
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	result, err := hook.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["command_exists"])
	assert.True(t, result.Prerequisites["valid_syntax"])
}

func TestHookOperation_Assess_EmptyCommand(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "",
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	result, err := hook.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "empty hook command", result.Reason)
}

func TestHookOperation_Assess_AbsolutePathNotFound(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "/nonexistent/command arg1 arg2",
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	result, err := hook.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Contains(t, result.Reason, "hook command not found")
}

func TestHookOperation_Intervene_Success(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "/usr/bin/tar --version",
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := hook.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "hook executed successfully", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "hook_execution", result.Changes[0].Type)
}

func TestHookOperation_Intervene_CommandFails(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "/bin/false", // Not whitelisted
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := hook.Intervene(ctx, assessment)

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "not whitelisted")
}

func TestHookOperation_Evaluate_Success(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "echo test",
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "hook executed successfully",
	}

	result, err := hook.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "hook execution validated", result.Message)
	assert.True(t, result.Validations["execution"].Passed)
}

func TestHookOperation_Evaluate_Failure(t *testing.T) {
	logger := createTestLogger(t)
	hook := &backup.HookOperation{
		Hook:            "echo test",
		Logger:          logger,
		HooksEnabled:    true,
		AllowedCommands: map[string]struct{}{"/usr/bin/tar": {}},
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: false,
		Message: "hook failed",
	}

	result, err := hook.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "hook execution failed", result.Message)
	assert.False(t, result.Validations["execution"].Passed)
}

func TestRunHook_Integration(t *testing.T) {
	logger := createTestLogger(t)
	ctx := context.Background()

	// Test successful hook
	err := backup.RunHook(ctx, logger, "/usr/bin/tar --version")
	assert.NoError(t, err)

	// Test failing hook
	err = backup.RunHook(ctx, logger, "/bin/false")
	assert.Error(t, err)
}

func TestBackupOperation_Assess_ValidPaths(t *testing.T) {
	logger := createTestLogger(t)
	tempDir := t.TempDir()

	// Create test files
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	profile := backup.Profile{
		Paths: []string{tempDir, testFile},
		Tags:  []string{"test"},
	}

	client := &MockClient{}
	operation := &backup.BackupOperation{
		Client:      client,
		ProfileName: "test-profile",
		Profile:     profile,
		RepoName:    "test-repo",
		DryRun:      false,
		Logger:      logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["repository_exists"])
	assert.True(t, result.Prerequisites[fmt.Sprintf("path_%s", tempDir)])
	assert.True(t, result.Prerequisites[fmt.Sprintf("path_%s", testFile)])
	assert.True(t, result.Prerequisites["disk_space_available"])
}

func TestBackupOperation_Assess_InvalidPaths(t *testing.T) {
	logger := createTestLogger(t)

	profile := backup.Profile{
		Paths: []string{"/nonexistent/path"},
		Tags:  []string{"test"},
	}

	client := &MockClient{}
	operation := &backup.BackupOperation{
		Client:      client,
		ProfileName: "test-profile",
		Profile:     profile,
		RepoName:    "test-repo",
		DryRun:      false,
		Logger:      logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Contains(t, result.Reason, "backup path does not exist")
}

func TestBackupOperation_Intervene_DryRun(t *testing.T) {
	logger := createTestLogger(t)

	profile := backup.Profile{
		Paths: []string{"/tmp"},
		Tags:  []string{"test"},
	}

	client := &MockClient{}
	operation := &backup.BackupOperation{
		Client:      client,
		ProfileName: "test-profile",
		Profile:     profile,
		RepoName:    "test-repo",
		DryRun:      true,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "dry run completed", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "dry_run_path", result.Changes[0].Type)
	assert.Empty(t, client.BackupCalls) // No actual backup should be called
}

func TestBackupOperation_Intervene_ActualBackup(t *testing.T) {
	logger := createTestLogger(t)

	profile := backup.Profile{
		Paths: []string{"/tmp"},
		Tags:  []string{"test"},
	}

	client := &MockClient{}
	operation := &backup.BackupOperation{
		Client:      client,
		ProfileName: "test-profile",
		Profile:     profile,
		RepoName:    "test-repo",
		DryRun:      false,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "backup completed successfully", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "backup", result.Changes[0].Type)
	assert.Equal(t, []string{"test-profile"}, client.BackupCalls)
}

func TestBackupOperation_Intervene_BackupFails(t *testing.T) {
	logger := createTestLogger(t)

	profile := backup.Profile{
		Paths: []string{"/tmp"},
		Tags:  []string{"test"},
	}

	client := &MockClient{
		BackupError: errors.New("backup failed"),
	}
	operation := &backup.BackupOperation{
		Client:      client,
		ProfileName: "test-profile",
		Profile:     profile,
		RepoName:    "test-repo",
		DryRun:      false,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "backup failed")
	assert.Equal(t, []string{"test-profile"}, client.BackupCalls)
}

func TestBackupOperation_Evaluate_Success(t *testing.T) {
	logger := createTestLogger(t)
	client := &MockClient{
		Snapshots: []backup.Snapshot{
			{ID: "snap-1", Time: time.Now()},
		},
	}
	operation := &backup.BackupOperation{
		Client: client,
		Logger: logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "backup completed",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "backup validated successfully", result.Message)
	assert.True(t, result.Validations["backup_exists"].Passed)
	assert.True(t, result.Validations["backup_integrity"].Passed)
}

func TestBackupOperation_Evaluate_Failure(t *testing.T) {
	logger := createTestLogger(t)
	client := &MockClient{
		ListSnapshotsErr: errors.New("list snapshots failed"),
	}
	operation := &backup.BackupOperation{
		Client: client,
		Logger: logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "backup completed",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "backup validation failed", result.Message)
	assert.False(t, result.Validations["backup_exists"].Passed)
}

func TestNotificationOperation_Assess_ValidMethod(t *testing.T) {
	logger := createTestLogger(t)

	config := backup.Notifications{
		Method: "email",
		Target: "test@example.com",
	}

	operation := &backup.NotificationOperation{
		Config:  config,
		Subject: "Test Subject",
		Body:    "Test Body",
		Logger:  logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["method_valid"])
	assert.True(t, result.Prerequisites["target_set"])
}

func TestNotificationOperation_Assess_InvalidMethod(t *testing.T) {
	logger := createTestLogger(t)

	config := backup.Notifications{
		Method: "invalid_method",
		Target: "test@example.com",
	}

	operation := &backup.NotificationOperation{
		Config:  config,
		Subject: "Test Subject",
		Body:    "Test Body",
		Logger:  logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Contains(t, result.Reason, "invalid notification method")
}

func TestNotificationOperation_Assess_MissingTarget(t *testing.T) {
	logger := createTestLogger(t)

	config := backup.Notifications{
		Method: "email",
		Target: "",
	}

	operation := &backup.NotificationOperation{
		Config:  config,
		Subject: "Test Subject",
		Body:    "Test Body",
		Logger:  logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "notification target not configured", result.Reason)
}

func TestNotificationOperation_Intervene_Email(t *testing.T) {
	logger := createTestLogger(t)

	config := backup.Notifications{
		Method: "email",
		Target: "test@example.com",
	}

	operation := &backup.NotificationOperation{
		Config:  config,
		Subject: "Backup Complete",
		Body:    "Backup completed successfully",
		Logger:  logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "notification sent", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "notification", result.Changes[0].Type)
	assert.Contains(t, result.Changes[0].Description, "email")
}

func TestNotificationOperation_Intervene_Slack(t *testing.T) {
	logger := createTestLogger(t)

	config := backup.Notifications{
		Method: "slack",
		Target: "#backups",
	}

	operation := &backup.NotificationOperation{
		Config:  config,
		Subject: "Backup Complete",
		Body:    "Backup completed successfully",
		Logger:  logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Changes[0].Description, "slack")
}

func TestNotificationOperation_Intervene_Webhook(t *testing.T) {
	logger := createTestLogger(t)

	config := backup.Notifications{
		Method: "webhook",
		Target: "https://hooks.example.com/backup",
	}

	operation := &backup.NotificationOperation{
		Config:  config,
		Subject: "Backup Complete",
		Body:    "Backup completed successfully",
		Logger:  logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.Changes[0].Description, "webhook")
}

func TestNotificationOperation_Evaluate(t *testing.T) {
	logger := createTestLogger(t)
	operation := &backup.NotificationOperation{
		Logger: logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "notification sent",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "notification delivery assumed successful", result.Message)
	assert.True(t, result.Validations["delivery"].Passed)
	assert.Contains(t, result.Validations["delivery"].Message, "not verified")
}

func TestSendNotification_Integration(t *testing.T) {
	logger := createTestLogger(t)
	ctx := context.Background()

	tests := []struct {
		name        string
		config      backup.Notifications
		expectError bool
	}{
		{
			name: "valid email notification",
			config: backup.Notifications{
				Method: "email",
				Target: "test@example.com",
			},
			expectError: false,
		},
		{
			name: "valid slack notification",
			config: backup.Notifications{
				Method: "slack",
				Target: "#backups",
			},
			expectError: false,
		},
		{
			name: "empty configuration",
			config: backup.Notifications{
				Method: "",
				Target: "",
			},
			expectError: false, // Should skip silently
		},
		{
			name: "invalid method",
			config: backup.Notifications{
				Method: "invalid",
				Target: "test",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backup.SendNotification(ctx, logger, tt.config, "Test Subject", "Test Body")
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Benchmark tests
func BenchmarkHookOperation_Execute(b *testing.B) {
	logger := zaptest.NewLogger(b)
	otelLogger := otelzap.New(logger).Ctx(context.Background())
	ctx := context.Background()

	hook := &backup.HookOperation{
		Hook:   "echo 'benchmark test'",
		Logger: otelLogger,
	}

	executor := patterns.NewExecutor(otelLogger)

	b.ResetTimer()
	for b.Loop() {
		err := executor.Execute(ctx, hook, "benchmark_hook")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBackupOperation_Assess(b *testing.B) {
	logger := zaptest.NewLogger(b)
	otelLogger := otelzap.New(logger).Ctx(context.Background())
	tempDir := b.TempDir()

	profile := backup.Profile{
		Paths: []string{tempDir},
		Tags:  []string{"benchmark"},
	}

	client := &MockClient{}
	operation := &backup.BackupOperation{
		Client:      client,
		ProfileName: "benchmark-profile",
		Profile:     profile,
		RepoName:    "benchmark-repo",
		DryRun:      true,
		Logger:      otelLogger,
	}

	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, err := operation.Assess(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}
