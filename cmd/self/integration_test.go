// cmd/self/integration_test.go - Integration tests for CLI commands using AIE pattern helpers
package self

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// MockSaltClient for testing Salt integration
type MockSaltClient struct {
	mock.Mock
}

func (m *MockSaltClient) StateApply(ctx context.Context, target string, state string, pillar map[string]interface{}) error {
	args := m.Called(ctx, target, state, pillar)
	return args.Error(0)
}

func (m *MockSaltClient) TestPing(ctx context.Context, target string) (bool, error) {
	args := m.Called(ctx, target)
	return args.Bool(0), args.Error(1)
}

func (m *MockSaltClient) GrainGet(ctx context.Context, target string, grain string) (map[string]interface{}, error) {
	args := m.Called(ctx, target, grain)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockSaltClient) CmdRun(ctx context.Context, target string, command string) (string, error) {
	args := m.Called(ctx, target, command)
	return args.String(0), args.Error(1)
}

func (m *MockSaltClient) CheckMinion(ctx context.Context, minion string) (bool, error) {
	args := m.Called(ctx, minion)
	return args.Bool(0), args.Error(1)
}

// MockVaultClient for testing Vault integration
type MockVaultClient struct {
	mock.Mock
}

func (m *MockVaultClient) Write(path string, data map[string]interface{}) error {
	args := m.Called(path, data)
	return args.Error(0)
}

func (m *MockVaultClient) Read(path string) (map[string]interface{}, error) {
	args := m.Called(path)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockVaultClient) Delete(path string) error {
	args := m.Called(path)
	return args.Error(0)
}

// BackupResult represents the result of a backup operation
type BackupResult struct {
	SnapshotID string
	Files      []string
	Duration   time.Duration
}

// MockBackupClient for testing backup operations
type MockBackupClient struct {
	mock.Mock
}

func (m *MockBackupClient) CreateRepository() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockBackupClient) Backup(paths []string, tags []string) (*BackupResult, error) {
	args := m.Called(paths, tags)
	return args.Get(0).(*BackupResult), args.Error(1)
}

func (m *MockBackupClient) CheckRepository() error {
	args := m.Called()
	return args.Error(0)
}

// Test helper to create runtime context for testing
func createTestRuntimeContext(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	return &eos_io.RuntimeContext{
		Ctx:        ctx,
		Log:        logger,
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    "test",
		Attributes: make(map[string]string),
	}
}

// Test backup command integration with AIE pattern
func TestBackupRunCommandIntegration(t *testing.T) {
	tests := []struct {
		name           string
		profileName    string
		mockSetup      func(*MockBackupClient)
		expectedError  bool
		expectedResult string
	}{
		{
			name:        "successful backup execution",
			profileName: "test-profile",
			mockSetup: func(mc *MockBackupClient) {
				mc.On("CheckRepository").Return(nil)
				mc.On("Backup",
					[]string{"/test/path"},
					[]string{"manual", "test"}).Return(&BackupResult{
					SnapshotID: "snap123",
					Files:      []string{"/test/path/file1.txt"},
					Duration:   time.Minute,
				}, nil)
			},
			expectedError: false,
		},
		{
			name:        "backup fails during execution",
			profileName: "fail-profile",
			mockSetup: func(mc *MockBackupClient) {
				mc.On("CheckRepository").Return(nil)
				mc.On("Backup", mock.Anything, mock.Anything).
					Return((*BackupResult)(nil), fmt.Errorf("backup failed"))
			},
			expectedError: true,
		},
		{
			name:        "repository check fails",
			profileName: "repo-fail",
			mockSetup: func(mc *MockBackupClient) {
				mc.On("CheckRepository").Return(fmt.Errorf("repository not accessible"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := createTestRuntimeContext(t)

			// Create mock backup client
			mockClient := &MockBackupClient{}
			tt.mockSetup(mockClient)

			// Create temporary config for testing
			tmpDir := t.TempDir()
			_ = filepath.Join(tmpDir, "backup.yaml")

			testConfig := &backup.Config{
				DefaultRepository: "test-repo",
				Repositories: map[string]backup.Repository{
					"test-repo": {
						Name:    "test-repo",
						Backend: "local",
						URL:     tmpDir,
					},
				},
				Profiles: map[string]backup.Profile{
					tt.profileName: {
						Paths:      []string{"/test/path"},
						Tags:       []string{"manual", "test"},
						Repository: "test-repo",
					},
				},
			}

			// Mock the backup client creation and operation
			backupOp := &TestBackupOperation{
				Client:      mockClient,
				ProfileName: tt.profileName,
				Profile:     testConfig.Profiles[tt.profileName],
				RepoName:    "test-repo",
				DryRun:      false,
				Logger:      otelzap.Ctx(rc.Ctx),
			}

			// Test the AIE pattern execution
			executor := patterns.NewExecutor(otelzap.Ctx(rc.Ctx))
			err := executor.Execute(rc.Ctx, backupOp, "test_backup")

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify all mock expectations
			mockClient.AssertExpectations(t)
		})
	}
}

// TestBackupOperation implements AIE pattern for testing
type TestBackupOperation struct {
	Client      *MockBackupClient
	ProfileName string
	Profile     backup.Profile
	RepoName    string
	DryRun      bool
	Logger      otelzap.LoggerWithCtx
}

func (b *TestBackupOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	b.Logger.Info("Assessing backup readiness",
		zap.String("profile", b.ProfileName))

	// Check repository accessibility
	if err := b.Client.CheckRepository(); err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "repository not accessible",
		}, err
	}

	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"repository_accessible": true,
			"paths_readable":        true,
		},
	}, nil
}

func (b *TestBackupOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	b.Logger.Info("Executing backup",
		zap.String("profile", b.ProfileName),
		zap.Bool("dry_run", b.DryRun))

	if b.DryRun {
		return &patterns.InterventionResult{
			Success: true,
			Message: "dry run completed",
		}, nil
	}

	result, err := b.Client.Backup(b.Profile.Paths, b.Profile.Tags)
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("backup failed: %v", err),
		}, err
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: fmt.Sprintf("backup completed: %s", result.SnapshotID),
		Changes: []patterns.Change{
			{
				Type:        "backup_created",
				Description: fmt.Sprintf("Created backup snapshot %s", result.SnapshotID),
				After:       result.SnapshotID,
			},
		},
	}, nil
}

func (b *TestBackupOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	return &patterns.EvaluationResult{
		Success: intervention.Success,
		Message: "backup operation validated",
		Validations: map[string]patterns.ValidationResult{
			"backup_completed": {
				Passed:  intervention.Success,
				Message: "backup execution completed",
			},
		},
	}, nil
}

// Test user creation command integration
func TestUserCreationCommandIntegration(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		groups        []string
		mockSetup     func(*MockSaltClient, *MockVaultClient)
		expectedError bool
	}{
		{
			name:     "successful user creation",
			username: "testuser",
			groups:   []string{"sudo", "users"},
			mockSetup: func(salt *MockSaltClient, vault *MockVaultClient) {
				// UserExistenceCheck assessment phase
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()

				// UserExistenceCheck intervention phase
				salt.On("CmdRun", mock.Anything, "*", "id testuser").
					Return("id: testuser: no such user", fmt.Errorf("user not found")).Once()

				// UserCreationOperation assessment phase
				// Second ping test for main operation
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()
				// User existence check again during main assessment
				salt.On("CmdRun", mock.Anything, "*", "id testuser").
					Return("id: testuser: no such user", fmt.Errorf("user not found")).Once()

				// Group checks during assessment
				salt.On("CmdRun", mock.Anything, "*", "getent group sudo").
					Return("sudo:x:27:", nil)
				salt.On("CmdRun", mock.Anything, "*", "getent group users").
					Return("users:x:100:", nil)
				salt.On("CmdRun", mock.Anything, "*", "test -f /bin/bash && echo exists").
					Return("exists", nil)

				// Intervention phase
				salt.On("StateApply", mock.Anything, "*", "users.create", mock.Anything).
					Return(nil)
				vault.On("Write", "secret/users/testuser", mock.Anything).
					Return(nil)

				// Evaluation phase
				salt.On("CmdRun", mock.Anything, "*", "id testuser").
					Return("uid=1001(testuser) gid=1001(testuser) groups=1001(testuser),27(sudo),100(users)", nil)
				salt.On("CmdRun", mock.Anything, "*", "groups testuser | grep -q sudo && echo yes || echo no").
					Return("yes", nil)
				salt.On("CmdRun", mock.Anything, "*", "groups testuser | grep -q users && echo yes || echo no").
					Return("yes", nil)
			},
			expectedError: false,
		},
		{
			name:     "user already exists",
			username: "existing",
			groups:   []string{"users"},
			mockSetup: func(salt *MockSaltClient, vault *MockVaultClient) {
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()
				// User existence check in assessment
				salt.On("CmdRun", mock.Anything, "*", "id existing").
					Return("uid=1001(existing) gid=1001(existing)", nil)
				// This will cause assessment to fail since user exists
			},
			expectedError: true,
		},
		{
			name:     "group does not exist",
			username: "testuser2",
			groups:   []string{"nonexistent"},
			mockSetup: func(salt *MockSaltClient, vault *MockVaultClient) {
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()
				salt.On("CmdRun", mock.Anything, "*", "id testuser2").
					Return("id: testuser2: no such user", fmt.Errorf("user not found"))
				salt.On("CmdRun", mock.Anything, "*", "getent group nonexistent").
					Return("", fmt.Errorf("group not found"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := createTestRuntimeContext(t)

			mockSalt := &MockSaltClient{}
			mockVault := &MockVaultClient{}
			tt.mockSetup(mockSalt, mockVault)

			// Create user operation
			userOp := &users.UserCreationOperation{
				Username:    tt.username,
				Password:    "testpass123",
				Groups:      tt.groups,
				Shell:       "/bin/bash",
				HomeDir:     fmt.Sprintf("/home/%s", tt.username),
				Target:      "*",
				SaltClient:  mockSalt,
				VaultClient: mockVault,
				Logger:      otelzap.Ctx(rc.Ctx),
			}

			// Execute AIE pattern
			executor := patterns.NewExecutor(otelzap.Ctx(rc.Ctx))
			err := executor.Execute(rc.Ctx, userOp, "user_creation")

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			mockSalt.AssertExpectations(t)
			mockVault.AssertExpectations(t)
		})
	}
}

// Test system service operation integration
func TestSystemServiceCommandIntegration(t *testing.T) {
	tests := []struct {
		name          string
		serviceName   string
		action        string
		mockSetup     func(*MockSaltClient)
		expectedError bool
	}{
		{
			name:        "successful service start",
			serviceName: "nginx",
			action:      "start",
			mockSetup: func(salt *MockSaltClient) {
				// Multiple connectivity checks throughout the process
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe().Maybe()
				salt.On("CmdRun", mock.Anything, "*", "systemctl --version").
					Return("systemd 247", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl cat nginx >/dev/null 2>&1 && echo exists || echo notfound").
					Return("exists", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl is-active nginx 2>/dev/null || echo inactive").
					Return("inactive", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl is-enabled nginx 2>/dev/null || echo disabled").
					Return("enabled", nil)

				salt.On("CmdRun", mock.Anything, "*", "systemctl start nginx").
					Return("", nil)

				// Evaluation phase
				salt.On("CmdRun", mock.Anything, "*", "systemctl is-active nginx").
					Return("active", nil)
			},
			expectedError: false,
		},
		{
			name:        "service does not exist",
			serviceName: "nonexistent",
			action:      "start",
			mockSetup: func(salt *MockSaltClient) {
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()
				salt.On("CmdRun", mock.Anything, "*", "systemctl --version").
					Return("systemd 247", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl cat nonexistent >/dev/null 2>&1 && echo exists || echo notfound").
					Return("notfound", nil)
			},
			expectedError: true,
		},
		{
			name:        "successful service stop",
			serviceName: "apache2",
			action:      "stop",
			mockSetup: func(salt *MockSaltClient) {
				// Assessment
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()
				salt.On("CmdRun", mock.Anything, "*", "systemctl --version").
					Return("systemd 247", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl cat apache2 >/dev/null 2>&1 && echo exists || echo notfound").
					Return("exists", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl is-active apache2 2>/dev/null || echo inactive").
					Return("active", nil)
				salt.On("CmdRun", mock.Anything, "*", "systemctl is-enabled apache2 2>/dev/null || echo disabled").
					Return("enabled", nil)

				salt.On("CmdRun", mock.Anything, "*", "systemctl stop apache2").
					Return("", nil)

				// Evaluation
				salt.On("CmdRun", mock.Anything, "*", "systemctl is-active apache2").
					Return("inactive", nil)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := createTestRuntimeContext(t)

			mockSalt := &MockSaltClient{}
			tt.mockSetup(mockSalt)

			// Create service operation
			serviceOp := &system.ServiceOperation{
				ServiceName: tt.serviceName,
				Action:      tt.action,
				Target:      "*",
				SaltClient:  mockSalt,
				Logger:      otelzap.Ctx(rc.Ctx),
			}

			// Execute AIE pattern
			executor := patterns.NewExecutor(otelzap.Ctx(rc.Ctx))
			err := executor.Execute(rc.Ctx, serviceOp, "service_management")

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			mockSalt.AssertExpectations(t)
		})
	}
}

// Test CLI command argument parsing and validation
func TestCommandArgumentValidation(t *testing.T) {
	tests := []struct {
		name          string
		command       *cobra.Command
		args          []string
		flags         map[string]string
		expectedError bool
		errorContains string
	}{
		{
			name:          "backup run with valid profile",
			command:       createMockBackupRunCommand(),
			args:          []string{"system"},
			flags:         map[string]string{},
			expectedError: false,
		},
		{
			name:          "backup run without profile",
			command:       createMockBackupRunCommand(),
			args:          []string{},
			expectedError: true,
			errorContains: "requires exactly 1 arg",
		},
		{
			name:          "user creation with username",
			command:       createMockUserCreateCommand(),
			args:          []string{"testuser"},
			flags:         map[string]string{},
			expectedError: false,
		},
		{
			name:          "user creation without username",
			command:       createMockUserCreateCommand(),
			args:          []string{},
			expectedError: true,
			errorContains: "username must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up command flags
			for key, value := range tt.flags {
				if err := tt.command.Flags().Set(key, value); err != nil {
					t.Fatalf("Failed to set flag %s=%s: %v", key, value, err)
				}
			}

			// Test argument validation
			err := tt.command.Args(tt.command, tt.args)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions to create mock commands for testing
func createMockBackupRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "run <profile>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.Flags().StringSlice("tags", nil, "Additional tags")
	cmd.Flags().Bool("dry-run", false, "Dry run mode")
	return cmd
}

func createMockUserCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "user-account [username]",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("username must be specified")
			}
			return nil
		},
	}
	cmd.Flags().String("target", "*", "Salt target")
	cmd.Flags().StringSlice("groups", []string{}, "User groups")
	cmd.Flags().Bool("sudo", false, "Grant sudo access")
	return cmd
}

// Test error handling and recovery
func TestErrorHandlingIntegration(t *testing.T) {
	tests := []struct {
		name          string
		operation     string
		mockSetup     func(*MockSaltClient)
		expectedPhase string // Which phase should fail
		expectedError bool
	}{
		{
			name:      "assessment failure - connectivity",
			operation: "user_creation",
			mockSetup: func(salt *MockSaltClient) {
				salt.On("TestPing", mock.Anything, "*").Return(false, fmt.Errorf("connection failed"))
			},
			expectedPhase: "assessment",
			expectedError: true,
		},
		{
			name:      "intervention failure - command error",
			operation: "service_control",
			mockSetup: func(salt *MockSaltClient) {
				salt.On("TestPing", mock.Anything, "*").Return(true, nil).Maybe()
				salt.On("CmdRun", mock.Anything, "*", mock.Anything).Return("enabled", nil)
				salt.On("StateApply", mock.Anything, "*", mock.Anything, mock.Anything).
					Return(fmt.Errorf("state apply failed"))
			},
			expectedPhase: "intervention",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := createTestRuntimeContext(t)

			mockSalt := &MockSaltClient{}
			tt.mockSetup(mockSalt)

			// Create a test operation based on type
			var operation patterns.AIEOperation
			switch tt.operation {
			case "user_creation":
				operation = &users.UserCreationOperation{
					Username:   "testuser",
					Password:   "testpass",
					Groups:     []string{"users"},
					Shell:      "/bin/bash",
					HomeDir:    "/home/testuser",
					Target:     "*",
					SaltClient: mockSalt,
					Logger:     otelzap.Ctx(rc.Ctx),
				}
			case "service_control":
				operation = &system.ServiceOperation{
					ServiceName: "test-service",
					Action:      "start",
					Target:      "*",
					SaltClient:  mockSalt,
					Logger:      otelzap.Ctx(rc.Ctx),
				}
			}

			// Execute and verify error handling
			executor := patterns.NewExecutor(otelzap.Ctx(rc.Ctx))
			err := executor.Execute(rc.Ctx, operation, "error_test")

			if tt.expectedError {
				assert.Error(t, err)
				t.Logf("Expected error in %s phase: %v", tt.expectedPhase, err)
			} else {
				assert.NoError(t, err)
			}

			mockSalt.AssertExpectations(t)
		})
	}
}

// Benchmark command execution performance
func BenchmarkCommandExecution(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx:        context.Background(),
		Log:        zaptest.NewLogger(b),
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    "benchmark",
		Attributes: make(map[string]string),
	}

	mockSalt := &MockSaltClient{}
	mockSalt.On("TestPing", mock.Anything, "*").Return(true, nil)
	mockSalt.On("CmdRun", mock.Anything, "*", mock.Anything).Return("active", nil)

	operation := &system.ServiceOperation{
		ServiceName: "test-service",
		Action:      "status",
		Target:      "*",
		SaltClient:  mockSalt,
		Logger:      otelzap.Ctx(rc.Ctx),
	}

	executor := patterns.NewExecutor(otelzap.Ctx(rc.Ctx))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = executor.Execute(rc.Ctx, operation, "benchmark")
	}
}
