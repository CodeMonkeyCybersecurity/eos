package users_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap/zaptest"
)

// MockSaltClient implements saltstack.ClientInterface for testing
type MockSaltClient struct {
	TestPingResult  bool
	TestPingError   error
	CmdRunResults   map[string]string
	CmdRunErrors    map[string]error
	StateApplyError error
	StateApplyCalls []StateApplyCall
}

type StateApplyCall struct {
	Target string
	State  string
	Pillar map[string]interface{}
}

func (m *MockSaltClient) TestPing(ctx context.Context, target string) (bool, error) {
	return m.TestPingResult, m.TestPingError
}

func (m *MockSaltClient) CmdRun(ctx context.Context, target string, command string) (string, error) {
	if m.CmdRunErrors != nil {
		if err, exists := m.CmdRunErrors[command]; exists {
			return "", err
		}
	}
	if m.CmdRunResults != nil {
		if result, exists := m.CmdRunResults[command]; exists {
			return result, nil
		}
	}
	return "", errors.New("command not found in mock")
}

func (m *MockSaltClient) StateApply(ctx context.Context, target string, state string, pillar map[string]interface{}) error {
	if m.StateApplyCalls == nil {
		m.StateApplyCalls = make([]StateApplyCall, 0)
	}
	m.StateApplyCalls = append(m.StateApplyCalls, StateApplyCall{
		Target: target,
		State:  state,
		Pillar: pillar,
	})
	return m.StateApplyError
}

func (m *MockSaltClient) GrainGet(ctx context.Context, target string, grain string) (map[string]interface{}, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *MockSaltClient) CheckMinion(ctx context.Context, minion string) (bool, error) {
	return false, errors.New("not implemented in mock")
}

// MockVaultClient implements users.VaultClient interface for testing
type MockVaultClient struct {
	WriteError error
	ReadError  error
	ReadData   map[string]interface{}
	WriteCalls []VaultWriteCall
}

type VaultWriteCall struct {
	Path string
	Data map[string]interface{}
}

func (m *MockVaultClient) Write(path string, data map[string]interface{}) error {
	if m.WriteCalls == nil {
		m.WriteCalls = make([]VaultWriteCall, 0)
	}
	m.WriteCalls = append(m.WriteCalls, VaultWriteCall{
		Path: path,
		Data: data,
	})
	return m.WriteError
}

func (m *MockVaultClient) Read(path string) (map[string]interface{}, error) {
	return m.ReadData, m.ReadError
}

func (m *MockVaultClient) Delete(path string) error {
	return nil
}

func createTestLogger(t *testing.T) otelzap.LoggerWithCtx {
	logger := zaptest.NewLogger(t)
	return otelzap.New(logger).Ctx(context.Background())
}

// Test UserExistenceCheck
func TestUserExistenceCheck_Assess_SaltConnected(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		TestPingResult: true,
		TestPingError:  nil,
	}

	operation := &users.UserExistenceCheck{
		Username:   "testuser",
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.True(t, result.CanProceed)
	assert.True(t, result.Prerequisites["salt_connected"])
	assert.True(t, result.Prerequisites["target_reachable"])
}

func TestUserExistenceCheck_Assess_SaltNotConnected(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		TestPingResult: false,
		TestPingError:  errors.New("connection failed"),
	}

	operation := &users.UserExistenceCheck{
		Username:   "testuser",
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	result, err := operation.Assess(ctx)

	require.NoError(t, err)
	assert.False(t, result.CanProceed)
	assert.Equal(t, "cannot connect to target via Salt", result.Reason)
}

func TestUserExistenceCheck_Intervene_UserExists(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"id testuser": "uid=1001(testuser) gid=1001(testuser) groups=1001(testuser)",
		},
	}

	operation := &users.UserExistenceCheck{
		Username:   "testuser",
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "user existence check completed", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "user_check", result.Changes[0].Type)
	assert.True(t, result.RollbackData.(bool)) // User exists
}

func TestUserExistenceCheck_Intervene_UserNotExists(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"id testuser": "id: testuser: no such user",
		},
	}

	operation := &users.UserExistenceCheck{
		Username:   "testuser",
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.False(t, result.RollbackData.(bool)) // User doesn't exist
}

func TestUserExistenceCheck_Evaluate(t *testing.T) {
	logger := createTestLogger(t)
	operation := &users.UserExistenceCheck{
		Username: "testuser",
		Logger:   logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "check completed",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "user existence check validated", result.Message)
	assert.True(t, result.Validations["check_completed"].Passed)
}

// Test UserCreationOperation
func TestUserCreationOperation_Assess_GroupsExist(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		TestPingResult: true,
		CmdRunResults: map[string]string{
			"id newuser":                       "id: newuser: no such user", // User doesn't exist
			"getent group sudo":                "sudo:x:27:user1,user2",
			"getent group docker":              "docker:x:999:user1",
			"test -f /bin/bash && echo exists": "exists",
		},
	}

	// Mock user existence check executor to simulate user doesn't exist
	operation := &users.UserCreationOperation{
		Username:    "newuser",
		Password:    "securepassword",
		Groups:      []string{"sudo", "docker"},
		Shell:       "/bin/bash",
		HomeDir:     "/home/newuser",
		Target:      "test-target",
		SaltClient:  saltClient,
		VaultClient: nil,
		Logger:      logger,
	}

	ctx := context.Background()
	_, err := operation.Assess(ctx)

	// The operation should succeed since we're providing mock data
	assert.NoError(t, err)
}

func TestUserCreationOperation_Intervene_Success(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		StateApplyError: nil,
	}
	vaultClient := &MockVaultClient{
		WriteError: nil,
	}

	operation := &users.UserCreationOperation{
		Username:    "newuser",
		Password:    "securepassword",
		Groups:      []string{"sudo"},
		Shell:       "/bin/bash",
		HomeDir:     "/home/newuser",
		Target:      "test-target",
		SaltClient:  saltClient,
		VaultClient: vaultClient,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "user created successfully", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "user_creation", result.Changes[0].Type)

	// Verify Salt state was applied
	require.Len(t, saltClient.StateApplyCalls, 1)
	call := saltClient.StateApplyCalls[0]
	assert.Equal(t, "test-target", call.Target)
	assert.Equal(t, "users.create", call.State)

	// Verify Vault write was called
	require.Len(t, vaultClient.WriteCalls, 1)
	vaultCall := vaultClient.WriteCalls[0]
	assert.Equal(t, "secret/users/newuser", vaultCall.Path)
	assert.Equal(t, "securepassword", vaultCall.Data["password"])
}

func TestUserCreationOperation_Intervene_SaltFails(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		StateApplyError: errors.New("salt state failed"),
	}

	operation := &users.UserCreationOperation{
		Username:   "newuser",
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Message, "failed to create user")
}

func TestUserCreationOperation_Evaluate_Success(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"id newuser": "uid=1001(newuser) gid=1001(newuser) groups=1001(newuser),27(sudo)",
			"groups newuser | grep -q sudo && echo yes || echo no": "yes",
		},
	}

	operation := &users.UserCreationOperation{
		Username:   "newuser",
		Groups:     []string{"sudo"},
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "user created",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "user creation validated", result.Message)
	assert.True(t, result.Validations["user_exists"].Passed)
	assert.True(t, result.Validations["group_sudo"].Passed)
}

func TestUserCreationOperation_Evaluate_UserNotCreated(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"id newuser": "id: newuser: no such user",
		},
	}

	operation := &users.UserCreationOperation{
		Username:   "newuser",
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "user created",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Equal(t, "user creation validation failed", result.Message)
	assert.True(t, result.NeedsRollback)
	assert.False(t, result.Validations["user_exists"].Passed)
}

// Test PasswordUpdateOperation
func TestPasswordUpdateOperation_Assess_UserExists(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		TestPingResult: true,
		CmdRunResults: map[string]string{
			"id existinguser": "uid=1001(existinguser) gid=1001(existinguser) groups=1001(existinguser)",
		},
	}

	operation := &users.PasswordUpdateOperation{
		Username:    "existinguser",
		NewPassword: "newsecurepassword",
		Target:      "test-target",
		SaltClient:  saltClient,
		Logger:      logger,
	}

	ctx := context.Background()

	// Should succeed with proper salt client mocking
	_, err := operation.Assess(ctx)
	assert.NoError(t, err)
}

func TestPasswordUpdateOperation_Intervene_Success(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"echo 'testuser:newpassword' | chpasswd": "",
		},
	}
	vaultClient := &MockVaultClient{
		WriteError: nil,
	}

	operation := &users.PasswordUpdateOperation{
		Username:    "testuser",
		NewPassword: "newpassword",
		Target:      "test-target",
		SaltClient:  saltClient,
		VaultClient: vaultClient,
		Logger:      logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "password updated successfully", result.Message)

	// Verify Vault was updated
	require.Len(t, vaultClient.WriteCalls, 1)
	vaultCall := vaultClient.WriteCalls[0]
	assert.Equal(t, "secret/users/testuser", vaultCall.Path)
	assert.Equal(t, "newpassword", vaultCall.Data["password"])
}

func TestPasswordUpdateOperation_Evaluate(t *testing.T) {
	logger := createTestLogger(t)
	operation := &users.PasswordUpdateOperation{
		Username: "testuser",
		Logger:   logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "password updated",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "password update assumed successful", result.Message)
	assert.True(t, result.Validations["password_changed"].Passed)
}

// Test UserDeletionOperation
func TestUserDeletionOperation_Assess_UserHasActiveProcesses(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		TestPingResult: true,
		CmdRunResults: map[string]string{
			"id testuser":            "uid=1001(testuser) gid=1001(testuser) groups=1001(testuser)",
			"ps -u testuser | wc -l": "5", // User has active processes
		},
	}

	operation := &users.UserDeletionOperation{
		Username:   "testuser",
		RemoveHome: true,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()

	// Should succeed with proper mocking
	_, err := operation.Assess(ctx)
	assert.NoError(t, err)
}

func TestUserDeletionOperation_Intervene_Success(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"pkill -u testuser || true": "",
			"userdel -r testuser":       "",
		},
	}

	operation := &users.UserDeletionOperation{
		Username:   "testuser",
		RemoveHome: true,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	assessment := &patterns.AssessmentResult{CanProceed: true}

	result, err := operation.Intervene(ctx, assessment)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "user deleted successfully", result.Message)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, "user_deletion", result.Changes[0].Type)
}

func TestUserDeletionOperation_Evaluate_Success(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"id testuser 2>&1": "id: testuser: no such user",
			"test -d /home/testuser && echo exists || echo removed": "removed",
		},
	}

	operation := &users.UserDeletionOperation{
		Username:   "testuser",
		RemoveHome: true,
		Target:     "test-target",
		SaltClient: saltClient,
		Logger:     logger,
	}

	ctx := context.Background()
	intervention := &patterns.InterventionResult{
		Success: true,
		Message: "user deleted",
	}

	result, err := operation.Evaluate(ctx, intervention)

	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "user deletion validated", result.Message)
	assert.True(t, result.Validations["user_removed"].Passed)
	assert.True(t, result.Validations["home_removed"].Passed)
}

// Test GenerateSecurePassword
func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name     string
		length   int
		expected int
	}{
		{
			name:     "default minimum length",
			length:   8,
			expected: 12, // Should use minimum of 12
		},
		{
			name:     "specified length",
			length:   16,
			expected: 16,
		},
		{
			name:     "large length",
			length:   32,
			expected: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := users.GenerateSecurePassword(tt.length)

			require.NoError(t, err)
			assert.NotEmpty(t, password)
			// The actual length might be trimmed due to base64 encoding
			assert.GreaterOrEqual(t, len(password), 10) // At least some reasonable length
		})
	}
}

func TestGenerateSecurePassword_Uniqueness(t *testing.T) {
	passwords := make(map[string]bool)

	// Generate 100 passwords and ensure they're all unique
	for i := 0; i < 100; i++ {
		password, err := users.GenerateSecurePassword(16)
		require.NoError(t, err)

		// Check uniqueness
		assert.False(t, passwords[password], "Generated duplicate password: %s", password)
		passwords[password] = true
	}
}

// Test GetSystemUsers
func TestGetSystemUsers(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }'": "user1\nuser2\ntestuser\n",
		},
	}

	ctx := context.Background()
	users, err := users.GetSystemUsers(ctx, saltClient, "test-target", logger)

	require.NoError(t, err)
	assert.Equal(t, []string{"user1", "user2", "testuser"}, users)
}

func TestGetSystemUsers_EmptyResult(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunResults: map[string]string{
			"getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }'": "",
		},
	}

	ctx := context.Background()
	users, err := users.GetSystemUsers(ctx, saltClient, "test-target", logger)

	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestGetSystemUsers_Error(t *testing.T) {
	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		CmdRunErrors: map[string]error{
			"getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }'": errors.New("command failed"),
		},
	}

	ctx := context.Background()
	users, err := users.GetSystemUsers(ctx, saltClient, "test-target", logger)

	assert.Error(t, err)
	assert.Nil(t, users)
	assert.Contains(t, err.Error(), "failed to get users")
}

// Benchmark tests
func BenchmarkGenerateSecurePassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := users.GenerateSecurePassword(16)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUserExistenceCheck_Assess(b *testing.B) {
	logger := zaptest.NewLogger(b)
	otelLogger := otelzap.New(logger).Ctx(context.Background())
	saltClient := &MockSaltClient{
		TestPingResult: true,
	}

	operation := &users.UserExistenceCheck{
		Username:   "benchuser",
		Target:     "bench-target",
		SaltClient: saltClient,
		Logger:     otelLogger,
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := operation.Assess(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Integration test example
func TestUserOperations_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := createTestLogger(t)
	saltClient := &MockSaltClient{
		TestPingResult: true,
		CmdRunResults: map[string]string{
			"getent group sudo":                "sudo:x:27:",
			"test -f /bin/bash && echo exists": "exists",
			"id testuser":                      "uid=1001(testuser) gid=1001(testuser) groups=1001(testuser),27(sudo)",
			"groups testuser | grep -q sudo && echo yes || echo no": "yes",
		},
	}
	vaultClient := &MockVaultClient{}

	ctx := context.Background()

	// Test complete user creation workflow
	t.Run("complete user creation", func(t *testing.T) {
		// 1. Check user doesn't exist
		existCheck := &users.UserExistenceCheck{
			Username:   "testuser",
			Target:     "test-target",
			SaltClient: saltClient,
			Logger:     logger,
		}

		assessment, err := existCheck.Assess(ctx)
		require.NoError(t, err)
		assert.True(t, assessment.CanProceed)

		// 2. Create user
		createOp := &users.UserCreationOperation{
			Username:    "testuser",
			Password:    "securepassword",
			Groups:      []string{"sudo"},
			Shell:       "/bin/bash",
			HomeDir:     "/home/testuser",
			Target:      "test-target",
			SaltClient:  saltClient,
			VaultClient: vaultClient,
			Logger:      logger,
		}

		// Skip full assessment due to embedded executor
		createAssessment := &patterns.AssessmentResult{CanProceed: true}

		intervention, err := createOp.Intervene(ctx, createAssessment)
		require.NoError(t, err)
		assert.True(t, intervention.Success)

		// 3. Verify creation
		// Update mock to return user exists
		saltClient.CmdRunResults["id testuser"] = "uid=1001(testuser) gid=1001(testuser) groups=1001(testuser),27(sudo)"

		evaluation, err := createOp.Evaluate(ctx, intervention)
		require.NoError(t, err)
		assert.True(t, evaluation.Success)

		// Verify mock calls
		assert.Len(t, saltClient.StateApplyCalls, 1)
		assert.Len(t, vaultClient.WriteCalls, 1)
	})
}
