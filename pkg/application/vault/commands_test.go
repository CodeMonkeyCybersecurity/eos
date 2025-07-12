package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockVaultService is a mock implementation of vault.VaultService
type MockVaultService struct {
	mock.Mock
}

func (m *MockVaultService) CheckHealth(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockVaultService) GetSecret(ctx context.Context, path string) (*vault.Secret, error) {
	args := m.Called(ctx, path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.Secret), args.Error(1)
}

func (m *MockVaultService) CreateSecret(ctx context.Context, path string, data map[string]interface{}) error {
	args := m.Called(ctx, path, data)
	return args.Error(0)
}

func (m *MockVaultService) DeleteSecret(ctx context.Context, path string) error {
	args := m.Called(ctx, path)
	return args.Error(0)
}

func (m *MockVaultService) ListSecrets(ctx context.Context, prefix string) ([]*vault.SecretMetadata, error) {
	args := m.Called(ctx, prefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*vault.SecretMetadata), args.Error(1)
}

func (m *MockVaultService) GetStatus(ctx context.Context) (*vault.VaultStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.VaultStatus), args.Error(1)
}

func (m *MockVaultService) UpdateSecret(ctx context.Context, path string, data map[string]interface{}) error {
	args := m.Called(ctx, path, data)
	return args.Error(0)
}

func (m *MockVaultService) Login(ctx context.Context, auth vault.AuthMethod) (*vault.AuthToken, error) {
	args := m.Called(ctx, auth)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.AuthToken), args.Error(1)
}

func (m *MockVaultService) Renew(ctx context.Context, token string) (*vault.AuthToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vault.AuthToken), args.Error(1)
}

func (m *MockVaultService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func TestNewCommands(t *testing.T) {
	mockService := &MockVaultService{}
	commands := NewCommands(mockService)
	
	assert.NotNil(t, commands)
	assert.Equal(t, mockService, commands.service)
}

func TestGetSecretCommand_Structure(t *testing.T) {
	tests := []struct {
		name     string
		cmd      GetSecretCommand
		validate func(t *testing.T, cmd GetSecretCommand)
	}{
		{
			name: "command with path",
			cmd:  GetSecretCommand{Path: "secret/data/myapp"},
			validate: func(t *testing.T, cmd GetSecretCommand) {
				assert.Equal(t, "secret/data/myapp", cmd.Path)
			},
		},
		{
			name: "command with empty path",
			cmd:  GetSecretCommand{Path: ""},
			validate: func(t *testing.T, cmd GetSecretCommand) {
				assert.Empty(t, cmd.Path)
			},
		},
		{
			name: "command with complex path",
			cmd:  GetSecretCommand{Path: "kv/data/prod/database/credentials"},
			validate: func(t *testing.T, cmd GetSecretCommand) {
				assert.Equal(t, "kv/data/prod/database/credentials", cmd.Path)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.cmd)
		})
	}
}

func TestCommands_Execute(t *testing.T) {
	tests := []struct {
		name           string
		cmd            GetSecretCommand
		setupMock      func(*MockVaultService)
		expectedSecret *vault.Secret
		expectedError  string
	}{
		{
			name: "successful secret retrieval",
			cmd:  GetSecretCommand{Path: "secret/data/myapp"},
			setupMock: func(m *MockVaultService) {
				m.On("CheckHealth", mock.Anything).Return(nil)
				m.On("GetSecret", mock.Anything, "secret/data/myapp").Return(
					&vault.Secret{
						Path: "secret/data/myapp",
						Data: map[string]interface{}{
							"username": "admin",
							"password": "secret123",
						},
					}, nil)
			},
			expectedSecret: &vault.Secret{
				Path: "secret/data/myapp",
				Data: map[string]interface{}{
					"username": "admin",
					"password": "secret123",
				},
			},
		},
		{
			name: "empty path validation",
			cmd:  GetSecretCommand{Path: ""},
			setupMock: func(m *MockVaultService) {
				// No mocks needed - should fail validation
			},
			expectedError: "secret path is required",
		},
		{
			name: "health check failure",
			cmd:  GetSecretCommand{Path: "secret/data/myapp"},
			setupMock: func(m *MockVaultService) {
				m.On("CheckHealth", mock.Anything).Return(errors.New("vault is sealed"))
			},
			expectedError: "vault health check failed: vault is sealed",
		},
		{
			name: "secret not found",
			cmd:  GetSecretCommand{Path: "secret/data/nonexistent"},
			setupMock: func(m *MockVaultService) {
				m.On("CheckHealth", mock.Anything).Return(nil)
				m.On("GetSecret", mock.Anything, "secret/data/nonexistent").Return(
					nil, errors.New("secret not found"))
			},
			expectedError: "getting secret: secret not found",
		},
		{
			name: "network error",
			cmd:  GetSecretCommand{Path: "secret/data/myapp"},
			setupMock: func(m *MockVaultService) {
				m.On("CheckHealth", mock.Anything).Return(nil)
				m.On("GetSecret", mock.Anything, "secret/data/myapp").Return(
					nil, errors.New("connection refused"))
			},
			expectedError: "getting secret: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockVaultService{}
			if tt.setupMock != nil {
				tt.setupMock(mockService)
			}

			commands := NewCommands(mockService)
			ctx := context.Background()

			secret, err := commands.Execute(ctx, tt.cmd)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, secret)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSecret, secret)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestCommands_Execute_ContextCancellation(t *testing.T) {
	mockService := &MockVaultService{}
	commands := NewCommands(mockService)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Mock should handle context cancellation
	mockService.On("CheckHealth", mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Err() != nil
	})).Return(context.Canceled)

	cmd := GetSecretCommand{Path: "secret/data/myapp"}
	_, err := commands.Execute(ctx, cmd)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "canceled")
}

func TestCommands_Execute_PathValidation(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		shouldFail    bool
		expectedError string
	}{
		{
			name:       "valid path",
			path:       "secret/data/myapp",
			shouldFail: false,
		},
		{
			name:          "empty path",
			path:          "",
			shouldFail:    true,
			expectedError: "secret path is required",
		},
		{
			name:       "path with special characters",
			path:       "secret/data/my-app_v1.0",
			shouldFail: false,
		},
		{
			name:       "deeply nested path",
			path:       "kv/data/prod/region/us-east-1/service/api/credentials",
			shouldFail: false,
		},
		{
			name:       "path with spaces",
			path:       "secret/data/my app",
			shouldFail: false, // Vault might handle this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockVaultService{}
			commands := NewCommands(mockService)

			if !tt.shouldFail {
				mockService.On("CheckHealth", mock.Anything).Return(nil)
				mockService.On("GetSecret", mock.Anything, tt.path).Return(
					&vault.Secret{Path: tt.path, Data: map[string]interface{}{}}, nil)
			}

			cmd := GetSecretCommand{Path: tt.path}
			_, err := commands.Execute(context.Background(), cmd)

			if tt.shouldFail {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestCommands_Execute_SecretData(t *testing.T) {
	tests := []struct {
		name         string
		secretData   map[string]interface{}
		validateData func(t *testing.T, data map[string]interface{})
	}{
		{
			name: "simple string values",
			secretData: map[string]interface{}{
				"username": "admin",
				"password": "secret123",
			},
			validateData: func(t *testing.T, data map[string]interface{}) {
				assert.Equal(t, "admin", data["username"])
				assert.Equal(t, "secret123", data["password"])
			},
		},
		{
			name: "numeric values",
			secretData: map[string]interface{}{
				"port":    5432,
				"timeout": 30.5,
			},
			validateData: func(t *testing.T, data map[string]interface{}) {
				assert.Equal(t, 5432, data["port"])
				assert.Equal(t, 30.5, data["timeout"])
			},
		},
		{
			name: "nested data",
			secretData: map[string]interface{}{
				"database": map[string]interface{}{
					"host": "localhost",
					"port": 5432,
				},
			},
			validateData: func(t *testing.T, data map[string]interface{}) {
				db, ok := data["database"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "localhost", db["host"])
				assert.Equal(t, 5432, db["port"])
			},
		},
		{
			name:       "empty data",
			secretData: map[string]interface{}{},
			validateData: func(t *testing.T, data map[string]interface{}) {
				assert.Empty(t, data)
			},
		},
		{
			name: "nil values",
			secretData: map[string]interface{}{
				"optional": nil,
				"required": "value",
			},
			validateData: func(t *testing.T, data map[string]interface{}) {
				assert.Nil(t, data["optional"])
				assert.Equal(t, "value", data["required"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockVaultService{}
			mockService.On("CheckHealth", mock.Anything).Return(nil)
			mockService.On("GetSecret", mock.Anything, "test/path").Return(
				&vault.Secret{
					Path: "test/path",
					Data: tt.secretData,
				}, nil)

			commands := NewCommands(mockService)
			cmd := GetSecretCommand{Path: "test/path"}

			secret, err := commands.Execute(context.Background(), cmd)
			require.NoError(t, err)
			require.NotNil(t, secret)

			tt.validateData(t, secret.Data)
			mockService.AssertExpectations(t)
		})
	}
}

func TestCommands_Execute_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name          string
		healthError   error
		secretError   error
		expectedError string
	}{
		{
			name:          "vault sealed",
			healthError:   errors.New("vault is sealed"),
			expectedError: "vault health check failed: vault is sealed",
		},
		{
			name:          "authentication failure",
			healthError:   nil,
			secretError:   errors.New("permission denied"),
			expectedError: "getting secret: permission denied",
		},
		{
			name:          "network timeout",
			healthError:   nil,
			secretError:   errors.New("i/o timeout"),
			expectedError: "getting secret: i/o timeout",
		},
		{
			name:          "invalid token",
			healthError:   errors.New("invalid token"),
			expectedError: "vault health check failed: invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &MockVaultService{}
			
			if tt.healthError != nil {
				mockService.On("CheckHealth", mock.Anything).Return(tt.healthError)
			} else {
				mockService.On("CheckHealth", mock.Anything).Return(nil)
				mockService.On("GetSecret", mock.Anything, mock.Anything).Return(nil, tt.secretError)
			}

			commands := NewCommands(mockService)
			cmd := GetSecretCommand{Path: "secret/path"}

			_, err := commands.Execute(context.Background(), cmd)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)

			mockService.AssertExpectations(t)
		})
	}
}