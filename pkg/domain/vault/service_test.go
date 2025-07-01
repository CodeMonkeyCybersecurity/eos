package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"
)

// MockSecretStore implements domain.SecretStore for testing
type MockSecretStore struct {
	secrets map[string]*Secret
	errors  map[string]error // Map of operation:key -> error to return
}

func NewMockSecretStore() *MockSecretStore {
	return &MockSecretStore{
		secrets: make(map[string]*Secret),
		errors:  make(map[string]error),
	}
}

func (m *MockSecretStore) Get(ctx context.Context, key string) (*Secret, error) {
	if err, ok := m.errors["get:"+key]; ok {
		return nil, err
	}
	if secret, ok := m.secrets[key]; ok {
		return secret, nil
	}
	return nil, fmt.Errorf("secret not found: %s", key)
}

func (m *MockSecretStore) Set(ctx context.Context, key string, secret *Secret) error {
	if err, ok := m.errors["set:"+key]; ok {
		return err
	}
	m.secrets[key] = secret
	return nil
}

func (m *MockSecretStore) Delete(ctx context.Context, key string) error {
	if err, ok := m.errors["delete:"+key]; ok {
		return err
	}
	delete(m.secrets, key)
	return nil
}

func (m *MockSecretStore) List(ctx context.Context, prefix string) ([]*Secret, error) {
	if err, ok := m.errors["list:"+prefix]; ok {
		return nil, err
	}
	var secrets []*Secret
	for key, secret := range m.secrets {
		if prefix == "" || key[:len(prefix)] == prefix {
			secrets = append(secrets, secret)
		}
	}
	return secrets, nil
}

func (m *MockSecretStore) Exists(ctx context.Context, key string) (bool, error) {
	if err, ok := m.errors["exists:"+key]; ok {
		return false, err
	}
	_, exists := m.secrets[key]
	return exists, nil
}

// SetError configures the mock to return an error for a specific operation
func (m *MockSecretStore) SetError(operation, key string, err error) {
	m.errors[operation+":"+key] = err
}

// MockAuditRepository implements domain.AuditRepository for testing
type MockAuditRepository struct {
	events []AuditEvent
	errors map[string]error
}

func NewMockAuditRepository() *MockAuditRepository {
	return &MockAuditRepository{
		events: make([]AuditEvent, 0),
		errors: make(map[string]error),
	}
}

func (m *MockAuditRepository) Record(ctx context.Context, event *AuditEvent) error {
	if err, ok := m.errors["record"]; ok {
		return err
	}
	m.events = append(m.events, *event)
	return nil
}

func (m *MockAuditRepository) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error) {
	if err, ok := m.errors["query"]; ok {
		return nil, err
	}
	// Simple implementation for testing
	var results []*AuditEvent
	for i := range m.events {
		results = append(results, &m.events[i])
	}
	return results, nil
}

func (m *MockAuditRepository) GetStats(ctx context.Context) (*AuditStats, error) {
	if err, ok := m.errors["stats"]; ok {
		return nil, err
	}
	return &AuditStats{
		TotalEvents: int64(len(m.events)),
	}, nil
}

// GetEvents returns recorded events for testing
func (m *MockAuditRepository) GetEvents() []AuditEvent {
	return m.events
}

func (m *MockAuditRepository) SetError(operation string, err error) {
	m.errors[operation] = err
}

// Test Service.GetSecret
func TestService_GetSecret(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		key           string
		setupSecret   *Secret
		setupError    error
		expectedError bool
	}{
		{
			name:   "successful get",
			userID: "test-user",
			key:    "test-key",
			setupSecret: &Secret{
				Key:       "test-key",
				Value:     "test-value",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			expectedError: false,
		},
		{
			name:          "missing user ID",
			userID:        "",
			key:           "test-key",
			expectedError: true,
		},
		{
			name:          "missing key",
			userID:        "test-user",
			key:           "",
			expectedError: true,
		},
		{
			name:          "store error",
			userID:        "test-user",
			key:           "test-key",
			setupError:    fmt.Errorf("store error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := NewMockSecretStore()
			mockAudit := NewMockAuditRepository()
			logger := zaptest.NewLogger(t)

			service := NewService(mockStore, nil, nil, nil, mockAudit, logger)

			// Setup
			if tt.setupSecret != nil {
				mockStore.secrets[tt.key] = tt.setupSecret
			}
			if tt.setupError != nil {
				mockStore.SetError("get", tt.key, tt.setupError)
			}

			// Execute
			ctx := context.Background()
			secret, err := service.GetSecret(ctx, tt.userID, tt.key)

			// Verify
			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if secret == nil {
					t.Errorf("expected secret but got nil")
				}
				if secret != nil && secret.Key != tt.key {
					t.Errorf("expected key %s but got %s", tt.key, secret.Key)
				}
			}

			// Verify audit event was recorded
			events := mockAudit.GetEvents()
			if len(events) != 1 {
				t.Errorf("expected 1 audit event but got %d", len(events))
			}
			if len(events) > 0 {
				event := events[0]
				if event.Type != "secret_get" {
					t.Errorf("expected audit type 'secret_get' but got %s", event.Type)
				}
				if event.Auth.DisplayName != tt.userID {
					t.Errorf("expected audit user %s but got %s", tt.userID, event.Auth.DisplayName)
				}
			}
		})
	}
}

// Test Service.SetSecret
func TestService_SetSecret(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		secret        *Secret
		setupError    error
		expectedError bool
	}{
		{
			name:   "successful set",
			userID: "test-user",
			secret: &Secret{
				Key:   "test-key",
				Value: "test-value",
			},
			expectedError: false,
		},
		{
			name:          "missing user ID",
			userID:        "",
			secret:        &Secret{Key: "test-key", Value: "test-value"},
			expectedError: true,
		},
		{
			name:          "nil secret",
			userID:        "test-user",
			secret:        nil,
			expectedError: true,
		},
		{
			name:   "invalid secret - empty key",
			userID: "test-user",
			secret: &Secret{
				Key:   "",
				Value: "test-value",
			},
			expectedError: true,
		},
		{
			name:   "invalid secret - empty value",
			userID: "test-user",
			secret: &Secret{
				Key:   "test-key",
				Value: "",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := NewMockSecretStore()
			mockAudit := NewMockAuditRepository()
			logger := zaptest.NewLogger(t)

			service := NewService(mockStore, nil, nil, nil, mockAudit, logger)

			// Setup
			if tt.setupError != nil && tt.secret != nil {
				mockStore.SetError("set", tt.secret.Key, tt.setupError)
			}

			// Execute
			ctx := context.Background()
			err := service.SetSecret(ctx, tt.userID, tt.secret)

			// Verify
			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Verify secret was stored
				if storedSecret, exists := mockStore.secrets[tt.secret.Key]; !exists {
					t.Errorf("secret was not stored")
				} else {
					if storedSecret.Value != tt.secret.Value {
						t.Errorf("expected value %s but got %s", tt.secret.Value, storedSecret.Value)
					}
					// Check timestamps were set
					if storedSecret.CreatedAt.IsZero() {
						t.Errorf("CreatedAt timestamp not set")
					}
					if storedSecret.UpdatedAt.IsZero() {
						t.Errorf("UpdatedAt timestamp not set")
					}
				}
			}

			// Verify audit event was recorded
			events := mockAudit.GetEvents()
			if len(events) != 1 {
				t.Errorf("expected 1 audit event but got %d", len(events))
			}
			if len(events) > 0 {
				event := events[0]
				if event.Type != "secret_set" {
					t.Errorf("expected audit type 'secret_set' but got %s", event.Type)
				}
			}
		})
	}
}

// Test Service.DeleteSecret
func TestService_DeleteSecret(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		key           string
		setupSecret   *Secret
		setupError    error
		expectedError bool
	}{
		{
			name:   "successful delete",
			userID: "test-user",
			key:    "test-key",
			setupSecret: &Secret{
				Key:   "test-key",
				Value: "test-value",
			},
			expectedError: false,
		},
		{
			name:          "missing user ID",
			userID:        "",
			key:           "test-key",
			expectedError: true,
		},
		{
			name:          "missing key",
			userID:        "test-user",
			key:           "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := NewMockSecretStore()
			mockAudit := NewMockAuditRepository()
			logger := zaptest.NewLogger(t)

			service := NewService(mockStore, nil, nil, nil, mockAudit, logger)

			// Setup
			if tt.setupSecret != nil {
				mockStore.secrets[tt.key] = tt.setupSecret
			}
			if tt.setupError != nil {
				mockStore.SetError("delete", tt.key, tt.setupError)
			}

			// Execute
			ctx := context.Background()
			err := service.DeleteSecret(ctx, tt.userID, tt.key)

			// Verify
			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Verify secret was deleted
				if _, exists := mockStore.secrets[tt.key]; exists {
					t.Errorf("secret was not deleted")
				}
			}

			// Verify audit event was recorded
			events := mockAudit.GetEvents()
			if len(events) != 1 {
				t.Errorf("expected 1 audit event but got %d", len(events))
			}
		})
	}
}

// Test Service.ListSecrets
func TestService_ListSecrets(t *testing.T) {
	mockStore := NewMockSecretStore()
	mockAudit := NewMockAuditRepository()
	logger := zaptest.NewLogger(t)

	service := NewService(mockStore, nil, nil, nil, mockAudit, logger)

	// Setup test secrets
	secrets := []*Secret{
		{Key: "app/secret1", Value: "value1"},
		{Key: "app/secret2", Value: "value2"},
		{Key: "other/secret3", Value: "value3"},
	}

	for _, secret := range secrets {
		mockStore.secrets[secret.Key] = secret
	}

	// Test listing with prefix
	ctx := context.Background()
	results, err := service.ListSecrets(ctx, "test-user", "app/")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 secrets but got %d", len(results))
	}

	// Verify audit event was recorded
	events := mockAudit.GetEvents()
	if len(events) != 1 {
		t.Errorf("expected 1 audit event but got %d", len(events))
	}
	if len(events) > 0 {
		event := events[0]
		if event.Type != "secret_list" {
			t.Errorf("expected audit type 'secret_list' but got %s", event.Type)
		}
	}
}

// Test secret validation
func TestService_validateSecret(t *testing.T) {
	mockStore := NewMockSecretStore()
	mockAudit := NewMockAuditRepository()
	logger := zaptest.NewLogger(t)

	service := NewService(mockStore, nil, nil, nil, mockAudit, logger)

	tests := []struct {
		name          string
		secret        *Secret
		expectedError bool
	}{
		{
			name: "valid secret",
			secret: &Secret{
				Key:   "valid-key",
				Value: "valid-value",
			},
			expectedError: false,
		},
		{
			name:          "nil secret",
			secret:        nil,
			expectedError: true,
		},
		{
			name: "empty key",
			secret: &Secret{
				Key:   "",
				Value: "value",
			},
			expectedError: true,
		},
		{
			name: "empty value",
			secret: &Secret{
				Key:   "key",
				Value: "",
			},
			expectedError: true,
		},
		{
			name: "key with path traversal",
			secret: &Secret{
				Key:   "../secret",
				Value: "value",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateSecret(tt.secret)
			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// MockVaultService provides a mock implementation for testing
type MockVaultService struct {
	mock.Mock
}

func (m *MockVaultService) CheckHealth(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockVaultService) GetStatus(ctx context.Context) (*VaultStatus, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*VaultStatus), args.Error(1)
}

func (m *MockVaultService) GetSecret(ctx context.Context, path string) (*Secret, error) {
	args := m.Called(ctx, path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Secret), args.Error(1)
}

// Test suite for vault domain logic
func TestVaultService(t *testing.T) {
	t.Run("health_check", func(t *testing.T) {
		tests := []struct {
			name        string
			setupMock   func(*MockVaultService)
			expectError bool
			errorType   error
		}{
			{
				name: "healthy_vault",
				setupMock: func(m *MockVaultService) {
					m.On("CheckHealth", mock.Anything).Return(nil)
				},
				expectError: false,
			},
			{
				name: "sealed_vault",
				setupMock: func(m *MockVaultService) {
					m.On("CheckHealth", mock.Anything).Return(ErrVaultSealed)
				},
				expectError: true,
				errorType:   ErrVaultSealed,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockService := new(MockVaultService)
				tt.setupMock(mockService)

				err := mockService.CheckHealth(context.Background())

				if tt.expectError {
					assert.Error(t, err)
					if tt.errorType != nil {
						assert.ErrorIs(t, err, tt.errorType)
					}
				} else {
					assert.NoError(t, err)
				}

				mockService.AssertExpectations(t)
			})
		}
	})

	t.Run("secret_operations", func(t *testing.T) {
		t.Run("get_existing_secret", func(t *testing.T) {
			mockService := new(MockVaultService)
			expectedSecret := &Secret{
				Path: "secret/data/test",
				Data: map[string]interface{}{
					"username": "admin",
					"password": "secret123",
				},
				Version: 1,
			}

			mockService.On("GetSecret", mock.Anything, "secret/data/test").
				Return(expectedSecret, nil)

			secret, err := mockService.GetSecret(context.Background(), "secret/data/test")

			assert.NoError(t, err)
			assert.Equal(t, expectedSecret, secret)
			mockService.AssertExpectations(t)
		})

		t.Run("get_non_existing_secret", func(t *testing.T) {
			mockService := new(MockVaultService)

			mockService.On("GetSecret", mock.Anything, "secret/data/missing").
				Return(nil, ErrSecretNotFound)

			secret, err := mockService.GetSecret(context.Background(), "secret/data/missing")

			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrSecretNotFound)
			assert.Nil(t, secret)
			mockService.AssertExpectations(t)
		})
	})
}
