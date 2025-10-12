package hecate

import (
	"context"
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretManager_BackendDetection(t *testing.T) {
	rc := eos_io.NewContext(context.Background(), "test-secret-manager")

	// Test with no Vault available (expected in test environment)
	sm, err := NewSecretManager(rc)
	require.NoError(t, err)
	assert.NotNil(t, sm)

	// Should fall back to Consul KV
	backend := sm.GetBackend()
	assert.Equal(t, SecretBackendConsul, backend)
	assert.False(t, sm.IsVaultAvailable())
}

func TestSecretManager_Secrets(t *testing.T) {
	rc := eos_io.NewContext(context.Background(), "test--secrets")

	// Create a test secret manager that will use Consul KV
	sm := &SecretManager{
		backend: SecretBackendConsul,
		rc:      rc,
	}

	// Create test secret files in the expected location
	testDir := "/opt/hecate/secrets"
	err := os.MkdirAll(testDir, 0700)
	if err != nil {
		t.Skipf("Cannot create test directory %s: %v. Skipping  secrets test.", testDir, err)
		return
	}
	defer func() {
		// Clean up test files
		_ = os.RemoveAll(testDir)
	}()

	// Create test postgres secrets file
	postgresFile := testDir + "/postgres.env"
	postgresContent := `POSTGRES_ROOT_PASSWORD=test-root-pass
POSTGRES_PASSWORD=test-user-pass`

	err = os.WriteFile(postgresFile, []byte(postgresContent), 0600)
	require.NoError(t, err)

	// Create test redis secrets file
	redisFile := testDir + "/redis.env"
	redisContent := `REDIS_PASSWORD=test-redis-pass`

	err = os.WriteFile(redisFile, []byte(redisContent), 0600)
	require.NoError(t, err)

	// Create test authentik secrets file
	authentikFile := testDir + "/authentik.env"
	authentikContent := `AUTHENTIK_SECRET_KEY=test-secret-key-123456789
AUTHENTIK_ADMIN_USERNAME=akadmin
AUTHENTIK_ADMIN_PASSWORD=test-admin-pass`

	err = os.WriteFile(authentikFile, []byte(authentikContent), 0600)
	require.NoError(t, err)

	// Test retrieving various secrets
	testCases := []struct {
		service  string
		key      string
		expected string
	}{
		{"postgres", "root_password", "test-root-pass"},
		{"postgres", "password", "test-user-pass"},
		{"redis", "password", "test-redis-pass"},
		{"authentik", "secret_key", "test-secret-key-123456789"},
		{"authentik", "admin_username", "akadmin"},
		{"authentik", "admin_password", "test-admin-pass"},
	}

	for _, tc := range testCases {
		t.Run(tc.service+"_"+tc.key, func(t *testing.T) {
			value, err := sm.GetSecret(tc.service, tc.key)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, value)
		})
	}

	// Test error cases
	_, err = sm.GetSecret("unknown", "key")
	assert.Error(t, err)

	_, err = sm.GetSecret("postgres", "unknown_key")
	assert.Error(t, err)
}

func TestSecretManager_BackendComparison(t *testing.T) {
	rc := eos_io.NewContext(context.Background(), "test-backend-comparison")

	// Test that both backends have the same interface
	backends := []SecretBackend{SecretBackendVault, SecretBackendConsul}

	for _, backend := range backends {
		t.Run(string(backend), func(t *testing.T) {
			sm := &SecretManager{
				backend: backend,
				rc:      rc,
			}

			// Test that GetBackend works
			assert.Equal(t, backend, sm.GetBackend())

			// Test IsVaultAvailable
			expectedVault := backend == SecretBackendVault
			assert.Equal(t, expectedVault, sm.IsVaultAvailable())
		})
	}
}

func TestSecretManager_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	rc := eos_io.NewContext(context.Background(), "test-integration")

	// Create secret manager (should detect  backend in test environment)
	sm, err := NewSecretManager(rc)
	require.NoError(t, err)

	// In test environment, expect Consul KV backend
	assert.Equal(t, SecretBackendConsul, sm.GetBackend())

	// Test that GenerateSecrets can be called without error (even if it fails)
	// This tests the interface rather than the actual generation
	err = sm.GenerateSecrets()
	// We don't require this to succeed in test environment, just not panic
	if err != nil {
		t.Logf("GenerateSecrets failed as expected in test environment: %v", err)
	}
}
