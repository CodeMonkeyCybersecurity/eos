// pkg/infrastructure/vault/client_test.go
package vault_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestVaultClient(t *testing.T) {
	t.Run("health_check_integration", func(t *testing.T) {
		// Create test server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/sys/health", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
                "initialized": true,
                "sealed": false,
                "standby": false,
                "version": "1.13.0",
                "cluster_name": "test-cluster",
                "cluster_id": "test-id"
            }`))
		}))
		defer server.Close()

		logger := zaptest.NewLogger(t)
		client, err := vault.NewClient(server.URL, logger)
		require.NoError(t, err)

		err = client.CheckHealth(context.Background())
		assert.NoError(t, err)
	})

	t.Run("sealed_vault_health_check", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"sealed": true}`))
		}))
		defer server.Close()

		logger := zaptest.NewLogger(t)
		client, err := vault.NewClient(server.URL, logger)
		require.NoError(t, err)

		err = client.CheckHealth(context.Background())
		assert.Error(t, err)
	})
}
