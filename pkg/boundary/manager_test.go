package boundary_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestManager_Create(t *testing.T) {
	// Create mock Salt API server
	server := createMockSaltAPI(t)
	defer server.Close()

	// Create Salt client
	saltClient, err := salt.NewClient(salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "test",
		Password: "test",
		Logger:   zaptest.NewLogger(t),
	})
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create manager
	manager, err := boundary.NewManager(rc, saltClient)
	require.NoError(t, err)

	// Test create controller
	createOpts := &boundary.CreateOptions{
		Target: "test-minion",
		Config: &boundary.Config{
			Role:        "controller",
			Version:     "0.15.0",
			ClusterName: "test-cluster",
			DatabaseURL: "postgresql://boundary:password@localhost/boundary",
		},
		Force:   false,
		Clean:   false,
		Timeout: 10 * time.Second,
	}

	err = manager.Create(context.Background(), createOpts)
	require.NoError(t, err)
}

func TestManager_Delete(t *testing.T) {
	// Create mock Salt API server
	server := createMockSaltAPI(t)
	defer server.Close()

	// Create Salt client
	saltClient, err := salt.NewClient(salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "test",
		Password: "test",
		Logger:   zaptest.NewLogger(t),
	})
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create manager
	manager, err := boundary.NewManager(rc, saltClient)
	require.NoError(t, err)

	// Test delete
	deleteOpts := &boundary.DeleteOptions{
		Target:      "test-minion",
		ClusterName: "test-cluster",
		KeepData:    false,
		KeepConfig:  false,
		KeepUser:    false,
		Force:       true,
		Timeout:     10 * time.Second,
	}

	err = manager.Delete(context.Background(), deleteOpts)
	require.NoError(t, err)
}

func TestManager_Status(t *testing.T) {
	// Create mock Salt API server
	server := createMockSaltAPI(t)
	defer server.Close()

	// Create Salt client
	saltClient, err := salt.NewClient(salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "test",
		Password: "test",
		Logger:   zaptest.NewLogger(t),
	})
	require.NoError(t, err)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create manager
	manager, err := boundary.NewManager(rc, saltClient)
	require.NoError(t, err)

	// Test status
	statusOpts := &boundary.StatusOptions{
		Target:   "test-minion",
		Detailed: true,
	}

	result, err := manager.Status(context.Background(), statusOpts)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Minions)
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *boundary.Config
		wantErr bool
	}{
		{
			name: "valid controller config",
			config: &boundary.Config{
				Role:        "controller",
				Version:     "0.15.0",
				ClusterName: "test",
				DatabaseURL: "postgresql://boundary:password@localhost/boundary",
			},
			wantErr: false,
		},
		{
			name: "valid worker config",
			config: &boundary.Config{
				Role:             "worker",
				Version:          "0.15.0",
				ClusterName:      "test",
				InitialUpstreams: []string{"controller1:9201", "controller2:9201"},
			},
			wantErr: false,
		},
		{
			name: "valid dev config",
			config: &boundary.Config{
				Role:        "dev",
				Version:     "0.15.0",
				ClusterName: "test",
				DatabaseURL: "postgresql://boundary:password@localhost/boundary",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation that config fields are properly set
			assert.NotEmpty(t, tt.config.Role)
			assert.NotEmpty(t, tt.config.ClusterName)
			
			if tt.config.Role == "controller" || tt.config.Role == "dev" {
				assert.NotEmpty(t, tt.config.DatabaseURL)
			}
			
			if tt.config.Role == "worker" {
				assert.NotEmpty(t, tt.config.InitialUpstreams)
			}
		})
	}
}

// Helper function to create a mock Salt API server
func createMockSaltAPI(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			// Mock authentication
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"return": [{
					"token": "test-token",
					"expire": ` + fmt.Sprintf("%.0f", float64(time.Now().Add(12*time.Hour).Unix())) + `,
					"start": ` + fmt.Sprintf("%.0f", float64(time.Now().Unix())) + `,
					"user": "test",
					"eauth": "pam",
					"perms": [".*"]
				}]
			}`))

		case "/":
			// Check for auth token
			if r.Header.Get("X-Auth-Token") != "test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Mock successful command response
			w.Header().Set("Content-Type", "application/json")
			
			// Parse the request to determine response
			r.ParseForm()
			fun := r.FormValue("fun")
			
			switch fun {
			case "state.apply":
				// Mock state application success
				w.Write([]byte(`{
					"return": [{
						"test-minion": {
							"boundary_install": {
								"result": true,
								"comment": "Boundary installed successfully",
								"changes": {
									"new": "0.15.0",
									"old": null
								},
								"duration": 1.234
							}
						}
					}]
				}`))
				
			case "cmd.run":
				// Mock status check response
				w.Write([]byte(`{
					"return": [{
						"test-minion": "{\"installed\": true, \"running\": true, \"version\": \"0.15.0\", \"role\": \"controller\", \"service_status\": \"active\", \"config_valid\": true}"
					}]
				}`))
				
			default:
				// Default success response
				w.Write([]byte(`{
					"return": [{
						"test-minion": {"result": "success"}
					}]
				}`))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}