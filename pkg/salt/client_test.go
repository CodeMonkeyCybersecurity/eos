package salt_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestClient_Authentication(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "testuser", r.FormValue("username"))
			assert.Equal(t, "testpass", r.FormValue("password"))
			assert.Equal(t, "pam", r.FormValue("eauth"))

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"return": [{
					"token": "test-token-123",
					"expire": 1234567890,
					"start": 1234567890,
					"user": "testuser",
					"eauth": "pam",
					"perms": [".*"]
				}]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client
	config := salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
		Logger:   zaptest.NewLogger(t),
	}

	client, err := salt.NewClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestClient_ExecuteCommand(t *testing.T) {
	// Create test server with auth and command handling
	authenticated := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			authenticated = true
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"return": [{"token": "test-token"}]}`))

		case "/":
			assert.True(t, authenticated)
			assert.Equal(t, "test-token", r.Header.Get("X-Auth-Token"))
			assert.Equal(t, "local", r.FormValue("client"))
			assert.Equal(t, "*", r.FormValue("tgt"))
			assert.Equal(t, "test.ping", r.FormValue("fun"))

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"return": [{
					"minion1": true,
					"minion2": true
				}]
			}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client and execute command
	config := salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
		Logger:   zaptest.NewLogger(t),
	}

	client, err := salt.NewClient(config)
	require.NoError(t, err)

	cmd := salt.Command{
		Client:   "local",
		Target:   "*",
		Function: "test.ping",
	}

	result, err := client.ExecuteCommand(context.Background(), cmd)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, true, result.Raw["minion1"])
	assert.Equal(t, true, result.Raw["minion2"])
}

func TestClient_StateApply(t *testing.T) {
	// This tests the state application flow
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"return": [{"token": "test-token"}]}`))

		case "/":
			if r.FormValue("client") == "local_async" {
				// Starting async job
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{
					"return": [{
						"jid": "20231123123456789",
						"minions": ["minion1"]
					}]
				}`))
			} else {
				// Regular command
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"return": [{"result": true}]}`))
			}

		case "/events":
			// Simulate server-sent events
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")

			// Send a progress event
			fmt.Fprintf(w, "data: %s\n\n", `{
				"tag": "salt/job/20231123123456789/prog",
				"data": {
					"state": "Installing package",
					"message": "Downloading consul binary"
				}
			}`)
			w.(http.Flusher).Flush()

			// Send completion event
			time.Sleep(100 * time.Millisecond)
			jobReturn := map[string]interface{}{
				"return": map[string]interface{}{
					"consul_package": map[string]interface{}{
						"result":   true,
						"comment":  "Package installed successfully",
						"changes":  map[string]interface{}{"new": "1.16.0", "old": ""},
						"duration": 1.234,
					},
				},
			}
			jobReturnJSON, _ := json.Marshal(jobReturn)
			fmt.Fprintf(w, "data: %s\n\n", fmt.Sprintf(`{
				"tag": "salt/job/20231123123456789/ret",
				"data": %s
			}`, string(jobReturnJSON)))
			w.(http.Flusher).Flush()

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	config := salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
		Logger:   zaptest.NewLogger(t),
		Timeout:  5 * time.Second,
	}

	client, err := salt.NewClient(config)
	require.NoError(t, err)

	// Track progress updates
	var progressUpdates []salt.StateProgress
	result, err := client.ExecuteStateApply(context.Background(), "test.state",
		map[string]interface{}{"test": "value"},
		func(progress salt.StateProgress) {
			progressUpdates = append(progressUpdates, progress)
		})

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Completed)
	assert.False(t, result.Failed)
	assert.Len(t, result.States, 1)

	// Verify we got progress updates
	assert.GreaterOrEqual(t, len(progressUpdates), 1)
}

func TestClient_TokenRefresh(t *testing.T) {
	// Test that token is refreshed when expired
	loginCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			loginCount++
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(fmt.Sprintf(`{"return": [{"token": "token-%d"}]}`, loginCount)))

		case "/":
			expectedToken := fmt.Sprintf("token-%d", loginCount)
			assert.Equal(t, expectedToken, r.Header.Get("X-Auth-Token"))

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"return": [{"result": true}]}`))
		}
	}))
	defer server.Close()

	config := salt.ClientConfig{
		BaseURL:  server.URL,
		Username: "testuser",
		Password: "testpass",
		Logger:   zaptest.NewLogger(t),
	}

	client, err := salt.NewClient(config)
	require.NoError(t, err)

	// First command should use initial token
	cmd := salt.Command{
		Client:   "local",
		Target:   "*",
		Function: "test.ping",
	}

	_, err = client.ExecuteCommand(context.Background(), cmd)
	require.NoError(t, err)
	assert.Equal(t, 1, loginCount)

	// This is just a basic test - in real implementation you'd
	// need to expose token expiry for testing or use time mocking
}

func TestClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		serverHandler http.HandlerFunc
		wantErr       string
	}{
		{
			name: "authentication failure",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Invalid credentials"))
				}
			},
			wantErr: "authentication failed",
		},
		{
			name: "empty auth response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"return": []}`))
				}
			},
			wantErr: "authentication failed",
		},
		{
			name: "server error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := salt.ClientConfig{
				BaseURL:    server.URL,
				Username:   "testuser",
				Password:   "testpass",
				Logger:     zaptest.NewLogger(t),
				MaxRetries: 1, // Reduce retries for faster tests
			}

			_, err := salt.NewClient(config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}