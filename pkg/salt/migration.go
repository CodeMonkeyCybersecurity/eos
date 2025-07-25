package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MigrationClient provides a transitional interface that attempts API first, then falls back
// This should be replaced with APIClient once the API is fully operational
type MigrationClient struct {
	apiClient *APIClient
	logger    otelzap.LoggerWithCtx
	rc        *eos_io.RuntimeContext
}

// NewMigrationClient creates a client that prefers API but can fall back
func NewMigrationClient(rc *eos_io.RuntimeContext) *MigrationClient {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try to create API client
	config := ClientConfig{
		BaseURL:            os.Getenv("SALT_API_URL"),
		Username:           os.Getenv("SALT_API_USER"),
		Password:           os.Getenv("SALT_API_PASSWORD"),
		EAuth:              "pam",
		Timeout:            10 * time.Minute,
		InsecureSkipVerify: os.Getenv("SALT_API_INSECURE") == "true",
		Logger:             logger.ZapLogger(),
	}
	
	var apiClient *APIClient
	if config.BaseURL != "" && config.Username != "" && config.Password != "" {
		client, err := NewAPIClient(rc, config)
		if err != nil {
			logger.Warn("Failed to create Salt API client",
				zap.Error(err))
		} else {
			apiClient = client
		}
	}
	
	return &MigrationClient{
		apiClient: apiClient,
		logger:    logger,
		rc:        rc,
	}
}

// IsAPIAvailable checks if the API is available
func (m *MigrationClient) IsAPIAvailable() bool {
	if m.apiClient == nil {
		return false
	}
	
	// Try a simple ping to verify API works
	ctx, cancel := context.WithTimeout(m.rc.Ctx, 5*time.Second)
	defer cancel()
	
	if err := m.apiClient.CheckStatus(ctx); err != nil {
		m.logger.Debug("Salt API not available",
			zap.Error(err))
		return false
	}
	
	return true
}

// StateApply applies a state with automatic fallback
func (m *MigrationClient) StateApply(ctx context.Context, target, state string, pillar map[string]interface{}) error {
	if m.IsAPIAvailable() {
		m.logger.Debug("Using Salt API for state.apply")
		_, err := m.apiClient.ExecuteStateApply(ctx, state, pillar, nil)
		return err
	}
	
	// Fallback to salt-call
	m.logger.Debug("Falling back to salt-call for state.apply")
	return m.fallbackStateApply(ctx, state, pillar)
}

// CmdRun runs a command with automatic fallback
func (m *MigrationClient) CmdRun(ctx context.Context, target, command string) (string, error) {
	if m.IsAPIAvailable() {
		m.logger.Debug("Using Salt API for cmd.run")
		cmd := Command{
			Client:   "local",
			Target:   target,
			Function: "cmd.run",
			Args:     []string{command},
		}
		
		result, err := m.apiClient.ExecuteCommand(ctx, cmd)
		if err != nil {
			return "", err
		}
		
		// Extract first result
		for _, output := range result.Raw {
			if str, ok := output.(string); ok {
				return str, nil
			}
		}
		
		return "", fmt.Errorf("no output received")
	}
	
	// Fallback to salt-call
	m.logger.Debug("Falling back to salt-call for cmd.run")
	return m.fallbackCmdRun(ctx, command)
}

// ListKeys lists Salt keys with automatic fallback
func (m *MigrationClient) ListKeys(ctx context.Context) (*KeyList, error) {
	if m.IsAPIAvailable() {
		m.logger.Debug("Using Salt API for key.list")
		return m.apiClient.ListKeys(ctx)
	}
	
	// Fallback to salt-key
	m.logger.Debug("Falling back to salt-key for key listing")
	return m.fallbackListKeys(ctx)
}

// AcceptKey accepts a key with automatic fallback
func (m *MigrationClient) AcceptKey(ctx context.Context, minion string) error {
	if m.IsAPIAvailable() {
		m.logger.Debug("Using Salt API for key.accept")
		return m.apiClient.AcceptKey(ctx, minion)
	}
	
	// Fallback to salt-key
	m.logger.Debug("Falling back to salt-key for key acceptance")
	return m.fallbackAcceptKey(ctx, minion)
}

// Fallback implementations

func (m *MigrationClient) fallbackStateApply(ctx context.Context, state string, pillar map[string]interface{}) error {
	args := []string{"--local", "state.apply", state}
	
	if len(pillar) > 0 {
		pillarJSON, err := json.Marshal(pillar)
		if err != nil {
			return fmt.Errorf("failed to marshal pillar: %w", err)
		}
		args = append(args, fmt.Sprintf("pillar=%s", string(pillarJSON)))
	}
	
	cmd := exec.CommandContext(ctx, "salt-call", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Error("salt-call failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("salt-call failed: %w", err)
	}
	
	return nil
}

func (m *MigrationClient) fallbackCmdRun(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "salt-call", "--local", "cmd.run", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("salt-call failed: %w", err)
	}
	
	return string(output), nil
}

func (m *MigrationClient) fallbackListKeys(ctx context.Context) (*KeyList, error) {
	cmd := exec.CommandContext(ctx, "salt-key", "-L", "--out=json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("salt-key failed: %w", err)
	}
	
	// Parse JSON output
	var result struct {
		Minions         []string `json:"minions"`
		MinionsPre      []string `json:"minions_pre"`
		MinionsRejected []string `json:"minions_rejected"`
		MinionsDenied   []string `json:"minions_denied"`
	}
	
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse salt-key output: %w", err)
	}
	
	return &KeyList{
		Minions:         result.Minions,
		MinionsPre:      result.MinionsPre,
		MinionsRejected: result.MinionsRejected,
		MinionsDenied:   result.MinionsDenied,
	}, nil
}

func (m *MigrationClient) fallbackAcceptKey(ctx context.Context, minion string) error {
	cmd := exec.CommandContext(ctx, "salt-key", "-a", minion, "-y")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("salt-key accept failed: %w", err)
	}
	
	return nil
}

// GetAPIClient returns the underlying API client if available
func (m *MigrationClient) GetAPIClient() *APIClient {
	return m.apiClient
}

// ForceAPI returns an error if API is not available, useful for testing
func (m *MigrationClient) ForceAPI() error {
	if !m.IsAPIAvailable() {
		return fmt.Errorf("Salt API is not available")
	}
	return nil
}