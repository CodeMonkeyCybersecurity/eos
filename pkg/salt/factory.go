package salt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ClientFactory creates the appropriate Salt client based on configuration
type ClientFactory struct {
	rc *eos_io.RuntimeContext
}

// NewClientFactory creates a new client factory
func NewClientFactory(rc *eos_io.RuntimeContext) *ClientFactory {
	return &ClientFactory{rc: rc}
}

// CreateClient creates the appropriate Salt client
// This is the main entry point that should be used throughout the codebase
func (f *ClientFactory) CreateClient() (SaltClient, error) {
	logger := otelzap.Ctx(f.rc.Ctx)
	
	// Check for API configuration
	apiURL := os.Getenv("SALT_API_URL")
	apiUser := os.Getenv("SALT_API_USER")
	apiPass := os.Getenv("SALT_API_PASSWORD")
	
	// If API is not configured, return error
	if apiURL == "" || apiUser == "" || apiPass == "" {
		logger.Error("Salt API configuration missing",
			zap.Bool("has_url", apiURL != ""),
			zap.Bool("has_user", apiUser != ""),
			zap.Bool("has_pass", apiPass != ""))
		
		return nil, fmt.Errorf("Salt API not configured. Please set SALT_API_URL, SALT_API_USER, and SALT_API_PASSWORD")
	}
	
	// Create API client configuration
	config := ClientConfig{
		BaseURL:            apiURL,
		Username:           apiUser,
		Password:           apiPass,
		EAuth:              getEnvOrDefault("SALT_API_EAUTH", "pam"),
		Timeout:            10 * time.Minute,
		MaxRetries:         3,
		InsecureSkipVerify: os.Getenv("SALT_API_INSECURE") == "true",
		Logger:             logger.ZapLogger(),
	}
	
	// Try to create API client
	apiClient, err := NewAPIClient(f.rc, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Salt API client: %w", err)
	}
	
	// Verify the API is working
	if err := apiClient.CheckStatus(f.rc.Ctx); err != nil {
		return nil, fmt.Errorf("Salt API is not responding: %w", err)
	}
	
	logger.Info("Successfully connected to Salt API",
		zap.String("url", apiURL))
	
	return apiClient, nil
}

// CreateMigrationClient creates a client that can fall back to CLI
// This should only be used during the migration period
func (f *ClientFactory) CreateMigrationClient() *MigrationClient {
	return NewMigrationClient(f.rc)
}

// SaltClient is the unified interface for all Salt operations
type SaltClient interface {
	// State operations
	StateApplyLocal(ctx context.Context, state string, pillar map[string]interface{}) (*StateResult, error)
	ExecuteStateApply(ctx context.Context, state string, pillar map[string]interface{}, progress func(StateProgress)) (*StateResult, error)
	HighstateApply(ctx context.Context, target string, progress func(StateProgress)) (*StateResult, error)
	
	// Command execution
	ExecuteCommand(ctx context.Context, cmd Command) (*CommandResult, error)
	CmdRunLocal(ctx context.Context, command string) (string, error)
	
	// Key management
	ListKeys(ctx context.Context) (*KeyList, error)
	AcceptKey(ctx context.Context, minion string) error
	DeleteKey(ctx context.Context, minion string) error
	RejectKey(ctx context.Context, minion string) error
	
	// Service management
	ServiceManage(ctx context.Context, target, service, action string) error
	
	// Package management
	PkgInstall(ctx context.Context, target string, packages []string) error
	
	// File management
	FileManage(ctx context.Context, target, path, contents string, mode string) error
	
	// Minion operations
	TestPing(ctx context.Context, target string) (map[string]bool, error)
	GetGrains(ctx context.Context, target string, grains []string) (map[string]interface{}, error)
	ManageUp(ctx context.Context) ([]string, error)
	ManageDown(ctx context.Context) ([]string, error)
	
	// Job management
	JobsActive(ctx context.Context) (map[string]JobInfo, error)
	
	// Runner operations
	RunnerExecute(ctx context.Context, function string, args map[string]interface{}) (*CommandResult, error)
	
	// Status check
	CheckStatus(ctx context.Context) error
}

// Helper functions

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}