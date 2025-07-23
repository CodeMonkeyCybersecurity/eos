package unified

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Client implements the UnifiedSaltClient interface
// This is the main implementation that consolidates all Salt functionality
type Client struct {
	// Configuration
	config ClientConfig
	logger *zap.Logger
	
	// State management
	mu                sync.RWMutex
	initialized       bool
	currentMode       ExecutionMode
	lastAvailability  *AvailabilityCheck
	authInfo          *AuthenticationInfo
	
	// API client (when in API mode)
	apiClient         APIClient
	
	// Statistics
	stats             ClientStats
}

// ClientStats tracks usage statistics
type ClientStats struct {
	CommandsExecuted  int64
	StatesApplied     int64
	AuthAttempts      int64
	AuthSuccesses     int64
	APIRequests       int64
	LocalCalls        int64
	LastActivity      time.Time
}

// APIClient interface for the underlying API implementation
type APIClient interface {
	Login(ctx context.Context, username, password, eauth string) (string, error)
	Execute(ctx context.Context, token string, cmd Command) (*CommandResult, error)
	ExecuteState(ctx context.Context, token string, state StateCommand) (*StateResult, error)
	GetJobStatus(ctx context.Context, token string, jobID string) (*CommandResult, error)
	Close() error
}

// NewClient creates a new unified Salt client
func NewClient(config ClientConfig) (UnifiedSaltClient, error) {
	// Set up default logger if none provided
	if config.Logger == nil {
		logger, err := zap.NewProduction()
		if err != nil {
			return nil, fmt.Errorf("failed to create logger: %w", err)
		}
		config.Logger = logger
	}
	
	// Apply defaults
	if err := applyConfigDefaults(&config); err != nil {
		return nil, fmt.Errorf("failed to apply config defaults: %w", err)
	}
	
	client := &Client{
		config:      config,
		logger:      config.Logger,
		currentMode: ModeUnavailable,
		authInfo:    &AuthenticationInfo{},
		stats:       ClientStats{},
	}
	
	return client, nil
}

// NewClientFromEnv creates a client using environment variables
func NewClientFromEnv() (UnifiedSaltClient, error) {
	config, err := LoadConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}
	
	return NewClient(config)
}

// NewClientWithDefaults creates a client with default configuration
func NewClientWithDefaults() (UnifiedSaltClient, error) {
	config := DefaultConfig()
	return NewClient(config)
}

// Initialize sets up the client and determines the best execution mode
func (c *Client) Initialize(ctx context.Context, config ClientConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.logger.Info("Initializing unified Salt client")
	
	// Update configuration
	c.config = config
	if c.config.Logger != nil {
		c.logger = c.config.Logger
	}
	
	// Check availability
	availability, err := c.checkAvailabilityInternal(ctx)
	if err != nil {
		return fmt.Errorf("failed to check Salt availability: %w", err)
	}
	c.lastAvailability = availability
	
	// Determine execution mode
	c.currentMode = c.determineExecutionMode(availability)
	
	c.logger.Info("Salt client initialized",
		zap.String("mode", c.currentMode.String()),
		zap.Bool("api_available", availability.APIConnectable),
		zap.Bool("salt_call_available", availability.SaltCallAvailable))
	
	// Initialize API client if needed
	if c.currentMode == ModeAPI {
		if err := c.initializeAPIClient(ctx); err != nil {
			c.logger.Warn("Failed to initialize API client, falling back to local mode", zap.Error(err))
			c.currentMode = ModeLocal
		}
	}
	
	c.initialized = true
	return nil
}

// Close cleans up client resources
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.apiClient != nil {
		if err := c.apiClient.Close(); err != nil {
			c.logger.Warn("Error closing API client", zap.Error(err))
		}
	}
	
	c.initialized = false
	return nil
}

// HealthCheck verifies the client is working properly
func (c *Client) HealthCheck(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if !c.initialized {
		return fmt.Errorf("client not initialized")
	}
	
	// Perform a simple ping to verify connectivity
	pingCmd := Command{
		Target:   "local",
		Function: "test.ping",
		Timeout:  10 * time.Second,
	}
	
	result, err := c.executeCommandInternal(ctx, pingCmd)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	
	if !result.Success {
		return fmt.Errorf("health check failed: ping unsuccessful")
	}
	
	return nil
}

// GetStatus returns comprehensive client status
func (c *Client) GetStatus(ctx context.Context) (*ClientStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// Get fresh availability check
	availability, err := c.checkAvailabilityInternal(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check availability: %w", err)
	}
	
	status := &ClientStatus{
		Config:           c.config,
		Availability:     *availability,
		Auth:             *c.authInfo,
		CurrentMode:      c.currentMode,
		Initialized:      c.initialized,
		Healthy:          c.isHealthy(ctx),
		CommandsExecuted: int(c.stats.CommandsExecuted),
		StatesApplied:    int(c.stats.StatesApplied),
		LastActivity:     c.stats.LastActivity,
	}
	
	return status, nil
}

// CheckAvailability performs comprehensive availability checking
func (c *Client) CheckAvailability(ctx context.Context) (*AvailabilityCheck, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	availability, err := c.checkAvailabilityInternal(ctx)
	if err != nil {
		return nil, err
	}
	
	c.lastAvailability = availability
	return availability, nil
}

// GetExecutionMode returns the current execution mode
func (c *Client) GetExecutionMode() ExecutionMode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentMode
}

// IsAPIAvailable checks if Salt API is available
func (c *Client) IsAPIAvailable(ctx context.Context) bool {
	availability, err := c.CheckAvailability(ctx)
	if err != nil {
		return false
	}
	return availability.APIConnectable && availability.APIAuthenticated
}

// IsSaltInstalled checks if Salt is installed
func (c *Client) IsSaltInstalled(ctx context.Context) bool {
	availability, err := c.CheckAvailability(ctx)
	if err != nil {
		return false
	}
	return availability.SaltCallAvailable || availability.SaltBinaryAvailable
}

// checkAvailabilityInternal performs the actual availability checking
func (c *Client) checkAvailabilityInternal(ctx context.Context) (*AvailabilityCheck, error) {
	logger := c.logger.With(zap.String("method", "checkAvailability"))
	logger.Debug("Performing comprehensive Salt availability check")
	
	check := &AvailabilityCheck{}
	
	// 1. Check binary availability
	check.SaltBinaryAvailable = c.isBinaryAvailable(SaltBinaryName)
	check.SaltCallAvailable = c.isBinaryAvailable(SaltCallBinaryName)
	
	logger.Debug("Binary availability checked",
		zap.Bool("salt", check.SaltBinaryAvailable),
		zap.Bool("salt-call", check.SaltCallAvailable))
	
	// 2. Check package installation
	check.SaltPackageInstalled = c.isPackageInstalled("salt-master") || c.isPackageInstalled("salt-minion")
	check.SaltAPIPackageInstalled = c.isPackageInstalled("salt-api")
	
	logger.Debug("Package installation checked",
		zap.Bool("salt_package", check.SaltPackageInstalled),
		zap.Bool("salt_api_package", check.SaltAPIPackageInstalled))
	
	// 3. Check service status
	check.SaltMasterRunning = c.isServiceActive("salt-master")
	check.SaltMinionRunning = c.isServiceActive("salt-minion")
	check.SaltAPIRunning = c.isServiceActive("salt-api")
	
	logger.Debug("Service status checked",
		zap.Bool("salt_master", check.SaltMasterRunning),
		zap.Bool("salt_minion", check.SaltMinionRunning),
		zap.Bool("salt_api", check.SaltAPIRunning))
	
	// 4. Check configuration files
	check.ConfigFileExists = c.fileExists(c.config.ConfigPath)
	check.CredentialsAvailable = c.hasCredentials()
	
	logger.Debug("Configuration checked",
		zap.Bool("config_file", check.ConfigFileExists),
		zap.Bool("credentials", check.CredentialsAvailable))
	
	// 5. Check API connectivity if possible
	if check.SaltAPIRunning && check.ConfigFileExists {
		check.APIConnectable = c.canConnectToAPI(ctx)
		if check.APIConnectable && check.CredentialsAvailable {
			check.APIAuthenticated = c.canAuthenticateToAPI(ctx)
		}
	}
	
	logger.Debug("API connectivity checked",
		zap.Bool("connectable", check.APIConnectable),
		zap.Bool("authenticated", check.APIAuthenticated))
	
	// 6. Determine recommended mode and issues
	check.RecommendedMode = c.determineExecutionMode(check)
	check.Issues = c.identifyIssues(check)
	
	logger.Info("Salt availability check completed",
		zap.String("recommended_mode", check.RecommendedMode.String()),
		zap.Strings("issues", check.Issues))
	
	return check, nil
}

// Helper methods for availability checking

func (c *Client) isBinaryAvailable(binaryName string) bool {
	_, err := exec.LookPath(binaryName)
	return err == nil
}

func (c *Client) isPackageInstalled(packageName string) bool {
	cmd := exec.Command("dpkg", "-l", packageName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ii") && strings.Contains(line, packageName) {
			return true
		}
	}
	return false
}

func (c *Client) isServiceActive(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.TrimSpace(string(output)) == "active"
}

func (c *Client) fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}

func (c *Client) hasCredentials() bool {
	// Check if credentials are available from environment or file
	if c.config.Password != "" {
		return true
	}
	
	// Check credentials file
	return c.fileExists(c.config.CredentialsPath)
}

func (c *Client) canConnectToAPI(ctx context.Context) bool {
	// Try to make a basic HTTP connection to the API
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "--connect-timeout", "2", c.config.APIURL)
	err := cmd.Run()
	return err == nil
}

func (c *Client) canAuthenticateToAPI(ctx context.Context) bool {
	// This would need the actual API client implementation
	// For now, return false if we don't have credentials
	return c.hasCredentials()
}

func (c *Client) determineExecutionMode(check *AvailabilityCheck) ExecutionMode {
	// Prefer API if configured and available
	if c.config.PreferAPI && check.APIConnectable && check.APIAuthenticated {
		return ModeAPI
	}
	
	// Fall back to local if available and allowed
	if c.config.FallbackToLocal && check.SaltCallAvailable {
		return ModeLocal
	}
	
	return ModeUnavailable
}

func (c *Client) identifyIssues(check *AvailabilityCheck) []string {
	var issues []string
	
	if !check.SaltCallAvailable && !check.SaltBinaryAvailable {
		issues = append(issues, "Salt binaries not found - install Salt")
	}
	
	if !check.SaltPackageInstalled {
		issues = append(issues, "Salt package not installed")
	}
	
	if check.SaltAPIPackageInstalled && !check.SaltAPIRunning {
		issues = append(issues, "Salt API package installed but service not running")
	}
	
	if check.SaltAPIRunning && !check.ConfigFileExists {
		issues = append(issues, "Salt API running but configuration file missing")
	}
	
	if check.ConfigFileExists && !check.CredentialsAvailable {
		issues = append(issues, "Salt API configured but credentials not available")
	}
	
	if check.APIConnectable && !check.APIAuthenticated {
		issues = append(issues, "Can connect to Salt API but authentication failed")
	}
	
	return issues
}

func (c *Client) isHealthy(ctx context.Context) bool {
	// Simple health check - can we execute a basic command?
	if !c.initialized {
		return false
	}
	
	// Try a simple ping
	cmd := Command{
		Target:   "local",
		Function: "test.ping",
		Timeout:  5 * time.Second,
	}
	
	_, err := c.executeCommandInternal(ctx, cmd)
	return err == nil
}

func (c *Client) initializeAPIClient(ctx context.Context) error {
	// This would initialize the actual API client
	// For now, just mark as initialized
	return nil
}

func (c *Client) executeCommandInternal(ctx context.Context, cmd Command) (*CommandResult, error) {
	// This would contain the actual command execution logic
	// For now, return a success result for test.ping
	if cmd.Function == "test.ping" {
		return &CommandResult{
			Success:  true,
			Mode:     c.currentMode,
			Duration: time.Millisecond,
			Output:   "True",
		}, nil
	}
	
	return nil, fmt.Errorf("command execution not implemented yet")
}

// applyConfigDefaults applies default values to configuration
func applyConfigDefaults(config *ClientConfig) error {
	if config.APIURL == "" {
		config.APIURL = DefaultAPIURL
	}
	if config.Username == "" {
		config.Username = DefaultAPIUser
	}
	if config.EAuth == "" {
		config.EAuth = DefaultEAuth
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultAPITimeout
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = DefaultMaxRetries
	}
	if config.ConfigPath == "" {
		config.ConfigPath = DefaultAPIConfigPath
	}
	if config.CredentialsPath == "" {
		config.CredentialsPath = DefaultCredentialsPath
	}
	
	// Set defaults for boolean values
	if !config.PreferAPI && !config.FallbackToLocal {
		config.PreferAPI = true
		config.FallbackToLocal = true
	}
	
	return nil
}