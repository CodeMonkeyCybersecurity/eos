package unified

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Factory implements the ClientFactory interface
type Factory struct{}

// NewFactory creates a new client factory
func NewFactory() ClientFactory {
	return &Factory{}
}

// NewClient creates a new unified Salt client with the provided configuration
func (f *Factory) NewClient(config ClientConfig) (UnifiedSaltClient, error) {
	return NewClient(config)
}

// NewClientFromEnv creates a client using environment variables
func (f *Factory) NewClientFromEnv() (UnifiedSaltClient, error) {
	return NewClientFromEnv()
}

// NewClientWithDefaults creates a client with default configuration
func (f *Factory) NewClientWithDefaults() (UnifiedSaltClient, error) {
	return NewClientWithDefaults()
}

// Global factory instance for convenience
var DefaultFactory = NewFactory()

// Convenience functions using the default factory

// NewSaltClient creates a new Salt client with the provided configuration
func NewSaltClient(config ClientConfig) (UnifiedSaltClient, error) {
	return DefaultFactory.NewClient(config)
}

// NewSaltClientFromEnv creates a Salt client using environment variables
func NewSaltClientFromEnv() (UnifiedSaltClient, error) {
	return DefaultFactory.NewClientFromEnv()
}

// NewSaltClientWithDefaults creates a Salt client with default configuration
func NewSaltClientWithDefaults() (UnifiedSaltClient, error) {
	return DefaultFactory.NewClientWithDefaults()
}

// NewSaltClientForEOS creates a Salt client optimized for EOS usage
func NewSaltClientForEOS(logger *zap.Logger) (UnifiedSaltClient, error) {
	config := DefaultConfig()
	
	// EOS-specific optimizations
	config.PreferAPI = true
	config.FallbackToLocal = true
	config.Timeout = 5 * time.Minute
	config.MaxRetries = 3
	
	if logger != nil {
		config.Logger = logger
	}
	
	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create EOS Salt client: %w", err)
	}
	
	return client, nil
}

// SetupSaltForEOS performs a complete Salt setup for EOS
// This is a high-level function that ensures Salt is properly configured
func SetupSaltForEOS(ctx context.Context, logger *zap.Logger) (UnifiedSaltClient, error) {
	logger = logger.With(zap.String("operation", "SetupSaltForEOS"))
	logger.Info("Setting up Salt for EOS")
	
	// Create client
	client, err := NewSaltClientForEOS(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	
	// Initialize client
	config := DefaultConfig()
	if logger != nil {
		config.Logger = logger
	}
	
	if err := client.Initialize(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to initialize client: %w", err)
	}
	
	// Check current status
	status, err := client.GetStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}
	
	logger.Info("Initial Salt status",
		zap.String("mode", status.CurrentMode.String()),
		zap.Bool("healthy", status.Healthy))
	
	// If Salt is not available, install it
	if status.CurrentMode == ModeUnavailable {
		logger.Info("Salt not available, installing...")
		
		if err := client.EnsureSaltInstalled(ctx); err != nil {
			return nil, fmt.Errorf("failed to install Salt: %w", err)
		}
		
		// Re-initialize after installation
		if err := client.Initialize(ctx, config); err != nil {
			return nil, fmt.Errorf("failed to reinitialize after installation: %w", err)
		}
	}
	
	// If we want API mode but it's not available, try to set it up
	if config.PreferAPI && client.GetExecutionMode() == ModeLocal {
		logger.Info("API mode preferred but not available, attempting setup...")
		
		// Try to set up API mode
		if err := setupAPIMode(ctx, client, logger); err != nil {
			logger.Warn("Failed to setup API mode, continuing with local mode", zap.Error(err))
		} else {
			// Re-initialize to switch to API mode
			if err := client.Initialize(ctx, config); err != nil {
				logger.Warn("Failed to reinitialize for API mode", zap.Error(err))
			}
		}
	}
	
	// Verify final setup
	finalStatus, err := client.GetStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get final status: %w", err)
	}
	
	logger.Info("Salt setup completed",
		zap.String("mode", finalStatus.CurrentMode.String()),
		zap.Bool("healthy", finalStatus.Healthy),
		zap.Bool("api_available", finalStatus.Availability.APIConnectable))
	
	return client, nil
}

// setupAPIMode attempts to set up Salt API mode
func setupAPIMode(ctx context.Context, client UnifiedSaltClient, logger *zap.Logger) error {
	logger.Info("Setting up Salt API mode")
	
	// Ensure Salt API is configured
	if err := client.EnsureSaltAPIConfigured(ctx); err != nil {
		return fmt.Errorf("failed to configure Salt API: %w", err)
	}
	
	// Ensure credentials are configured
	if err := client.EnsureCredentialsConfigured(ctx); err != nil {
		return fmt.Errorf("failed to configure credentials: %w", err)
	}
	
	// Ensure Salt API service is running
	if err := client.EnsureSaltAPIRunning(ctx); err != nil {
		return fmt.Errorf("failed to start Salt API service: %w", err)
	}
	
	logger.Info("Salt API mode setup completed")
	return nil
}

// QuickSaltClient creates a client for quick operations
// This is useful for simple operations where you don't need full setup
func QuickSaltClient(ctx context.Context) (UnifiedSaltClient, error) {
	client, err := NewSaltClientWithDefaults()
	if err != nil {
		return nil, err
	}
	
	// Quick initialization - prefer local mode for speed
	config := DefaultConfig()
	config.PreferAPI = false
	config.FallbackToLocal = true
	config.Timeout = 30 * time.Second
	
	if err := client.Initialize(ctx, config); err != nil {
		return nil, err
	}
	
	return client, nil
}

// GetSaltClientForCommand creates a client optimized for command execution
func GetSaltClientForCommand(ctx context.Context, preferAPI bool) (UnifiedSaltClient, error) {
	config := DefaultConfig()
	config.PreferAPI = preferAPI
	config.FallbackToLocal = true
	config.Timeout = 2 * time.Minute
	config.MaxRetries = 2
	
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	
	if err := client.Initialize(ctx, config); err != nil {
		return nil, err
	}
	
	return client, nil
}

// GetSaltClientForState creates a client optimized for state execution
func GetSaltClientForState(ctx context.Context, preferAPI bool) (UnifiedSaltClient, error) {
	config := DefaultConfig()
	config.PreferAPI = preferAPI
	config.FallbackToLocal = true
	config.Timeout = 10 * time.Minute
	config.MaxRetries = 1 // States are usually not retryable
	
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	
	if err := client.Initialize(ctx, config); err != nil {
		return nil, err
	}
	
	return client, nil
}

// ValidateEnvironment checks if the environment is suitable for Salt operations
func ValidateEnvironment(ctx context.Context) (map[string]interface{}, error) {
	client, err := QuickSaltClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()
	
	// Check availability
	availability, err := client.CheckAvailability(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check availability: %w", err)
	}
	
	validation := map[string]interface{}{
		"salt_available":           availability.SaltCallAvailable || availability.SaltBinaryAvailable,
		"salt_api_available":      availability.APIConnectable,
		"recommended_mode":        availability.RecommendedMode.String(),
		"issues":                  availability.Issues,
		"can_execute_commands":    availability.SaltCallAvailable,
		"can_execute_states":      availability.SaltCallAvailable,
		"can_use_api":            availability.APIConnectable && availability.APIAuthenticated,
	}
	
	// Test basic functionality
	if availability.SaltCallAvailable {
		ping, err := client.Ping(ctx, "local")
		validation["ping_test"] = ping
		validation["ping_error"] = err != nil
		if err != nil {
			validation["ping_error_message"] = err.Error()
		}
	}
	
	return validation, nil
}