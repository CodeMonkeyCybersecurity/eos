package unified

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Authenticate authenticates the client with Salt API
func (c *Client) Authenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	logger := c.logger.With(zap.String("method", "Authenticate"))
	logger.Debug("Authenticating with Salt API")
	
	// Only authenticate if using API mode
	if c.currentMode != ModeAPI {
		logger.Debug("Not in API mode, skipping authentication")
		return nil
	}
	
	if c.apiClient == nil {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "API client not initialized",
			Mode:    ModeAPI,
		}
	}
	
	// Get credentials
	username := c.config.Username
	password := c.config.Password
	
	// Try to load from file if not in config
	if password == "" {
		var err error
		username, password, err = LoadCredentialsFromFile(c.config.CredentialsPath)
		if err != nil {
			return &SaltError{
				Type:    ErrorTypeAuth,
				Message: fmt.Sprintf("Failed to load credentials: %s", err.Error()),
				Cause:   err,
				Mode:    ModeAPI,
			}
		}
	}
	
	// Attempt authentication
	c.stats.AuthAttempts++
	startTime := time.Now()
	
	token, err := c.apiClient.Login(ctx, username, password, c.config.EAuth)
	if err != nil {
		return &SaltError{
			Type:      ErrorTypeAuth,
			Message:   fmt.Sprintf("Authentication failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeAPI,
			Retryable: c.isRetryableError(err),
		}
	}
	
	// Update authentication info
	c.authInfo.Username = username
	c.authInfo.Password = password // Note: This is not logged
	c.authInfo.EAuth = c.config.EAuth
	c.authInfo.Token = token
	c.authInfo.TokenExpiry = time.Now().Add(12 * time.Hour) // Default Salt token expiry
	c.authInfo.Authenticated = true
	c.authInfo.LastAuth = time.Now()
	
	c.stats.AuthSuccesses++
	
	logger.Info("Authentication successful",
		zap.String("username", username),
		zap.String("eauth", c.config.EAuth),
		zap.Duration("duration", time.Since(startTime)))
	
	return nil
}

// RefreshToken refreshes the authentication token
func (c *Client) RefreshToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	logger := c.logger.With(zap.String("method", "RefreshToken"))
	logger.Debug("Refreshing authentication token")
	
	// Only refresh if using API mode
	if c.currentMode != ModeAPI {
		return nil
	}
	
	if c.apiClient == nil {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "API client not initialized",
			Mode:    ModeAPI,
		}
	}
	
	// Use existing credentials to get new token
	c.stats.AuthAttempts++
	startTime := time.Now()
	
	token, err := c.apiClient.Login(ctx, c.authInfo.Username, c.authInfo.Password, c.authInfo.EAuth)
	if err != nil {
		// Mark as not authenticated on failure
		c.authInfo.Authenticated = false
		
		return &SaltError{
			Type:      ErrorTypeAuth,
			Message:   fmt.Sprintf("Token refresh failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeAPI,
			Retryable: c.isRetryableError(err),
		}
	}
	
	// Update token info
	c.authInfo.Token = token
	c.authInfo.TokenExpiry = time.Now().Add(12 * time.Hour)
	c.authInfo.LastAuth = time.Now()
	c.stats.AuthSuccesses++
	
	logger.Debug("Token refreshed successfully",
		zap.Duration("duration", time.Since(startTime)))
	
	return nil
}

// IsAuthenticated checks if the client is currently authenticated
func (c *Client) IsAuthenticated(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// Local mode doesn't require authentication
	if c.currentMode == ModeLocal {
		return true
	}
	
	// API mode requires valid token
	if c.currentMode == ModeAPI {
		return c.authInfo.Authenticated && time.Now().Before(c.authInfo.TokenExpiry)
	}
	
	return false
}

// GetAuthInfo returns current authentication information
func (c *Client) GetAuthInfo(ctx context.Context) (*AuthenticationInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// Create a copy to avoid exposing sensitive data
	authCopy := &AuthenticationInfo{
		Username:      c.authInfo.Username,
		EAuth:         c.authInfo.EAuth,
		Authenticated: c.authInfo.Authenticated,
		LastAuth:      c.authInfo.LastAuth,
		TokenExpiry:   c.authInfo.TokenExpiry,
		// Note: We don't copy Password or Token for security
	}
	
	return authCopy, nil
}

// UpdateConfig updates the client configuration
func (c *Client) UpdateConfig(ctx context.Context, newConfig ClientConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	logger := c.logger.With(zap.String("method", "UpdateConfig"))
	logger.Info("Updating client configuration")
	
	// Validate new configuration
	if err := ValidateConfig(newConfig); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Check if authentication needs to be refreshed
	authChanged := c.config.APIURL != newConfig.APIURL ||
		c.config.Username != newConfig.Username ||
		c.config.Password != newConfig.Password ||
		c.config.EAuth != newConfig.EAuth
	
	// Update configuration
	oldMode := c.currentMode
	c.config = newConfig
	
	// Update logger if provided
	if newConfig.Logger != nil {
		c.logger = newConfig.Logger
	}
	
	// Re-determine execution mode if settings changed
	if availability := c.lastAvailability; availability != nil {
		c.currentMode = c.determineExecutionMode(availability)
	}
	
	// If mode changed or auth changed, reinitialize
	if oldMode != c.currentMode || authChanged {
		logger.Info("Configuration change requires reinitialization",
			zap.String("old_mode", oldMode.String()),
			zap.String("new_mode", c.currentMode.String()),
			zap.Bool("auth_changed", authChanged))
		
		// Clear authentication if it changed
		if authChanged {
			c.authInfo.Authenticated = false
			c.authInfo.Token = ""
		}
		
		// Reinitialize if needed
		if c.currentMode == ModeAPI {
			if err := c.initializeAPIClient(ctx); err != nil {
				logger.Warn("Failed to reinitialize API client after config update", zap.Error(err))
				c.currentMode = ModeLocal
			}
		}
	}
	
	logger.Info("Configuration updated successfully",
		zap.String("mode", c.currentMode.String()))
	
	return nil
}

// GetConfig returns the current configuration (without sensitive data)
func (c *Client) GetConfig() ClientConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// Create a copy without sensitive data
	configCopy := c.config
	configCopy.Password = "" // Don't expose password
	
	return configCopy
}

// ValidateConfig validates a client configuration
func (c *Client) ValidateConfig(ctx context.Context, config ClientConfig) error {
	return ValidateConfig(config)
}

// ClearAuthentication clears authentication state
func (c *Client) ClearAuthentication() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.authInfo.Authenticated = false
	c.authInfo.Token = ""
	c.authInfo.TokenExpiry = time.Time{}
	
	c.logger.Debug("Authentication state cleared")
}

// GetAuthenticationStatus returns detailed authentication status
func (c *Client) GetAuthenticationStatus(ctx context.Context) map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	status := map[string]interface{}{
		"mode":                c.currentMode.String(),
		"authenticated":       c.authInfo.Authenticated,
		"username":           c.authInfo.Username,
		"eauth":              c.authInfo.EAuth,
		"token_set":          c.authInfo.Token != "",
		"last_auth":          c.authInfo.LastAuth,
		"auth_attempts":      c.stats.AuthAttempts,
		"auth_successes":     c.stats.AuthSuccesses,
	}
	
	// Add token expiry info if authenticated
	if c.authInfo.Authenticated {
		status["token_expiry"] = c.authInfo.TokenExpiry
		status["token_expires_in"] = time.Until(c.authInfo.TokenExpiry).String()
		status["token_expired"] = time.Now().After(c.authInfo.TokenExpiry)
	}
	
	return status
}

// TestAuthentication tests authentication without storing the result
func (c *Client) TestAuthentication(ctx context.Context, username, password, eauth string) error {
	if c.currentMode != ModeAPI {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Cannot test authentication in non-API mode",
			Mode:    c.currentMode,
		}
	}
	
	if c.apiClient == nil {
		return &SaltError{
			Type:    ErrorTypeConfig,
			Message: "API client not initialized",
			Mode:    ModeAPI,
		}
	}
	
	// Test authentication without storing token
	_, err := c.apiClient.Login(ctx, username, password, eauth)
	if err != nil {
		return &SaltError{
			Type:      ErrorTypeAuth,
			Message:   fmt.Sprintf("Authentication test failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeAPI,
			Retryable: false, // Don't retry test operations
		}
	}
	
	return nil
}