// Package vault provides infrastructure implementations for vault domain interfaces
package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"

)

// VaultAuthProvider implements vault.VaultAuthenticator
type VaultAuthProvider struct {
	client *api.Client
	logger *zap.Logger
}

// NewVaultAuthProvider creates a new vault authentication provider
func NewVaultAuthProvider(client *api.Client, logger *zap.Logger) *VaultAuthProvider {
	return &VaultAuthProvider{
		client: client,
		logger: logger.Named("vault.auth"),
	}
}

// Authenticate performs user authentication using various methods
func (v *VaultAuthProvider) Authenticate(ctx context.Context, method string, credentials map[string]string) (*vault.AuthResult, error) {
	v.logger.Info("Performing vault authentication",
		zap.String("method", method),
		zap.String("user", credentials["username"]))

	switch method {
	case "userpass":
		return v.authenticateUserpass(ctx, credentials)
	case "approle":
		return v.authenticateAppRole(ctx, credentials)
	default:
		err := fmt.Errorf("unsupported authentication method: %s", method)
		v.logger.Error("Authentication failed", zap.Error(err))
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
			Method:       method,
		}, err
	}
}

// authenticateUserpass handles userpass authentication
func (v *VaultAuthProvider) authenticateUserpass(ctx context.Context, credentials map[string]string) (*vault.AuthResult, error) {
	username, ok := credentials["username"]
	if !ok {
		return nil, fmt.Errorf("username is required for userpass authentication")
	}

	password, ok := credentials["password"]
	if !ok {
		return nil, fmt.Errorf("password is required for userpass authentication")
	}

	// Prepare auth data
	authData := map[string]interface{}{
		"password": password,
	}

	// Perform authentication
	path := fmt.Sprintf("auth/userpass/login/%s", username)
	secret, err := v.client.Logical().WriteWithContext(ctx, path, authData)
	if err != nil {
		v.logger.Error("Userpass authentication failed",
			zap.String("username", username),
			zap.Error(err))
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
			Method:       "userpass",
		}, err
	}

	if secret == nil || secret.Auth == nil {
		err := fmt.Errorf("no authentication data returned")
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
			Method:       "userpass",
		}, err
	}

	// Set the token for future requests
	v.client.SetToken(secret.Auth.ClientToken)

	v.logger.Info("Userpass authentication successful",
		zap.String("username", username),
		zap.Duration("token_ttl", time.Duration(secret.Auth.LeaseDuration)*time.Second))

	return &vault.AuthResult{
		Success:   true,
		Token:     secret.Auth.ClientToken,
		TokenTTL:  time.Duration(secret.Auth.LeaseDuration) * time.Second,
		Renewable: secret.Auth.Renewable,
		Policies:  secret.Auth.Policies,
		Metadata:  secret.Auth.Metadata,
		Timestamp: time.Now(),
		Method:    "userpass",
	}, nil
}

// authenticateAppRole handles approle authentication
func (v *VaultAuthProvider) authenticateAppRole(ctx context.Context, credentials map[string]string) (*vault.AuthResult, error) {
	roleID, ok := credentials["role_id"]
	if !ok {
		return nil, fmt.Errorf("role_id is required for approle authentication")
	}

	secretID, ok := credentials["secret_id"]
	if !ok {
		return nil, fmt.Errorf("secret_id is required for approle authentication")
	}

	// Prepare auth data
	authData := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	// Perform authentication
	secret, err := v.client.Logical().WriteWithContext(ctx, "auth/approle/login", authData)
	if err != nil {
		v.logger.Error("AppRole authentication failed",
			zap.String("role_id", roleID),
			zap.Error(err))
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
			Method:       "approle",
		}, err
	}

	if secret == nil || secret.Auth == nil {
		err := fmt.Errorf("no authentication data returned")
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
			Method:       "approle",
		}, err
	}

	// Set the token for future requests
	v.client.SetToken(secret.Auth.ClientToken)

	v.logger.Info("AppRole authentication successful",
		zap.String("role_id", roleID),
		zap.Duration("token_ttl", time.Duration(secret.Auth.LeaseDuration)*time.Second))

	return &vault.AuthResult{
		Success:   true,
		Token:     secret.Auth.ClientToken,
		TokenTTL:  time.Duration(secret.Auth.LeaseDuration) * time.Second,
		Renewable: secret.Auth.Renewable,
		Policies:  secret.Auth.Policies,
		Metadata:  secret.Auth.Metadata,
		Timestamp: time.Now(),
		Method:    "approle",
	}, nil
}

// GetAuthStatus returns current authentication status
func (v *VaultAuthProvider) GetAuthStatus(ctx context.Context) (*vault.AuthStatus, error) {
	if v.client.Token() == "" {
		return &vault.AuthStatus{
			Authenticated: false,
		}, nil
	}

	// Verify token by looking up self
	secret, err := v.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		v.logger.Warn("Token lookup failed", zap.Error(err))
		return &vault.AuthStatus{
			Authenticated: false,
		}, nil
	}

	if secret == nil || secret.Data == nil {
		return &vault.AuthStatus{
			Authenticated: false,
		}, nil
	}

	// Parse token information
	var tokenExpiry *time.Time
	if ttl, ok := secret.Data["ttl"].(int64); ok && ttl > 0 {
		expiry := time.Now().Add(time.Duration(ttl) * time.Second)
		tokenExpiry = &expiry
	}

	var policies []string
	if policiesData, ok := secret.Data["policies"].([]interface{}); ok {
		for _, p := range policiesData {
			if policy, ok := p.(string); ok {
				policies = append(policies, policy)
			}
		}
	}

	var metadata map[string]string
	if metaData, ok := secret.Data["meta"].(map[string]interface{}); ok {
		metadata = make(map[string]string)
		for k, v := range metaData {
			if str, ok := v.(string); ok {
				metadata[k] = str
			}
		}
	}

	var displayName string
	if name, ok := secret.Data["display_name"].(string); ok {
		displayName = name
	}

	return &vault.AuthStatus{
		Authenticated: true,
		UserID:        displayName,
		Policies:      policies,
		TokenExpiry:   tokenExpiry,
		Metadata:      metadata,
	}, nil
}

// RefreshToken refreshes the current authentication token
func (v *VaultAuthProvider) RefreshToken(ctx context.Context) (*vault.AuthResult, error) {
	if v.client.Token() == "" {
		return nil, fmt.Errorf("no token to refresh")
	}

	// Attempt to renew the token
	secret, err := v.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		v.logger.Error("Token refresh failed", zap.Error(err))
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
		}, err
	}

	if secret == nil || secret.Auth == nil {
		err := fmt.Errorf("no auth data returned from token refresh")
		return &vault.AuthResult{
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
		}, err
	}

	v.logger.Info("Token refreshed successfully",
		zap.Duration("new_ttl", time.Duration(secret.Auth.LeaseDuration)*time.Second))

	return &vault.AuthResult{
		Success:   true,
		Token:     secret.Auth.ClientToken,
		TokenTTL:  time.Duration(secret.Auth.LeaseDuration) * time.Second,
		Renewable: secret.Auth.Renewable,
		Policies:  secret.Auth.Policies,
		Metadata:  secret.Auth.Metadata,
		Timestamp: time.Now(),
	}, nil
}
