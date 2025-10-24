// pkg/shared/consul_tokens.go
//
// Consul Token Management via Vault
//
// This module provides helpers for applications to request dynamic Consul tokens
// from Vault's Consul secrets engine. Part of Phase 1 implementation.
//
// Usage Pattern:
//   1. Application reads Vault token (from agent or AppRole)
//   2. Calls GetConsulTokenFromVault(rc, vaultClient, "eos-role")
//   3. Receives short-lived Consul token (default 1h TTL)
//   4. Uses token for Consul operations
//   5. Token automatically expires/revokes

package shared

import (
	"context"
	"fmt"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulTokenInfo contains information about a Consul token from Vault
type ConsulTokenInfo struct {
	Token         string        // The Consul ACL token
	Accessor      string        // Token accessor (for revocation)
	LeaseDuration time.Duration // Token TTL
	LeaseID       string        // Vault lease ID (for renewal/revocation)
	Renewable     bool          // Whether token can be renewed
}

// GetConsulTokenFromVault requests a dynamic Consul token from Vault
//
// Parameters:
//   - ctx: Context for logging and cancellation
//   - vaultClient: Authenticated Vault API client
//   - roleName: Vault role to use (e.g., "eos-role", "service-role")
//
// Returns:
//   - ConsulTokenInfo with token and metadata
//   - Error if token generation fails
//
// Example:
//
//	vaultClient, err := vault.GetAuthenticatedClient(ctx)
//	if err != nil {
//	    return fmt.Errorf("vault auth failed: %w", err)
//	}
//
//	consulTokenInfo, err := shared.GetConsulTokenFromVault(ctx, vaultClient, "eos-role")
//	if err != nil {
//	    return fmt.Errorf("consul token request failed: %w", err)
//	}
//
//	// Use consulTokenInfo.Token for Consul operations
//	consulClient := consul.NewClient(&consul.Config{Token: consulTokenInfo.Token})
func GetConsulTokenFromVault(ctx context.Context, vaultClient *vaultapi.Client, roleName string) (*ConsulTokenInfo, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Requesting dynamic Consul token from Vault",
		zap.String("role", roleName))

	// Request token from Vault Consul secrets engine
	path := fmt.Sprintf("consul/creds/%s", roleName)
	secret, err := vaultClient.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to request Consul token from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no token returned from Vault (path: %s) - is Consul secrets engine enabled and configured?", path)
	}

	// Extract token from response
	token, ok := secret.Data["token"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token format in Vault response")
	}

	accessor, _ := secret.Data["accessor"].(string)

	tokenInfo := &ConsulTokenInfo{
		Token:         token,
		Accessor:      accessor,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		LeaseID:       secret.LeaseID,
		Renewable:     secret.Renewable,
	}

	logger.Info("Consul token obtained from Vault",
		zap.String("role", roleName),
		zap.String("accessor", accessor),
		zap.Duration("ttl", tokenInfo.LeaseDuration),
		zap.Bool("renewable", tokenInfo.Renewable))

	return tokenInfo, nil
}

// RenewConsulToken renews a Consul token lease before it expires
//
// Parameters:
//   - ctx: Context for logging and cancellation
//   - vaultClient: Authenticated Vault API client
//   - leaseID: The lease ID from ConsulTokenInfo.LeaseID
//   - increment: Requested renewal duration (0 = use default)
//
// Returns:
//   - New lease duration
//   - Error if renewal fails
//
// Example:
//
//	// Renew token for another hour
//	newDuration, err := shared.RenewConsulToken(ctx, vaultClient, tokenInfo.LeaseID, time.Hour)
//	if err != nil {
//	    // Token may have expired, request new token
//	    tokenInfo, err = shared.GetConsulTokenFromVault(ctx, vaultClient, "eos-role")
//	}
func RenewConsulToken(ctx context.Context, vaultClient *vaultapi.Client, leaseID string, increment time.Duration) (time.Duration, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Renewing Consul token lease",
		zap.String("lease_id", leaseID),
		zap.Duration("increment", increment))

	incrementSecs := int(increment.Seconds())
	secret, err := vaultClient.Sys().Renew(leaseID, incrementSecs)
	if err != nil {
		return 0, fmt.Errorf("failed to renew Consul token lease: %w", err)
	}

	newDuration := time.Duration(secret.LeaseDuration) * time.Second

	logger.Info("Consul token lease renewed",
		zap.String("lease_id", leaseID),
		zap.Duration("new_duration", newDuration))

	return newDuration, nil
}

// RevokeConsulToken revokes a Consul token immediately
//
// Parameters:
//   - ctx: Context for logging
//   - vaultClient: Authenticated Vault API client
//   - leaseID: The lease ID from ConsulTokenInfo.LeaseID
//
// Example:
//
//	// Revoke token when no longer needed
//	if err := shared.RevokeConsulToken(ctx, vaultClient, tokenInfo.LeaseID); err != nil {
//	    logger.Warn("Failed to revoke Consul token", zap.Error(err))
//	}
func RevokeConsulToken(ctx context.Context, vaultClient *vaultapi.Client, leaseID string) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Revoking Consul token lease",
		zap.String("lease_id", leaseID))

	if err := vaultClient.Sys().Revoke(leaseID); err != nil {
		return fmt.Errorf("failed to revoke Consul token: %w", err)
	}

	logger.Info("Consul token revoked successfully",
		zap.String("lease_id", leaseID))

	return nil
}

// AutoRenewConsulToken automatically renews a Consul token before it expires
// This is a blocking function that runs until the context is canceled
//
// Parameters:
//   - ctx: Context for cancellation and logging
//   - vaultClient: Authenticated Vault API client
//   - tokenInfo: Initial token info
//   - onRenew: Callback when token is renewed (receives new token info)
//   - onError: Callback when renewal fails
//
// Example:
//
//	go shared.AutoRenewConsulToken(ctx, vaultClient, tokenInfo,
//	    func(newToken *shared.ConsulTokenInfo) {
//	        // Update Consul client with new token
//	        consulClient.SetToken(newToken.Token)
//	    },
//	    func(err error) {
//	        logger.Error("Token renewal failed", zap.Error(err))
//	        // Request new token or handle error
//	    },
//	)
func AutoRenewConsulToken(
	ctx context.Context,
	vaultClient *vaultapi.Client,
	tokenInfo *ConsulTokenInfo,
	onRenew func(*ConsulTokenInfo),
	onError func(error),
) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting automatic Consul token renewal",
		zap.String("lease_id", tokenInfo.LeaseID),
		zap.Duration("initial_ttl", tokenInfo.LeaseDuration))

	// Renew at 50% of TTL
	renewInterval := tokenInfo.LeaseDuration / 2

	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping token renewal (context canceled)")
			return

		case <-ticker.C:
			// Attempt renewal
			newDuration, err := RenewConsulToken(ctx, vaultClient, tokenInfo.LeaseID, 0)
			if err != nil {
				logger.Error("Failed to renew Consul token",
					zap.Error(err),
					zap.String("lease_id", tokenInfo.LeaseID))
				if onError != nil {
					onError(err)
				}
				return
			}

			// Update token info
			tokenInfo.LeaseDuration = newDuration

			// Calculate new renewal interval (50% of new TTL)
			renewInterval = newDuration / 2
			ticker.Reset(renewInterval)

			logger.Info("Consul token renewed automatically",
				zap.Duration("new_ttl", newDuration),
				zap.Duration("next_renewal_in", renewInterval))

			if onRenew != nil {
				onRenew(tokenInfo)
			}
		}
	}
}

// GetConsulTokenOrFallback attempts to get a Consul token from Vault, or falls back to env/config
//
// This helper is useful during migration when some systems use Vault tokens and others don't.
//
// Order of precedence:
//  1. Try Vault Consul secrets engine (if vaultClient provided)
//  2. Fall back to CONSUL_HTTP_TOKEN environment variable
//  3. Fall back to provided fallbackToken parameter
//  4. Return error if all methods fail
//
// Example:
//
//	token, source, err := shared.GetConsulTokenOrFallback(ctx, vaultClient, "eos-role", "")
//	if err != nil {
//	    return fmt.Errorf("no Consul token available: %w", err)
//	}
//	logger.Info("Using Consul token", zap.String("source", source))
func GetConsulTokenOrFallback(ctx context.Context, vaultClient *vaultapi.Client, roleName string, fallbackToken string) (string, string, error) {
	logger := otelzap.Ctx(ctx)

	// Try Vault first (if client provided)
	if vaultClient != nil {
		tokenInfo, err := GetConsulTokenFromVault(ctx, vaultClient, roleName)
		if err == nil {
			logger.Info("Using Consul token from Vault",
				zap.String("role", roleName),
				zap.Duration("ttl", tokenInfo.LeaseDuration))
			return tokenInfo.Token, "vault", nil
		}

		logger.Debug("Failed to get Consul token from Vault, trying fallback",
			zap.Error(err))
	}

	// Try environment variable
	if envToken := os.Getenv("CONSUL_HTTP_TOKEN"); envToken != "" {
		logger.Info("Using Consul token from environment variable")
		return envToken, "environment", nil
	}

	// Try fallback parameter
	if fallbackToken != "" {
		logger.Info("Using Consul token from configuration")
		return fallbackToken, "config", nil
	}

	return "", "", fmt.Errorf("no Consul token available (Vault: %v, Env: empty, Config: empty)",
		vaultClient != nil)
}
