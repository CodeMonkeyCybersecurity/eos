// pkg/vault/rate_limit.go
package vault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// SECURITY: Rate limiting for Vault operations prevents brute force attacks
// - Unseal operations: 5 attempts per minute (prevents key guessing)
// - Init operations: 3 attempts per minute (prevents initialization spam)
// - Auth operations: 10 attempts per minute (prevents credential stuffing)

var (
	// Global rate limiters for different Vault operation types
	unsealLimiter = rate.NewLimiter(rate.Every(12*time.Second), 5)  // 5/min
	initLimiter   = rate.NewLimiter(rate.Every(20*time.Second), 3)  // 3/min
	authLimiter   = rate.NewLimiter(rate.Every(6*time.Second), 10)  // 10/min
	rateLimitMu   sync.Mutex
)

// VaultOperationType represents different types of Vault operations for rate limiting
type VaultOperationType string

const (
	VaultOpUnseal VaultOperationType = "unseal"
	VaultOpInit   VaultOperationType = "init"
	VaultOpAuth   VaultOperationType = "auth"
)

// RateLimitVaultOperation applies rate limiting to Vault operations
// SECURITY: Prevents brute force attacks on Vault unseal keys and authentication
func RateLimitVaultOperation(rc *eos_io.RuntimeContext, opType VaultOperationType) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Select appropriate limiter based on operation type
	var limiter *rate.Limiter
	var opName string

	switch opType {
	case VaultOpUnseal:
		limiter = unsealLimiter
		opName = "unseal"
	case VaultOpInit:
		limiter = initLimiter
		opName = "initialization"
	case VaultOpAuth:
		limiter = authLimiter
		opName = "authentication"
	default:
		return fmt.Errorf("unknown vault operation type for rate limiting: %s", opType)
	}

	// Wait for rate limit slot
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	if !limiter.Allow() {
		// Calculate wait time
		reservation := limiter.Reserve()
		waitTime := reservation.Delay()
		reservation.Cancel() // Cancel the reservation

		logger.Warn("Rate limit exceeded for Vault operation",
			zap.String("operation", opName),
			zap.Duration("retry_after", waitTime),
			zap.String("security_note", "rate limiting prevents brute force attacks"))

		return fmt.Errorf("rate limit exceeded for Vault %s operation (security protection: max attempts reached, retry after %v)", opName, waitTime)
	}

	logger.Debug("Rate limit check passed",
		zap.String("operation", opName))

	return nil
}

// RateLimitVaultOperationWithWait applies rate limiting and waits if necessary
// Uses context for cancellation support
func RateLimitVaultOperationWithWait(ctx context.Context, rc *eos_io.RuntimeContext, opType VaultOperationType) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Select appropriate limiter
	var limiter *rate.Limiter
	var opName string

	switch opType {
	case VaultOpUnseal:
		limiter = unsealLimiter
		opName = "unseal"
	case VaultOpInit:
		limiter = initLimiter
		opName = "initialization"
	case VaultOpAuth:
		limiter = authLimiter
		opName = "authentication"
	default:
		return fmt.Errorf("unknown vault operation type: %s", opType)
	}

	// Wait for rate limit with context cancellation
	if err := limiter.Wait(ctx); err != nil {
		logger.Error("Rate limit wait cancelled",
			zap.String("operation", opName),
			zap.Error(err))
		return fmt.Errorf("rate limit wait for %s cancelled: %w", opName, err)
	}

	logger.Debug("Rate limit wait completed",
		zap.String("operation", opName))

	return nil
}

// ResetRateLimits resets all Vault rate limiters (for testing)
func ResetRateLimits() {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()

	unsealLimiter = rate.NewLimiter(rate.Every(12*time.Second), 5)
	initLimiter = rate.NewLimiter(rate.Every(20*time.Second), 3)
	authLimiter = rate.NewLimiter(rate.Every(6*time.Second), 10)
}
