// pkg/wazuh/circuit_breaker.go - Enhanced circuit breaker implementation
package wazuh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig holds configuration for a circuit breaker
type CircuitBreakerConfig struct {
	Name               string        `json:"name"`
	FailureThreshold   int           `json:"failure_threshold"`    // Number of failures to open circuit
	SuccessThreshold   int           `json:"success_threshold"`    // Number of successes to close circuit in half-open
	Timeout            time.Duration `json:"timeout"`              // Time to wait before transitioning to half-open
	MaxConcurrentCalls int           `json:"max_concurrent_calls"` // Max concurrent calls in half-open state
}

// DefaultCircuitBreakerConfig returns sensible defaults
func DefaultCircuitBreakerConfig(name string) CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Name:               name,
		FailureThreshold:   5,
		SuccessThreshold:   3,
		Timeout:            60 * time.Second,
		MaxConcurrentCalls: 1,
	}
}

// CircuitBreaker implements the circuit breaker pattern with Redis for distributed coordination
type CircuitBreaker struct {
	config     CircuitBreakerConfig
	redis      *redis.Client
	localState CircuitState
	localMutex sync.RWMutex
	logger     *zap.Logger

	// Redis keys
	stateKey       string
	failureKey     string
	successKey     string
	lastFailureKey string
	concurrentKey  string
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig, redisClient *redis.Client, logger *zap.Logger) *CircuitBreaker {
	cb := &CircuitBreaker{
		config:     config,
		redis:      redisClient,
		localState: StateClosed,
		logger:     logger,

		stateKey:       fmt.Sprintf("circuit_breaker:%s:state", config.Name),
		failureKey:     fmt.Sprintf("circuit_breaker:%s:failures", config.Name),
		successKey:     fmt.Sprintf("circuit_breaker:%s:successes", config.Name),
		lastFailureKey: fmt.Sprintf("circuit_breaker:%s:last_failure", config.Name),
		concurrentKey:  fmt.Sprintf("circuit_breaker:%s:concurrent", config.Name),
	}

	return cb
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	if !cb.allowRequest(ctx) {
		cb.logger.Warn("Circuit breaker preventing request",
			zap.String("circuit", cb.config.Name),
			zap.String("state", cb.getState(ctx).String()))
		return NewCircuitOpenError(cb.config.Name)
	}

	// Increment concurrent request counter for half-open state
	if cb.getState(ctx) == StateHalfOpen {
		concurrent, err := cb.redis.Incr(ctx, cb.concurrentKey).Result()
		if err != nil {
			cb.logger.Error("Failed to increment concurrent counter", zap.Error(err))
		}

		// Respect max concurrent calls in half-open state
		if concurrent > int64(cb.config.MaxConcurrentCalls) {
			cb.redis.Decr(ctx, cb.concurrentKey)
			return NewCircuitOpenError(cb.config.Name)
		}

		// Set expiry for concurrent counter
		cb.redis.Expire(ctx, cb.concurrentKey, 30*time.Second)

		defer func() {
			cb.redis.Decr(ctx, cb.concurrentKey)
		}()
	}

	// Execute the function
	err := fn()

	if err != nil {
		cb.recordFailure(ctx, err)
		return err
	}

	cb.recordSuccess(ctx)
	return nil
}

// allowRequest determines if a request should be allowed through
func (cb *CircuitBreaker) allowRequest(ctx context.Context) bool {
	state := cb.getState(ctx)

	switch state {
	case StateClosed:
		return true
	case StateOpen:
		return cb.shouldAttemptReset(ctx)
	case StateHalfOpen:
		// Check concurrent request limit
		concurrent, err := cb.redis.Get(ctx, cb.concurrentKey).Int64()
		if err != nil && err != redis.Nil {
			cb.logger.Error("Failed to get concurrent counter", zap.Error(err))
			return false
		}
		return concurrent < int64(cb.config.MaxConcurrentCalls)
	default:
		return false
	}
}

// getState retrieves the current circuit breaker state
func (cb *CircuitBreaker) getState(ctx context.Context) CircuitState {
	stateStr, err := cb.redis.Get(ctx, cb.stateKey).Result()
	if err == redis.Nil {
		// No state set, default to closed
		cb.setState(ctx, StateClosed)
		return StateClosed
	} else if err != nil {
		cb.logger.Error("Failed to get circuit breaker state", zap.Error(err))
		// Return local state as fallback
		cb.localMutex.RLock()
		defer cb.localMutex.RUnlock()
		return cb.localState
	}

	switch stateStr {
	case "OPEN":
		return StateOpen
	case "HALF_OPEN":
		return StateHalfOpen
	default:
		return StateClosed
	}
}

// setState updates the circuit breaker state
func (cb *CircuitBreaker) setState(ctx context.Context, state CircuitState) {
	// Update Redis state
	err := cb.redis.Set(ctx, cb.stateKey, state.String(), 24*time.Hour).Err()
	if err != nil {
		cb.logger.Error("Failed to set circuit breaker state",
			zap.String("state", state.String()),
			zap.Error(err))
	}

	// Update local state
	cb.localMutex.Lock()
	cb.localState = state
	cb.localMutex.Unlock()

	cb.logger.Info("Circuit breaker state changed",
		zap.String("circuit", cb.config.Name),
		zap.String("new_state", state.String()))
}

// recordFailure records a failure and potentially opens the circuit
func (cb *CircuitBreaker) recordFailure(ctx context.Context, err error) {
	// Increment failure counter
	failures, redisErr := cb.redis.Incr(ctx, cb.failureKey).Result()
	if redisErr != nil {
		cb.logger.Error("Failed to increment failure counter", zap.Error(redisErr))
		return
	}

	// Set expiry for failure counter (sliding window)
	cb.redis.Expire(ctx, cb.failureKey, 5*time.Minute)

	// Record last failure time
	cb.redis.Set(ctx, cb.lastFailureKey, time.Now().Unix(), 24*time.Hour)

	// Reset success counter on failure
	cb.redis.Del(ctx, cb.successKey)

	cb.logger.Warn("Circuit breaker recorded failure",
		zap.String("circuit", cb.config.Name),
		zap.Int64("failure_count", failures),
		zap.Int("threshold", cb.config.FailureThreshold),
		zap.Error(err))

	// Check if we should open the circuit
	if failures >= int64(cb.config.FailureThreshold) {
		currentState := cb.getState(ctx)
		if currentState == StateClosed || currentState == StateHalfOpen {
			cb.setState(ctx, StateOpen)
			cb.logger.Error("Circuit breaker opened due to failure threshold",
				zap.String("circuit", cb.config.Name),
				zap.Int64("failures", failures),
				zap.Int("threshold", cb.config.FailureThreshold))
		}
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *CircuitBreaker) recordSuccess(ctx context.Context) {
	state := cb.getState(ctx)

	// Reset failure counter on success
	cb.redis.Del(ctx, cb.failureKey)

	if state == StateHalfOpen {
		// Increment success counter
		successes, err := cb.redis.Incr(ctx, cb.successKey).Result()
		if err != nil {
			cb.logger.Error("Failed to increment success counter", zap.Error(err))
			return
		}

		cb.logger.Debug("Circuit breaker recorded success in half-open state",
			zap.String("circuit", cb.config.Name),
			zap.Int64("success_count", successes),
			zap.Int("threshold", cb.config.SuccessThreshold))

		// Check if we should close the circuit
		if successes >= int64(cb.config.SuccessThreshold) {
			cb.setState(ctx, StateClosed)
			cb.redis.Del(ctx, cb.successKey)
			cb.redis.Del(ctx, cb.concurrentKey)
			cb.logger.Info("Circuit breaker closed after successful recovery",
				zap.String("circuit", cb.config.Name),
				zap.Int64("successes", successes))
		}
	}
}

// shouldAttemptReset checks if enough time has passed to attempt reset
func (cb *CircuitBreaker) shouldAttemptReset(ctx context.Context) bool {
	lastFailureStr, err := cb.redis.Get(ctx, cb.lastFailureKey).Result()
	if err != nil {
		if err == redis.Nil {
			// No last failure recorded, allow reset
			cb.setState(ctx, StateHalfOpen)
			return true
		}
		cb.logger.Error("Failed to get last failure time", zap.Error(err))
		return false
	}

	lastFailureTime, err := time.Parse(time.RFC3339, lastFailureStr)
	if err != nil {
		// Parse as Unix timestamp
		var lastFailureUnix int64
		if _, parseErr := fmt.Sscanf(lastFailureStr, "%d", &lastFailureUnix); parseErr == nil {
			lastFailureTime = time.Unix(lastFailureUnix, 0)
		} else {
			cb.logger.Error("Failed to parse last failure time", zap.Error(err))
			return false
		}
	}

	if time.Since(lastFailureTime) >= cb.config.Timeout {
		cb.setState(ctx, StateHalfOpen)
		cb.logger.Info("Circuit breaker transitioning to half-open",
			zap.String("circuit", cb.config.Name),
			zap.Duration("time_since_failure", time.Since(lastFailureTime)))
		return true
	}

	return false
}

// GetStats returns current circuit breaker statistics
func (cb *CircuitBreaker) GetStats(ctx context.Context) CircuitBreakerStats {
	state := cb.getState(ctx)

	failures, _ := cb.redis.Get(ctx, cb.failureKey).Int64()
	successes, _ := cb.redis.Get(ctx, cb.successKey).Int64()
	concurrent, _ := cb.redis.Get(ctx, cb.concurrentKey).Int64()

	var lastFailureTime *time.Time
	if lastFailureStr, err := cb.redis.Get(ctx, cb.lastFailureKey).Result(); err == nil {
		if lastFailureUnix, parseErr := time.Parse("", lastFailureStr); parseErr == nil {
			lastFailureTime = &lastFailureUnix
		}
	}

	return CircuitBreakerStats{
		Name:               cb.config.Name,
		State:              state,
		FailureCount:       failures,
		SuccessCount:       successes,
		ConcurrentRequests: concurrent,
		LastFailureTime:    lastFailureTime,
		Config:             cb.config,
	}
}

// CircuitBreakerStats holds statistics about a circuit breaker
type CircuitBreakerStats struct {
	Name               string               `json:"name"`
	State              CircuitState         `json:"state"`
	FailureCount       int64                `json:"failure_count"`
	SuccessCount       int64                `json:"success_count"`
	ConcurrentRequests int64                `json:"concurrent_requests"`
	LastFailureTime    *time.Time           `json:"last_failure_time,omitempty"`
	Config             CircuitBreakerConfig `json:"config"`
}

// CircuitOpenError is returned when the circuit breaker is open
type CircuitOpenError struct {
	CircuitName string
}

func (e *CircuitOpenError) Error() string {
	return fmt.Sprintf("circuit breaker '%s' is open", e.CircuitName)
}

func NewCircuitOpenError(name string) *CircuitOpenError {
	return &CircuitOpenError{CircuitName: name}
}

// IsCircuitOpen checks if an error is a circuit open error
func IsCircuitOpen(err error) bool {
	_, ok := err.(*CircuitOpenError)
	return ok
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	redis    *redis.Client
	logger   *zap.Logger
	mutex    sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(redisClient *redis.Client, logger *zap.Logger) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
		redis:    redisClient,
		logger:   logger,
	}
}

// GetOrCreate gets an existing circuit breaker or creates a new one
func (cbm *CircuitBreakerManager) GetOrCreate(name string, config *CircuitBreakerConfig) *CircuitBreaker {
	cbm.mutex.RLock()
	if cb, exists := cbm.breakers[name]; exists {
		cbm.mutex.RUnlock()
		return cb
	}
	cbm.mutex.RUnlock()

	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()

	// Double-check pattern
	if cb, exists := cbm.breakers[name]; exists {
		return cb
	}

	// Use provided config or default
	var cbConfig CircuitBreakerConfig
	if config != nil {
		cbConfig = *config
	} else {
		cbConfig = DefaultCircuitBreakerConfig(name)
	}

	cb := NewCircuitBreaker(cbConfig, cbm.redis, cbm.logger)
	cbm.breakers[name] = cb

	cbm.logger.Info("Created new circuit breaker",
		zap.String("name", name),
		zap.Int("failure_threshold", cbConfig.FailureThreshold),
		zap.Duration("timeout", cbConfig.Timeout))

	return cb
}

// GetAllStats returns statistics for all circuit breakers
func (cbm *CircuitBreakerManager) GetAllStats(ctx context.Context) map[string]CircuitBreakerStats {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()

	stats := make(map[string]CircuitBreakerStats)
	for name, cb := range cbm.breakers {
		stats[name] = cb.GetStats(ctx)
	}

	return stats
}
