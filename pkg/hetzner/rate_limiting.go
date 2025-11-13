// pkg/hetzner/rate_limiting.go
//
// Rate limiting support for Hetzner DNS API.
// Parses response headers and implements exponential backoff.

package hetzner

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// RateLimitInfo holds rate limit state extracted from HTTP response headers.
//
// Hetzner DNS API returns rate limit information via headers:
//   - Ratelimit-Limit: Total requests allowed per hour
//   - Ratelimit-Remaining: Requests remaining in current window
//   - Ratelimit-Reset: UNIX timestamp when limit resets
//
// Example headers:
//
//	Ratelimit-Limit: 3600
//	Ratelimit-Remaining: 3542
//	Ratelimit-Reset: 1706745600
type RateLimitInfo struct {
	Limit     int       // Total requests allowed per hour
	Remaining int       // Requests remaining in current window
	ResetTime time.Time // When the rate limit window resets
}

// ParseRateLimitHeaders extracts rate limit information from HTTP response headers.
//
// Behavior:
//   - ASSESS: Check for Ratelimit-* headers in response
//   - EVALUATE: Parse header values into RateLimitInfo struct
//   - EVALUATE: Handle missing/malformed headers gracefully
//
// Header Format:
//
//	Ratelimit-Limit: 3600
//	Ratelimit-Remaining: 3542
//	Ratelimit-Reset: 1706745600
//
// Error Handling:
//   - Returns nil if headers are missing (no rate limit info available)
//   - Treats parse errors as 0 (conservative approach)
//   - Does not return error (defensive parsing)
//
// Parameters:
//
//	headers: HTTP response headers from Hetzner API
//
// Returns:
//
//	*RateLimitInfo: Parsed rate limit info, or nil if headers missing
func ParseRateLimitHeaders(headers http.Header) *RateLimitInfo {
	limitStr := headers.Get("Ratelimit-Limit")
	remainingStr := headers.Get("Ratelimit-Remaining")
	resetStr := headers.Get("Ratelimit-Reset")

	// If no rate limit headers present, return nil
	if limitStr == "" {
		return nil
	}

	// Parse limit (conservative: treat parse error as 0)
	limit, _ := strconv.Atoi(limitStr)

	// Parse remaining (conservative: treat parse error as 0)
	remaining, _ := strconv.Atoi(remainingStr)

	// Parse reset timestamp (conservative: treat parse error as current time)
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	resetTime := time.Now()
	if err == nil {
		resetTime = time.Unix(resetUnix, 0)
	}

	return &RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		ResetTime: resetTime,
	}
}

// ShouldRetryAfterRateLimit determines if we should retry after hitting rate limit.
//
// Decision logic:
//   - If ResetTime is in the future and wait is ≤ max backoff → retry
//   - If ResetTime is in the past → retry immediately (new window)
//   - If wait > max backoff → don't retry (requires too long wait)
//
// Behavior:
//   - ASSESS: Calculate wait duration until reset
//   - EVALUATE: Check if wait is reasonable (≤ RateLimitMaxBackoff)
//
// Conservative Approach:
//   - Returns false if RateLimitInfo is nil
//   - Returns false if wait duration exceeds RateLimitMaxBackoff (30s)
//   - Returns initial backoff if ResetTime is in the past
//
// Parameters:
//
//	r: RateLimitInfo parsed from response headers
//
// Returns:
//
//	bool: True if retry is recommended
//	time.Duration: How long to wait before retrying (0 if no retry)
func (r *RateLimitInfo) ShouldRetryAfterRateLimit() (bool, time.Duration) {
	if r == nil {
		return false, 0
	}

	// Calculate wait duration until reset
	waitDuration := time.Until(r.ResetTime)

	// If reset time is in the past, use initial backoff
	if waitDuration < 0 {
		waitDuration = RateLimitInitialBackoff
	}

	// Don't wait longer than max backoff (30 seconds)
	if waitDuration > RateLimitMaxBackoff {
		return false, 0
	}

	return true, waitDuration
}

// String implements fmt.Stringer for human-readable rate limit info.
func (r *RateLimitInfo) String() string {
	if r == nil {
		return "rate limit info unavailable"
	}

	return fmt.Sprintf(
		"Rate Limit: %d/%d remaining, resets at %s (%s)",
		r.Remaining,
		r.Limit,
		r.ResetTime.Format(time.RFC3339),
		time.Until(r.ResetTime).Truncate(time.Second),
	)
}

// IsNearLimit returns true if remaining requests are below 10% of limit.
//
// Use this to proactively slow down requests before hitting the limit.
//
// Example:
//
//	if rateLimitInfo != nil && rateLimitInfo.IsNearLimit() {
//	    logger.Warn("Approaching rate limit", zap.String("info", rateLimitInfo.String()))
//	    time.Sleep(5 * time.Second) // Slow down
//	}
func (r *RateLimitInfo) IsNearLimit() bool {
	if r == nil || r.Limit == 0 {
		return false
	}

	threshold := float64(r.Limit) * 0.1 // 10% threshold
	return float64(r.Remaining) < threshold
}

// ExponentialBackoff calculates wait duration with exponential backoff.
//
// Strategy: Start with initial backoff, double each attempt, cap at max backoff.
//
// Behavior:
//   - Attempt 1: RateLimitInitialBackoff (5s)
//   - Attempt 2: 10s
//   - Attempt 3: 20s
//   - Attempt 4+: RateLimitMaxBackoff (30s)
//
// Parameters:
//
//	attempt: Retry attempt number (1-indexed)
//
// Returns:
//
//	time.Duration: Wait duration for this attempt
func ExponentialBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}

	// Calculate: initialBackoff * 2^(attempt-1)
	backoff := RateLimitInitialBackoff
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if backoff > RateLimitMaxBackoff {
			return RateLimitMaxBackoff
		}
	}

	return backoff
}
