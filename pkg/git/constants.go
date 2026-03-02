// pkg/git/constants.go
//
// Centralized constants for git operations.
// SINGLE SOURCE OF TRUTH per CLAUDE.md P0 Rule #12.

package git

import "time"

const (
	// GitPullMaxAttempts is the maximum number of retry attempts for transient
	// git pull failures (HTTP 502/503/504, DNS, timeouts).
	// RATIONALE: 4 attempts with jittered backoff covers typical CDN/proxy
	// recovery windows (5-15s) without excessive delay in CI.
	GitPullMaxAttempts = 4

	// GitPullBaseBackoff is the base duration for retry backoff calculation.
	// Actual backoff = baseBackoff * attempt + jitter.
	GitPullBaseBackoff = 2 * time.Second

	// GitPullMaxJitter is the upper bound for random jitter added to backoff.
	// RATIONALE: Prevents thundering herd when multiple Eos instances
	// retry against the same git remote simultaneously.
	GitPullMaxJitter = 1 * time.Second
)
