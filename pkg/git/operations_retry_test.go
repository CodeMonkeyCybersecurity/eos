package git

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// --- Classification tests ---

func TestIsTransientGitPullFailure_AllTransientMarkers(t *testing.T) {
	// Every entry in transientMarkers must be recognized as transient.
	for marker, wantReason := range transientMarkers {
		t.Run(wantReason, func(t *testing.T) {
			output := "fatal: " + marker
			got, reason := isTransientGitPullFailure(output)
			if !got {
				t.Fatalf("expected transient=true for %q", marker)
			}
			if reason != wantReason {
				t.Fatalf("reason = %q, want %q", reason, wantReason)
			}
		})
	}
}

func TestIsTransientGitPullFailure_AllPermanentMarkers(t *testing.T) {
	// Every entry in permanentMarkers must be recognized as permanent.
	for _, marker := range permanentMarkers {
		t.Run(marker, func(t *testing.T) {
			output := "fatal: " + marker
			got, reason := isTransientGitPullFailure(output)
			if got {
				t.Fatalf("expected transient=false for %q", marker)
			}
			if reason != "permanent" {
				t.Fatalf("reason = %q, want %q", reason, "permanent")
			}
		})
	}
}

func TestIsTransientGitPullFailure_CaseInsensitive(t *testing.T) {
	got, reason := isTransientGitPullFailure("The Requested URL Returned Error: 502")
	if !got {
		t.Fatal("expected transient=true for mixed-case 502")
	}
	if reason != "http_502" {
		t.Fatalf("reason = %q, want http_502", reason)
	}
}

func TestIsTransientGitPullFailure_UnknownIsNotTransient(t *testing.T) {
	got, reason := isTransientGitPullFailure("something completely unexpected happened")
	if got {
		t.Fatal("expected transient=false for unknown error")
	}
	if reason != "unknown" {
		t.Fatalf("reason = %q, want %q", reason, "unknown")
	}
}

func TestIsTransientGitPullFailure_PermanentTakesPrecedence(t *testing.T) {
	// If output contains both permanent and transient markers, permanent wins.
	output := "authentication failed\nrequested url returned error: 502"
	got, reason := isTransientGitPullFailure(output)
	if got {
		t.Fatal("permanent markers should take precedence over transient")
	}
	if reason != "permanent" {
		t.Fatalf("reason = %q, want %q", reason, "permanent")
	}
}

func TestIsTransientGitPullFailure_RealGitOutputFormats(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
		reason string
	}{
		{
			name:   "real http 502 from gitea",
			output: "fatal: unable to access 'https://gitea.cybermonkey.sh/eos.git/': The requested URL returned error: 502",
			want:   true,
			reason: "http_502",
		},
		{
			name:   "real auth failure",
			output: "remote: Authentication failed for 'https://gitea.cybermonkey.sh/eos.git/'",
			want:   false,
			reason: "permanent",
		},
		{
			name:   "real remote hung up",
			output: "fatal: the remote end hung up unexpectedly",
			want:   true,
			reason: "remote_hung_up",
		},
		{
			name:   "real dns failure",
			output: "fatal: unable to access 'https://gitea.example.com/eos.git/': Could not resolve host: gitea.example.com",
			want:   true,
			reason: "dns_resolution_failure",
		},
		{
			name:   "real connection refused",
			output: "fatal: unable to access 'https://gitea.example.com:3000/eos.git/': Failed to connect to gitea.example.com port 3000: Connection refused",
			want:   true,
			reason: "connection_refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := isTransientGitPullFailure(tt.output)
			if got != tt.want {
				t.Fatalf("isTransientGitPullFailure() = %v, want %v", got, tt.want)
			}
			if reason != tt.reason {
				t.Fatalf("reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

// --- Retry behavior tests ---

func TestRunGitPullWithRetry_SucceedsAfterTransientFailures(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	callCount := 0
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		callCount++
		if callCount < 3 {
			return []byte("The requested URL returned error: 502"), errors.New("exit status 1")
		}
		return []byte("Already up to date."), nil
	}

	var sleptDurations []time.Duration
	gitPullRetrySleep = func(d time.Duration) { sleptDurations = append(sleptDurations, d) }

	out, err := runGitPullWithRetry(testutil.TestContext(t), "/tmp/repo", "main", false)
	if err != nil {
		t.Fatalf("runGitPullWithRetry() error = %v", err)
	}
	if string(out) != "Already up to date." {
		t.Fatalf("unexpected output: %q", string(out))
	}
	if callCount != 3 {
		t.Fatalf("attempts = %d, want 3", callCount)
	}
	if len(sleptDurations) != 2 {
		t.Fatalf("sleep count = %d, want 2", len(sleptDurations))
	}
	// Verify backoff durations are increasing (base + jitter, so at least base)
	for i, d := range sleptDurations {
		minExpected := time.Duration(i+1) * GitPullBaseBackoff
		if d < minExpected {
			t.Fatalf("sleep[%d] = %v, want >= %v", i, d, minExpected)
		}
	}
}

func TestRunGitPullWithRetry_DoesNotRetryPermanentFailures(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	callCount := 0
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		callCount++
		return []byte("remote: Authentication failed"), errors.New("exit status 1")
	}
	gitPullRetrySleep = func(d time.Duration) {
		t.Fatal("should not sleep on permanent failure")
	}

	_, err := runGitPullWithRetry(testutil.TestContext(t), "/tmp/repo", "main", false)
	if err == nil {
		t.Fatal("expected error for permanent failure")
	}
	if callCount != 1 {
		t.Fatalf("attempts = %d, want 1", callCount)
	}
}

func TestRunGitPullWithRetry_ExhaustsAllAttempts(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	callCount := 0
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		callCount++
		return []byte("The requested URL returned error: 503"), errors.New("exit status 1")
	}
	gitPullRetrySleep = func(d time.Duration) {}

	_, err := runGitPullWithRetry(testutil.TestContext(t), "/tmp/repo", "main", false)
	if err == nil {
		t.Fatal("expected error after exhausting all attempts")
	}
	if callCount != GitPullMaxAttempts {
		t.Fatalf("attempts = %d, want %d", callCount, GitPullMaxAttempts)
	}
	// Verify error message includes failure history
	errMsg := err.Error()
	if !strings.Contains(errMsg, "attempt=1") || !strings.Contains(errMsg, "http_503") {
		t.Fatalf("error should contain failure history, got: %s", errMsg)
	}
}

func TestRunGitPullWithRetry_SucceedsFirstTry(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		return []byte("Already up to date."), nil
	}
	gitPullRetrySleep = func(d time.Duration) {
		t.Fatal("should not sleep on first-try success")
	}

	out, err := runGitPullWithRetry(testutil.TestContext(t), "/tmp/repo", "main", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "Already up to date." {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestRunGitPullWithRetry_MixedTransientErrors(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	responses := []struct {
		output string
		err    error
	}{
		{"temporary failure in name resolution", errors.New("exit 1")},
		{"The requested URL returned error: 502", errors.New("exit 1")},
		{"Already up to date.", nil},
	}

	callCount := 0
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		r := responses[callCount]
		callCount++
		return []byte(r.output), r.err
	}
	gitPullRetrySleep = func(d time.Duration) {}

	out, err := runGitPullWithRetry(testutil.TestContext(t), "/tmp/repo", "main", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "Already up to date." {
		t.Fatalf("unexpected output: %q", string(out))
	}
	if callCount != 3 {
		t.Fatalf("attempts = %d, want 3", callCount)
	}
}

func TestRunGitPullWithRetry_UnknownErrorDoesNotRetry(t *testing.T) {
	origRun := runGitPullAttempt
	origSleep := gitPullRetrySleep
	t.Cleanup(func() {
		runGitPullAttempt = origRun
		gitPullRetrySleep = origSleep
	})

	callCount := 0
	runGitPullAttempt = func(repoDir, branch string, autostash bool, interactive bool, extraEnv []string) ([]byte, error) {
		callCount++
		return []byte("some weird git internal error"), errors.New("exit status 128")
	}
	gitPullRetrySleep = func(d time.Duration) {
		t.Fatal("should not sleep on unknown error")
	}

	_, err := runGitPullWithRetry(testutil.TestContext(t), "/tmp/repo", "main", false)
	if err == nil {
		t.Fatal("expected error for unknown failure")
	}
	if callCount != 1 {
		t.Fatalf("attempts = %d, want 1 (unknown errors should not retry)", callCount)
	}
}

// --- Backoff tests ---

func TestRetryBackoff_IncreasesByAttempt(t *testing.T) {
	prev := time.Duration(0)
	for attempt := 1; attempt <= GitPullMaxAttempts; attempt++ {
		base := time.Duration(attempt) * GitPullBaseBackoff
		d := retryBackoff(attempt)
		if d < base {
			t.Fatalf("attempt %d: backoff %v < base %v", attempt, d, base)
		}
		maxExpected := base + GitPullMaxJitter
		if d > maxExpected {
			t.Fatalf("attempt %d: backoff %v > max %v", attempt, d, maxExpected)
		}
		if d <= prev && attempt > 1 {
			// This can occasionally fail due to jitter, but base increase
			// guarantees min(attempt N) > max(attempt N-1) when base > jitter.
			// With base=2s and jitter=1s, this always holds.
			t.Logf("warning: attempt %d backoff %v <= attempt %d backoff %v (jitter overlap)", attempt, d, attempt-1, prev)
		}
		prev = d
	}
}
