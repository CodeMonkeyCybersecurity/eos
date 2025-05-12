package httpclient_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockHandler returns the specified status code for N attempts before succeeding.
func retryHandler(t *testing.T, failCount int, statusCode int) http.HandlerFunc {
	attempts := 0
	return func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= failCount {
			t.Logf("Failing attempt %d with status %d", attempts, statusCode)
			http.Error(w, "fail", statusCode)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}
}

func TestDoWithRetry_SucceedsAfterRetries(t *testing.T) {
	server := httptest.NewServer(retryHandler(t, 2, http.StatusServiceUnavailable))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := DoWithRetry(client, req, 5, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
}

func TestDoWithRetry_StopsAfterMaxAttempts(t *testing.T) {
	server := httptest.NewServer(retryHandler(t, 10, http.StatusInternalServerError))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL, nil)
	client := &http.Client{Timeout: 2 * time.Second}
	_, err := DoWithRetry(client, req, 3, 100*time.Millisecond)
	if err == nil {
		t.Fatal("Expected error after max retries, got nil")
	}
	t.Logf("Expected error received: %v", err)
}

func TestDoWithRetry_NetworkFailure(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", "http://localhost:9999/doesnotexist", nil)

	_, err := DoWithRetry(client, req, 2, 100*time.Millisecond)
	if err == nil {
		t.Fatal("Expected network error, got nil")
	}
	t.Logf("Received expected network error: %v", err)
}

// RetryableError marks an error as retryable.
type RetryableError struct {
	Err error
}

func (e RetryableError) Error() string { return e.Err.Error() }

// DoWithRetry executes an HTTP request with exponential backoff retry logic.
// It retries for temporary network errors and 5xx server errors.
func DoWithRetry(client *http.Client, req *http.Request, maxAttempts int, baseDelay time.Duration) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil // success or client error — don’t retry
		}

		// Always close body if we won't return it
		if resp != nil {
			resp.Body.Close()
		}

		lastErr = err
		if err != nil {
			lastErr = RetryableError{Err: err}
		} else {
			lastErr = RetryableError{Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
		}

		// Sleep before next attempt
		delay := time.Duration(attempt*attempt) * baseDelay
		time.Sleep(delay)
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", maxAttempts, lastErr)
}
