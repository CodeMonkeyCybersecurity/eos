package eos_io

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
)

func TestNewContext(t *testing.T) {
	t.Run("creates_valid_context", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test-command")

		if rc == nil {
			t.Fatal("expected non-nil runtime context")
		}
		if rc.Ctx == nil {
			t.Fatal("expected non-nil context")
		}
		if rc.Log == nil {
			t.Fatal("expected non-nil logger")
		}
		// Command is derived from caller context, not the passed name
		if rc.Command == "" {
			t.Error("expected non-empty command")
		}
		if rc.Attributes == nil {
			t.Fatal("expected non-nil attributes map")
		}

		// Verify timestamp is recent
		now := time.Now()
		if rc.Timestamp.After(now) || rc.Timestamp.Before(now.Add(-time.Second)) {
			t.Errorf("timestamp should be recent, got %v", rc.Timestamp)
		}
	})

	t.Run("creates_unique_contexts", func(t *testing.T) {
		ctx := context.Background()
		rc1 := NewContext(ctx, "command1")
		time.Sleep(time.Millisecond) // Ensure different timestamps
		rc2 := NewContext(ctx, "command2")

		// Commands may be the same since they're derived from caller context
		// But timestamps should be different
		if !rc1.Timestamp.Before(rc2.Timestamp) {
			t.Error("expected rc1 timestamp to be before rc2 timestamp")
		}

		// Attributes should be separate instances
		rc1.Attributes["test"] = "value1"
		rc2.Attributes["test"] = "value2"
		if rc1.Attributes["test"] != "value1" {
			t.Errorf("expected 'value1', got %s", rc1.Attributes["test"])
		}
		if rc2.Attributes["test"] != "value2" {
			t.Errorf("expected 'value2', got %s", rc2.Attributes["test"])
		}
	})
}

func TestRuntimeContext_HandlePanic(t *testing.T) {
	t.Run("recovers_panic_and_sets_error", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")
		var err error

		func() {
			defer rc.HandlePanic(&err)
			panic("test panic")
		}()

		if err == nil {
			t.Fatal("expected error after panic recovery")
		}
		if !contains(err.Error(), "panic: test panic") {
			t.Errorf("expected error to contain 'panic: test panic', got %s", err.Error())
		}
	})

	t.Run("no_panic_leaves_error_unchanged", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")
		var err error

		func() {
			defer rc.HandlePanic(&err)
			// No panic
		}()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("preserves_existing_error", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")
		existingErr := errors.New("existing error")
		err := existingErr

		func() {
			defer rc.HandlePanic(&err)
			// No panic
		}()

		if err != existingErr {
			t.Errorf("expected existing error to be preserved")
		}
	})
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsInner(s, substr))))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRuntimeContext_End(t *testing.T) {
	// Initialize telemetry to prevent nil pointer dereference
	if err := telemetry.Init("test"); err != nil {
		t.Fatalf("Failed to initialize telemetry: %v", err)
	}

	t.Run("logs_successful_completion", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")
		var err error

		// Sleep briefly to ensure measurable duration
		time.Sleep(time.Millisecond)

		// Should not panic
		rc.End(&err)
	})

	t.Run("logs_failed_completion", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")
		err := errors.New("test failure")

		time.Sleep(time.Millisecond)

		// Should not panic
		rc.End(&err)
	})

	t.Run("includes_vault_context", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")
		rc.Attributes["vault_addr"] = "http://localhost:8200"
		var err error

		// Should not panic and should include vault address
		rc.End(&err)
	})
}

func TestRuntimeContext_Attributes(t *testing.T) {
	t.Run("can_store_and_retrieve_attributes", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		rc.Attributes["key1"] = "value1"
		rc.Attributes["key2"] = "value2"

		if rc.Attributes["key1"] != "value1" {
			t.Errorf("expected 'value1', got %s", rc.Attributes["key1"])
		}
		if rc.Attributes["key2"] != "value2" {
			t.Errorf("expected 'value2', got %s", rc.Attributes["key2"])
		}
	})

	t.Run("attributes_are_isolated_per_context", func(t *testing.T) {
		ctx := context.Background()
		rc1 := NewContext(ctx, "test1")
		rc2 := NewContext(ctx, "test2")

		rc1.Attributes["shared_key"] = "value1"
		rc2.Attributes["shared_key"] = "value2"

		if rc1.Attributes["shared_key"] != "value1" {
			t.Errorf("expected 'value1', got %s", rc1.Attributes["shared_key"])
		}
		if rc2.Attributes["shared_key"] != "value2" {
			t.Errorf("expected 'value2', got %s", rc2.Attributes["shared_key"])
		}
	})
}

func TestContextCancellation(t *testing.T) {
	t.Run("context_cancellation_propagates", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rc := NewContext(ctx, "test")
		defer cancel()

		// Start a goroutine that waits for context cancellation
		done := make(chan bool)
		go func() {
			<-rc.Ctx.Done()
			done <- true
		}()

		// Cancel the context
		cancel()

		// Should receive cancellation signal
		select {
		case <-done:
			// Success
		case <-time.After(100 * time.Millisecond):
			t.Fatal("context cancellation did not propagate")
		}
	})

	t.Run("context_timeout_works", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		rc := NewContext(ctx, "test")
		defer cancel()

		// Wait for timeout
		select {
		case <-rc.Ctx.Done():
			// Should timeout
			if rc.Ctx.Err() != context.DeadlineExceeded {
				t.Errorf("expected deadline exceeded, got %v", rc.Ctx.Err())
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("context did not timeout as expected")
		}
	})
}

func TestLogVaultContext(t *testing.T) {
	t.Run("logs_valid_vault_address", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		addr := LogVaultContext(rc.Log, "http://localhost:8200", nil)
		if addr != "http://localhost:8200" {
			t.Errorf("expected 'http://localhost:8200', got %s", addr)
		}
	})

	t.Run("logs_vault_error", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		addr := LogVaultContext(rc.Log, "", errors.New("vault error"))
		if addr != "(unavailable)" {
			t.Errorf("expected '(unavailable)', got %s", addr)
		}
	})

	t.Run("logs_empty_address", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		addr := LogVaultContext(rc.Log, "", nil)
		if addr != "(unavailable)" {
			t.Errorf("expected '(unavailable)', got %s", addr)
		}
	})
}

func TestContextualLogger(t *testing.T) {
	t.Run("creates_contextual_logger", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		logger := ContextualLogger(rc, 2, nil)
		if logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("uses_base_logger_when_provided", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		logger := ContextualLogger(rc, 2, rc.Log)
		if logger == nil {
			t.Error("expected non-nil logger")
		}
	})
}

func TestLogRuntimeExecutionContext(t *testing.T) {
	t.Run("logs_execution_context", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test")

		// Should not panic
		LogRuntimeExecutionContext(rc)
	})
}

func TestNewExtendedContext(t *testing.T) {
	t.Run("creates_extended_context_with_timeout", func(t *testing.T) {
		ctx := context.Background()
		timeout := 30 * time.Second

		rc := NewExtendedContext(ctx, "test-command", timeout)

		if rc == nil {
			t.Fatal("expected non-nil runtime context")
		}
		if rc.Ctx == nil {
			t.Fatal("expected non-nil context")
		}
		if rc.Log == nil {
			t.Fatal("expected non-nil logger")
		}
		if rc.Command == "" {
			t.Error("expected non-empty command")
		}
		if rc.Attributes == nil {
			t.Fatal("expected non-nil attributes map")
		}

		// Verify the context has a timeout
		deadline, ok := rc.Ctx.Deadline()
		if !ok {
			t.Error("expected context to have a deadline")
		}
		
		// The deadline should be approximately timeout from now
		expectedDeadline := time.Now().Add(timeout)
		if deadline.Before(expectedDeadline.Add(-time.Second)) || deadline.After(expectedDeadline.Add(time.Second)) {
			t.Errorf("deadline not within expected range: got %v, expected around %v", deadline, expectedDeadline)
		}
	})

	t.Run("creates_extended_context_with_short_timeout", func(t *testing.T) {
		ctx := context.Background()
		timeout := 100 * time.Millisecond

		rc := NewExtendedContext(ctx, "test-command", timeout)

		if rc == nil {
			t.Fatal("expected non-nil runtime context")
		}
		
		// Verify context will timeout
		select {
		case <-rc.Ctx.Done():
			// Should timeout quickly
			if rc.Ctx.Err() != context.DeadlineExceeded {
				t.Errorf("expected deadline exceeded, got %v", rc.Ctx.Err())
			}
		case <-time.After(200 * time.Millisecond):
			t.Error("context did not timeout as expected")
		}
	})

	t.Run("creates_extended_context_with_zero_timeout", func(t *testing.T) {
		ctx := context.Background()
		timeout := 0 * time.Second

		rc := NewExtendedContext(ctx, "test-command", timeout)

		if rc == nil {
			t.Fatal("expected non-nil runtime context")
		}
		
		// Context should be immediately cancelled with zero timeout
		select {
		case <-rc.Ctx.Done():
			// Should be cancelled immediately
		case <-time.After(10 * time.Millisecond):
			t.Error("context with zero timeout should be cancelled immediately")
		}
	})
}

func TestValidateAll(t *testing.T) {
	t.Run("validates_context_successfully", func(t *testing.T) {
		ctx := context.Background()
		rc := NewContext(ctx, "test-command")

		err := rc.ValidateAll()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("validates_context_with_nil_validate", func(t *testing.T) {
		rc := &RuntimeContext{
			Ctx: context.Background(),
			Log: NewContext(context.Background(), "test").Log,
			Validate: nil, // This should return nil
		}

		err := rc.ValidateAll()
		if err != nil {
			t.Errorf("expected no error for nil validate, got %v", err)
		}
	})

	t.Run("validates_context_with_empty_context", func(t *testing.T) {
		rc := &RuntimeContext{
			Ctx: context.Background(),
			Log: nil,
			Validate: nil, // ValidateAll returns nil when Validate is nil
		}

		err := rc.ValidateAll()
		if err != nil {
			t.Errorf("expected no error for nil validate, got %v", err)
		}
	})

	t.Run("validates_context_with_all_nil", func(t *testing.T) {
		rc := &RuntimeContext{}

		err := rc.ValidateAll()
		if err != nil {
			t.Errorf("expected no error for nil validate, got %v", err)
		}
	})
}
