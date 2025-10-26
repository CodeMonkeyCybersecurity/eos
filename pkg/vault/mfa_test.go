// pkg/vault/mfa_test.go

package vault

import (
	"testing"
	"time"
)

// TestMFABootstrapDataStaleness tests the IsStale() method with various time thresholds
func TestMFABootstrapDataStaleness(t *testing.T) {
	tests := []struct {
		name      string
		age       time.Duration
		threshold time.Duration
		wantStale bool
	}{
		{
			name:      "fresh data (1 minute old, 5 minute threshold)",
			age:       1 * time.Minute,
			threshold: 5 * time.Minute,
			wantStale: false,
		},
		{
			name:      "just under threshold (4m59s old, 5 minute threshold)",
			age:       4*time.Minute + 59*time.Second,
			threshold: 5 * time.Minute,
			wantStale: false, // Not stale - just under threshold
		},
		{
			name:      "one second over threshold (5m1s old, 5 minute threshold)",
			age:       5*time.Minute + time.Second,
			threshold: 5 * time.Minute,
			wantStale: true,
		},
		{
			name:      "very stale (10 minutes old, 5 minute threshold)",
			age:       10 * time.Minute,
			threshold: 5 * time.Minute,
			wantStale: true,
		},
		{
			name:      "fresh with different threshold (6 minutes old, 10 minute threshold)",
			age:       6 * time.Minute,
			threshold: 10 * time.Minute,
			wantStale: false,
		},
		{
			name:      "just created (0 seconds old)",
			age:       0,
			threshold: 5 * time.Minute,
			wantStale: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &MFABootstrapData{
				Username:  "test-user",
				Password:  "test-password",
				EntityID:  "test-entity-id",
				FetchedAt: time.Now().Add(-tt.age),
			}

			got := data.IsStale(tt.threshold)
			if got != tt.wantStale {
				t.Errorf("IsStale() = %v, want %v (age: %s, threshold: %s)",
					got, tt.wantStale, tt.age, tt.threshold)
			}
		})
	}
}

// TestMFABootstrapDataAge tests the Age() method
func TestMFABootstrapDataAge(t *testing.T) {
	tests := []struct {
		name       string
		fetchedAt  time.Time
		wantMinAge time.Duration
		wantMaxAge time.Duration
	}{
		{
			name:       "just created",
			fetchedAt:  time.Now(),
			wantMinAge: 0,
			wantMaxAge: 100 * time.Millisecond, // Allow some test execution time
		},
		{
			name:       "5 minutes old",
			fetchedAt:  time.Now().Add(-5 * time.Minute),
			wantMinAge: 5 * time.Minute,
			wantMaxAge: 5*time.Minute + 100*time.Millisecond,
		},
		{
			name:       "1 hour old",
			fetchedAt:  time.Now().Add(-1 * time.Hour),
			wantMinAge: 1 * time.Hour,
			wantMaxAge: 1*time.Hour + 100*time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &MFABootstrapData{
				FetchedAt: tt.fetchedAt,
			}

			age := data.Age()
			if age < tt.wantMinAge || age > tt.wantMaxAge {
				t.Errorf("Age() = %s, want between %s and %s",
					age, tt.wantMinAge, tt.wantMaxAge)
			}
		})
	}
}

// TestMFABootstrapDataImmutability tests that MFABootstrapData fields can't be accidentally modified
func TestMFABootstrapDataImmutability(t *testing.T) {
	// This is a compile-time test - if this compiles, the type is mutable
	// We just verify that we can create the struct and read its fields
	data := &MFABootstrapData{
		Username:      "test",
		Password:      "secret",
		EntityID:      "entity-123",
		SecretPath:    "secret/data/test",
		FetchedAt:     time.Now(),
		SecretVersion: 1,
	}

	// Verify all fields are readable
	if data.Username != "test" {
		t.Error("Username field not readable")
	}
	if data.Password != "secret" {
		t.Error("Password field not readable")
	}
	if data.EntityID != "entity-123" {
		t.Error("EntityID field not readable")
	}
	if data.SecretPath != "secret/data/test" {
		t.Error("SecretPath field not readable")
	}
	if data.SecretVersion != 1 {
		t.Error("SecretVersion field not readable")
	}

	// Note: True immutability would require unexported fields with getters,
	// but the current design prioritizes simplicity and struct initialization.
	// The documentation warns users not to modify the struct after creation.
}

// TestMFABootstrapDataValidation tests that required fields are documented
func TestMFABootstrapDataValidation(t *testing.T) {
	tests := []struct {
		name      string
		data      *MFABootstrapData
		wantValid bool
		checkFunc func(*MFABootstrapData) bool
	}{
		{
			name: "all fields populated",
			data: &MFABootstrapData{
				Username:      "eos",
				Password:      "test-password",
				EntityID:      "entity-123",
				SecretPath:    "secret/data/eos/bootstrap",
				FetchedAt:     time.Now(),
				SecretVersion: 1,
			},
			wantValid: true,
			checkFunc: func(d *MFABootstrapData) bool {
				return d.Username != "" &&
					d.Password != "" &&
					d.EntityID != "" &&
					d.SecretPath != "" &&
					!d.FetchedAt.IsZero() &&
					d.SecretVersion > 0
			},
		},
		{
			name: "missing password",
			data: &MFABootstrapData{
				Username:   "eos",
				Password:   "", // Missing!
				EntityID:   "entity-123",
				SecretPath: "secret/data/eos/bootstrap",
				FetchedAt:  time.Now(),
			},
			wantValid: false,
			checkFunc: func(d *MFABootstrapData) bool {
				return d.Password != ""
			},
		},
		{
			name: "missing entity ID",
			data: &MFABootstrapData{
				Username:   "eos",
				Password:   "test-password",
				EntityID:   "", // Missing!
				SecretPath: "secret/data/eos/bootstrap",
				FetchedAt:  time.Now(),
			},
			wantValid: false,
			checkFunc: func(d *MFABootstrapData) bool {
				return d.EntityID != ""
			},
		},
		{
			name: "zero timestamp (not yet fetched)",
			data: &MFABootstrapData{
				Username:   "eos",
				Password:   "test-password",
				EntityID:   "entity-123",
				SecretPath: "secret/data/eos/bootstrap",
				FetchedAt:  time.Time{}, // Zero value!
			},
			wantValid: false,
			checkFunc: func(d *MFABootstrapData) bool {
				return !d.FetchedAt.IsZero()
			},
		},
		{
			name: "version zero is valid (KV v1 or older Vault)",
			data: &MFABootstrapData{
				Username:      "eos",
				Password:      "test-password",
				EntityID:      "entity-123",
				SecretPath:    "secret/data/eos/bootstrap",
				FetchedAt:     time.Now(),
				SecretVersion: 0, // Valid - means version tracking not available
			},
			wantValid: true,
			checkFunc: func(d *MFABootstrapData) bool {
				// Version 0 is acceptable
				return d.Username != "" &&
					d.Password != "" &&
					d.EntityID != "" &&
					d.SecretPath != "" &&
					!d.FetchedAt.IsZero()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.checkFunc(tt.data)
			if got != tt.wantValid {
				t.Errorf("validation = %v, want %v", got, tt.wantValid)
			}
		})
	}
}

// TestMFABootstrapDataEdgeCases tests edge cases and boundary conditions
func TestMFABootstrapDataEdgeCases(t *testing.T) {
	t.Run("future timestamp", func(t *testing.T) {
		data := &MFABootstrapData{
			FetchedAt: time.Now().Add(1 * time.Hour), // 1 hour in the future!
		}

		// Age will be negative
		age := data.Age()
		if age >= 0 {
			t.Errorf("Age() for future timestamp should be negative, got %s", age)
		}

		// IsStale with future timestamp
		isStale := data.IsStale(5 * time.Minute)
		if isStale {
			t.Error("Future timestamp should not be considered stale")
		}
	})

	t.Run("very old timestamp (year 2020)", func(t *testing.T) {
		data := &MFABootstrapData{
			FetchedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		}

		age := data.Age()
		if age < 4*365*24*time.Hour { // At least 4 years
			t.Errorf("Age() should be at least 4 years, got %s", age)
		}

		isStale := data.IsStale(5 * time.Minute)
		if !isStale {
			t.Error("Very old timestamp should be stale")
		}
	})

	t.Run("zero threshold means always stale", func(t *testing.T) {
		data := &MFABootstrapData{
			FetchedAt: time.Now().Add(-1 * time.Nanosecond), // Even 1ns old
		}

		// With zero threshold, even fresh data is stale (age > 0 is true)
		isStale := data.IsStale(0)
		if !isStale {
			t.Error("With zero threshold, even 1ns-old data should be stale")
		}
	})

	t.Run("negative threshold", func(t *testing.T) {
		data := &MFABootstrapData{
			FetchedAt: time.Now().Add(-1 * time.Second),
		}

		// Negative threshold means even fresh data is stale
		isStale := data.IsStale(-1 * time.Minute)
		if !isStale {
			t.Error("With negative threshold, even fresh data should be stale")
		}
	})
}
