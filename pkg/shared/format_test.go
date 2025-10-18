// pkg/shared/format_test.go

package shared

import (
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero bytes", 0, "0 B"},
		{"bytes only", 512, "512 B"},
		{"kilobytes", 1024, "1.0 KiB"},
		{"megabytes", 1024 * 1024, "1.0 MiB"},
		{"gigabytes", 1024 * 1024 * 1024, "1.0 GiB"},
		{"terabytes", 1024 * 1024 * 1024 * 1024, "1.0 TiB"},
		{"mixed value", 1536 * 1024 * 1024, "1.5 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("FormatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint64
		wantErr  bool
	}{
		{"empty string", "", 0, false},
		{"zero", "0", 0, false},
		{"bytes", "1024", 1024, false},
		{"kilobytes", "10KB", 10 * 1024, false},
		{"megabytes", "100MB", 100 * 1024 * 1024, false},
		{"gigabytes", "50GB", 50 * 1024 * 1024 * 1024, false},
		{"terabytes", "2TB", 2 * 1024 * 1024 * 1024 * 1024, false},
		{"lowercase", "10gb", 10 * 1024 * 1024 * 1024, false},
		{"with spaces", " 5 GB ", 5 * 1024 * 1024 * 1024, false},
		{"decimal", "1.5GB", uint64(1.5 * 1024 * 1024 * 1024), false},
		{"invalid", "invalid", 0, true},
		{"invalid suffix", "10XB", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSize(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSize(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSize(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result != tt.expected {
				t.Errorf("ParseSize(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatAge(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		time     time.Time
		expected string
	}{
		{"just now", now, "now"},
		{"5 minutes ago", now.Add(-5 * time.Minute), "5m"},
		{"2 hours ago", now.Add(-2 * time.Hour), "2h"},
		{"3 days ago", now.Add(-3 * 24 * time.Hour), "3d"},
		{"2 weeks ago", now.Add(-14 * 24 * time.Hour), "2w"},
		{"2 months ago", now.Add(-60 * 24 * time.Hour), "2mo"},
		{"1 year ago", now.Add(-365 * 24 * time.Hour), "1y"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatAge(tt.time)
			if result != tt.expected {
				t.Errorf("FormatAge(%v) = %s, want %s", tt.time, result, tt.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		length   int
		expected string
	}{
		{"shorter than limit", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncate with ellipsis", "hello world", 8, "hello..."},
		{"truncate very short", "hello", 2, "he"},
		{"truncate at 3", "hello", 3, "hel"},
		{"empty string", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateString(tt.input, tt.length)
			if result != tt.expected {
				t.Errorf("TruncateString(%q, %d) = %q, want %q", tt.input, tt.length, result, tt.expected)
			}
		})
	}
}

func TestFormatBytesUint64(t *testing.T) {
	// Test the uint64 convenience wrapper
	result := FormatBytesUint64(1024 * 1024)
	expected := "1.0 MiB"
	if result != expected {
		t.Errorf("FormatBytesUint64(1048576) = %s, want %s", result, expected)
	}
}
