package fuzzing

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Duration:      5 * time.Second,
				ParallelJobs:  4,
				LogDir:        "/tmp/fuzzing",
				ReportFormat:  ReportFormatMarkdown,
			},
			wantErr: false,
		},
		{
			name: "zero duration",
			config: &Config{
				Duration:      0,
				ParallelJobs:  4,
				LogDir:        "/tmp/fuzzing",
				ReportFormat:  ReportFormatMarkdown,
			},
			wantErr: true,
			errMsg:  "duration must be positive",
		},
		{
			name: "zero parallel jobs",
			config: &Config{
				Duration:      5 * time.Second,
				ParallelJobs:  0,
				LogDir:        "/tmp/fuzzing",
				ReportFormat:  ReportFormatMarkdown,
			},
			wantErr: true,
			errMsg:  "parallel_jobs must be positive",
		},
		{
			name: "invalid report format",
			config: &Config{
				Duration:      5 * time.Second,
				ParallelJobs:  4,
				LogDir:        "/tmp/fuzzing",
				ReportFormat:  "invalid",
			},
			wantErr: true,
			errMsg:  "invalid report format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigureEnvironment(t *testing.T) {
	// Create test runtime context
	rc := NewTestContext(t)
	
	// Create temporary directory for testing
	tempDir := t.TempDir()
	
	config := &Config{
		Duration:      5 * time.Second,
		ParallelJobs:  2,
		LogDir:        filepath.Join(tempDir, "fuzzing"),
		ReportFormat:  ReportFormatMarkdown,
	}
	
	// Run configuration
	err := Configure(rc, config)
	require.NoError(t, err)
	
	// Verify directories were created
	assert.DirExists(t, config.LogDir)
	assert.DirExists(t, filepath.Join(config.LogDir, "sessions"))
	assert.DirExists(t, filepath.Join(config.LogDir, "reports"))
	assert.DirExists(t, filepath.Join(config.LogDir, "corpus"))
	assert.DirExists(t, filepath.Join(config.LogDir, "crashes"))
	
	// Verify TMPDIR was set
	assert.Equal(t, filepath.Join(config.LogDir, "tmp"), os.Getenv("TMPDIR"))
}

// These tests verify environment setup through the Configure function
// since the internal functions are not exported

func TestConfigureWithInvalidGoVersion(t *testing.T) {
	// This test would require mocking exec.Command, which is complex
	// Skip for now as it's an edge case
	t.Skip("Requires exec.Command mocking")
}

func TestValidateReportFormat(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{ReportFormatMarkdown, false},
		{ReportFormatJSON, false},
		{ReportFormatText, false},
		{"", false}, // Empty defaults to markdown
		{"invalid", true},
		{"html", true},
		{"xml", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			config := &Config{
				Duration:      5 * time.Second,
				ParallelJobs:  1,
				LogDir:        "/tmp",
				ReportFormat:  tt.format,
			}
			
			err := validateConfig(config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "report format")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}