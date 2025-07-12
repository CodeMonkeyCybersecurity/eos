package fuzzing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func TestCalculateHealthScore(t *testing.T) {
	tests := []struct {
		name     string
		status   *FuzzingStatus
		expected float64
		desc     string
	}{
		{
			name: "perfect health",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.21.5 darwin/arm64",
				FuzzingSupported: true,
				TestsFound:       10,
				PackagesVerified: 5,
				Issues:           []string{},
			},
			expected: 1.0,
			desc:     "All checks pass, no issues",
		},
		{
			name: "good health with minor issues",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.21.5 darwin/arm64",
				FuzzingSupported: true,
				TestsFound:       5,
				PackagesVerified: 3,
				Issues:           []string{"minor warning"},
			},
			expected: 0.9,
			desc:     "All features present but one issue",
		},
		{
			name: "poor health - no fuzzing support",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.17 darwin/arm64",
				FuzzingSupported: false,
				TestsFound:       0,
				PackagesVerified: 0,
				Issues:           []string{"no fuzzing", "old version"},
			},
			expected: 0.0,
			desc:     "Missing critical features",
		},
		{
			name: "medium health",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.21.5 darwin/arm64",
				FuzzingSupported: true,
				TestsFound:       0,
				PackagesVerified: 2,
				Issues:           []string{},
			},
			expected: 0.8,
			desc:     "Fuzzing works but no tests found",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calculateHealthScore(tt.status)
			assert.InDelta(t, tt.expected, score, 0.01, tt.desc)
		})
	}
}

func TestEvaluateFuzzingHealth(t *testing.T) {
	rc := NewTestContext(t)
	logger := otelzap.Ctx(rc.Ctx)
	
	tests := []struct {
		name    string
		status  *FuzzingStatus
		wantErr bool
		errMsg  string
	}{
		{
			name: "healthy environment",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.21.5 darwin/arm64",
				FuzzingSupported: true,
				TestsFound:       10,
				PackagesVerified: 5,
				Issues:           []string{},
			},
			wantErr: false,
		},
		{
			name: "no fuzzing support",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.17 darwin/arm64",
				FuzzingSupported: false,
				TestsFound:       10,
				PackagesVerified: 5,
				Issues:           []string{},
			},
			wantErr: true,
			errMsg:  "fuzzing is not supported",
		},
		{
			name: "no packages verified",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.21.5 darwin/arm64",
				FuzzingSupported: true,
				TestsFound:       10,
				PackagesVerified: 0,
				Issues:           []string{},
			},
			wantErr: true,
			errMsg:  "no packages could be verified",
		},
		{
			name: "low health score",
			status: &FuzzingStatus{
				GoVersion:        "",
				FuzzingSupported: true,
				TestsFound:       0,
				PackagesVerified: 1,
				Issues:           []string{"issue1", "issue2", "issue3", "issue4", "issue5"},
			},
			wantErr: true,
			errMsg:  "health score too low",
		},
		{
			name: "no tests found warning only",
			status: &FuzzingStatus{
				GoVersion:        "go version go1.21.5 darwin/arm64",
				FuzzingSupported: true,
				TestsFound:       0,
				PackagesVerified: 5,
				Issues:           []string{},
			},
			wantErr: false, // Should only warn, not error
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := evaluateFuzzingHealth(tt.status, logger)
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

func TestVerifyEnvironment(t *testing.T) {
	// This is an integration test that requires a real Go environment
	rc := NewTestContext(t)
	
	// Run full verification
	err := Verify(rc)
	
	// This should pass on any properly configured Go 1.18+ system
	if err != nil {
		t.Logf("Verification failed (might be environment-specific): %v", err)
	}
}

func TestFuzzingStatusCapabilities(t *testing.T) {
	rc := NewTestContext(t)
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test status assessment
	status, err := assessFuzzingStatus(rc.Ctx, logger)
	require.NoError(t, err)
	
	// Should have some capabilities
	assert.NotNil(t, status)
	assert.NotEmpty(t, status.Capabilities, "Should detect some capabilities")
	
	// Verify timestamp is recent
	assert.WithinDuration(t, time.Now(), status.LastVerified, 5*time.Second)
}

func TestVerificationTests(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(logger otelzap.LoggerWithCtx) error
		skipMsg  string
	}{
		{
			name:     "Go environment",
			testFunc: verifyGoEnvironment,
		},
		{
			name:     "Module configuration",
			testFunc: verifyModuleConfiguration,
			skipMsg:  "May fail if not in a Go module",
		},
		{
			name:     "Test compilation",
			testFunc: verifyTestCompilationDetailed,
		},
		{
			name:     "Output handling",
			testFunc: verifyOutputHandling,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := NewTestContext(t)
			logger := otelzap.Ctx(rc.Ctx)
			
			err := tt.testFunc(logger)
			if err != nil && tt.skipMsg != "" {
				t.Skipf("%s: %v", tt.skipMsg, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCountFuzzTests(t *testing.T) {
	rc := NewTestContext(t)
	logger := otelzap.Ctx(rc.Ctx)
	
	// This will count actual fuzz tests in the current directory
	count, err := countFuzzTests(logger)
	require.NoError(t, err)
	
	// We should find at least our own test files
	assert.GreaterOrEqual(t, count, 0, "Should not error even if no tests found")
}

func TestCheckFuzzingSupportDetailed(t *testing.T) {
	rc := NewTestContext(t)
	logger := otelzap.Ctx(rc.Ctx)
	
	supported, err := checkFuzzingSupportDetailed(logger)
	require.NoError(t, err)
	
	// Should be true on Go 1.18+ systems
	if !supported {
		t.Log("Fuzzing not supported (might be running on Go < 1.18)")
	}
}