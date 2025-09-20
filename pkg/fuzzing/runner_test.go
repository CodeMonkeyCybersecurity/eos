package fuzzing

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func TestExtractFuzzTests(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "example_test.go")

	testContent := `package example

import "testing"

func FuzzExample(f *testing.F) {
	f.Add("test")
	f.Fuzz(func(t *testing.T, input string) {
		// Test logic
	})
}

func FuzzAnother(f *testing.F) {
	f.Add(42)
	f.Fuzz(func(t *testing.T, num int) {
		// Test logic
	})
}

func TestRegular(t *testing.T) {
	// Not a fuzz test
}
`

	err := os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	rc := NewTestContext(t)
	logger := otelzap.Ctx(rc.Ctx)

	tests, err := extractFuzzTests(testFile, logger)
	require.NoError(t, err)

	assert.Len(t, tests, 2)
	assert.Equal(t, "FuzzExample", tests[0].Name)
	assert.Equal(t, "FuzzAnother", tests[1].Name)
}

func TestCategorizeTest(t *testing.T) {
	tests := []struct {
		name     string
		test     FuzzTest
		filePath string
		expected string
	}{
		{
			name:     "security critical - crypto path",
			test:     FuzzTest{Name: "FuzzEncryption"},
			filePath: "pkg/crypto/encrypt_test.go",
			expected: CategorySecurityCritical,
		},
		{
			name:     "security critical - auth name",
			test:     FuzzTest{Name: "FuzzPassword"},
			filePath: "pkg/utils/password_test.go",
			expected: CategorySecurityCritical,
		},
		{
			name:     "architecture - ",
			test:     FuzzTest{Name: "FuzzDeploy"},
			filePath: "pkg//deploy_test.go",
			expected: CategoryArchitecture,
		},
		{
			name:     "component - default",
			test:     FuzzTest{Name: "FuzzParser"},
			filePath: "pkg/parser/parse_test.go",
			expected: CategoryComponent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeTest(tt.test, tt.filePath)
			assert.Equal(t, tt.expected, result.Category)
			assert.NotEmpty(t, result.Description)
			assert.Greater(t, result.Priority, 0)
		})
	}
}

func TestExtractExecutionCount(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected int64
	}{
		{
			name:     "standard fuzzing output",
			output:   "fuzz: elapsed: 3s, execs: 18206 (6068/sec), new interesting: 12",
			expected: 18206,
		},
		{
			name:     "multiple exec counts",
			output:   "fuzz: elapsed: 1s, execs: 5000 (5000/sec)\nfuzz: elapsed: 2s, execs: 10000 (5000/sec)",
			expected: 5000, // Takes first match
		},
		{
			name:     "no execution count",
			output:   "fuzz: elapsed: 3s, new interesting: 12",
			expected: 0,
		},
		{
			name:     "malformed output",
			output:   "some random output without exec info",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractExecutionCount(tt.output)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractNewInputs(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected int
	}{
		{
			name:     "standard output",
			output:   "fuzz: elapsed: 3s, execs: 18206 (6068/sec), new interesting: 12 (total: 204)",
			expected: 12,
		},
		{
			name:     "no new inputs",
			output:   "fuzz: elapsed: 3s, execs: 18206 (6068/sec)",
			expected: 0,
		},
		{
			name:     "multiple occurrences",
			output:   "new interesting: 5\nnew interesting: 10",
			expected: 5, // Takes first match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNewInputs(tt.output)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractCrashData(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		expectCrash bool
		panicReason string
	}{
		{
			name: "panic detected",
			output: `panic: runtime error: index out of range
			
goroutine 1 [running]:
example.FuzzTest.func1(...)
	/path/to/file.go:123
testing.(*F).Fuzz.func1.1(0xc00010e000)
	input: "crash"`,
			expectCrash: true,
			panicReason: "runtime error: index out of range",
		},
		{
			name: "test failure",
			output: `FAIL: FuzzTest
--- FAIL: FuzzTest (0.00s)
    fuzzing process terminated`,
			expectCrash: true,
			panicReason: "",
		},
		{
			name: "successful test",
			output: `fuzz: elapsed: 3s, execs: 18206 (6068/sec)
PASS`,
			expectCrash: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCrashData(tt.output)
			if tt.expectCrash {
				assert.NotNil(t, result)
				if tt.panicReason != "" {
					assert.Equal(t, tt.panicReason, result.PanicReason)
				}
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestGenerateMarkdownReport(t *testing.T) {
	rc := NewTestContext(t)
	runner := NewRunner(rc, &Config{})

	session := &FuzzSession{
		ID:        "test-session-123",
		StartTime: time.Now().Add(-10 * time.Minute),
		EndTime:   time.Now(),
		Config: Config{
			ReportFormat: ReportFormatMarkdown,
		},
		Results: []TestResult{
			{
				TestName:   "FuzzExample",
				Package:    "./pkg/example",
				Duration:   5 * time.Second,
				Success:    true,
				Executions: 10000,
				ExecRate:   2000,
				NewInputs:  15,
			},
			{
				TestName:     "FuzzCrash",
				Package:      "./pkg/crash",
				Duration:     3 * time.Second,
				Success:      false,
				ErrorMessage: "test failed",
				CrashData: &CrashData{
					PanicReason: "index out of range",
					Severity:    "medium",
				},
			},
		},
		Summary: SessionSummary{
			TotalTests:      2,
			PassedTests:     1,
			FailedTests:     1,
			SuccessRate:     0.5,
			TotalExecutions: 10000,
			TotalDuration:   8 * time.Second,
			CrashesFound:    1,
			SecurityAlert:   true,
		},
	}

	report, err := runner.generateMarkdownReport(session)
	require.NoError(t, err)

	// Verify report contains key elements
	assert.Contains(t, report, "# Fuzzing Session Report")
	assert.Contains(t, report, "test-session-123")
	assert.Contains(t, report, "## Summary")
	assert.Contains(t, report, "Total Tests: 2")
	assert.Contains(t, report, "Success Rate: 50.0%")
	assert.Contains(t, report, "SECURITY ALERT")
	assert.Contains(t, report, "✅ PASS FuzzExample")
	assert.Contains(t, report, "❌ FAIL FuzzCrash")
	assert.Contains(t, report, "index out of range")
}

func TestGenerateTextReport(t *testing.T) {
	rc := NewTestContext(t)
	runner := NewRunner(rc, &Config{})

	session := &FuzzSession{
		ID: "test-123",
		Summary: SessionSummary{
			TotalTests:    10,
			PassedTests:   8,
			FailedTests:   2,
			SuccessRate:   0.8,
			TotalDuration: 1 * time.Minute,
			SecurityAlert: false,
		},
	}

	report, err := runner.generateTextReport(session)
	require.NoError(t, err)

	// Verify text report format
	assert.Contains(t, report, "FUZZING SESSION REPORT")
	assert.Contains(t, report, "Session ID: test-123")
	assert.Contains(t, report, "8/10 passed (80.0%)")
	assert.NotContains(t, report, "SECURITY ALERT") // Should not be present when false
}

func TestSelectTests(t *testing.T) {
	rc := NewTestContext(t)
	runner := NewRunner(rc, &Config{})

	discovery := &TestDiscovery{
		SecurityCritical: []FuzzTest{
			{Name: "FuzzAuth", Category: CategorySecurityCritical},
			{Name: "FuzzCrypto", Category: CategorySecurityCritical},
		},
		Architecture: []FuzzTest{
			{Name: "FuzzDeploy", Category: CategoryArchitecture},
		},
		Component: []FuzzTest{
			{Name: "FuzzParser", Category: CategoryComponent},
			{Name: "FuzzValidator", Category: CategoryComponent},
		},
	}

	tests := []struct {
		name     string
		config   Config
		expected int
		hasAuth  bool
	}{
		{
			name: "security focus only",
			config: Config{
				SecurityFocus:       true,
				ArchitectureTesting: false,
			},
			expected: 4, // 2 security + 2 component
			hasAuth:  true,
		},
		{
			name: "architecture testing",
			config: Config{
				SecurityFocus:       false,
				ArchitectureTesting: true,
			},
			expected: 3, // 1 architecture + 2 component
			hasAuth:  false,
		},
		{
			name: "CI mode with limit",
			config: Config{
				SecurityFocus: true,
				CIMode:        true,
			},
			expected: 4, // Would be limited to 20 in real scenario
			hasAuth:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected := runner.selectTests(discovery, tt.config)
			assert.Len(t, selected, tt.expected)

			// Check if security tests are included when expected
			hasAuth := false
			for _, test := range selected {
				if test.Name == "FuzzAuth" {
					hasAuth = true
					break
				}
			}
			assert.Equal(t, tt.hasAuth, hasAuth)
		})
	}
}

func TestCalculateSummary(t *testing.T) {
	rc := NewTestContext(t)
	runner := NewRunner(rc, &Config{})

	results := []TestResult{
		{
			Success:    true,
			Executions: 5000,
			Duration:   5 * time.Second,
		},
		{
			Success:    true,
			Executions: 3000,
			Duration:   3 * time.Second,
		},
		{
			Success:    false,
			Executions: 1000,
			Duration:   2 * time.Second,
			CrashData:  &CrashData{},
		},
	}

	summary := runner.calculateSummary(results)

	assert.Equal(t, 3, summary.TotalTests)
	assert.Equal(t, 2, summary.PassedTests)
	assert.Equal(t, 1, summary.FailedTests)
	assert.Equal(t, int64(9000), summary.TotalExecutions)
	assert.Equal(t, 10*time.Second, summary.TotalDuration)
	assert.Equal(t, 1, summary.CrashesFound)
	assert.True(t, summary.SecurityAlert)
	assert.InDelta(t, 0.666, summary.SuccessRate, 0.01)
}

func TestDiscoverTests(t *testing.T) {
	// Create temporary test structure
	tempDir := t.TempDir()

	// Create test files in different categories
	testFiles := map[string]string{
		"pkg/crypto/crypto_fuzz_test.go": `package crypto
func FuzzEncrypt(f *testing.F) {}
func FuzzDecrypt(f *testing.F) {}`,
		"pkg//_fuzz_test.go": `package   
func FuzzDeploy(f *testing.F) {}`,
		"pkg/utils/util_fuzz_test.go": `package utils
func FuzzParser(f *testing.F) {}`,
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tempDir, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err)
	}

	// Change to temp directory for discovery
	originalWd, _ := os.Getwd()
	err := os.Chdir(tempDir)
	require.NoError(t, err)
	defer func() { _ = os.Chdir(originalWd) }()

	rc := NewTestContext(t)
	runner := NewRunner(rc, &Config{})

	discovery, err := runner.DiscoverTests(context.Background())
	require.NoError(t, err)

	// Verify categorization
	assert.Equal(t, 2, len(discovery.SecurityCritical))
	assert.Equal(t, 1, len(discovery.Architecture))
	assert.Equal(t, 1, len(discovery.Component))
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		filePath string
		expected string
	}{
		{"pkg/fuzzing/runner_test.go", "./pkg/fuzzing"},
		{"cmd/self/fuzz_test.go", "./cmd/self"},
		{"test.go", "."},
		{"./test.go", "."},
		{"deep/nested/path/test.go", "./deep/nested/path"},
	}

	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			result := extractPackageName(tt.filePath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRunnerReportFormats(t *testing.T) {
	rc := NewTestContext(t)
	runner := NewRunner(rc, &Config{})

	session := &FuzzSession{
		ID:     "test-formats",
		Config: Config{},
		Summary: SessionSummary{
			TotalTests:  1,
			PassedTests: 1,
		},
	}

	// Test each format
	formats := []string{
		ReportFormatMarkdown,
		ReportFormatJSON,
		ReportFormatText,
	}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			session.Config.ReportFormat = format
			report, err := runner.GenerateReport(session)
			require.NoError(t, err)
			assert.NotEmpty(t, report)

			// JSON format currently returns error message
			if format == ReportFormatJSON {
				assert.Contains(t, report, "not implemented")
			}
		})
	}
}
