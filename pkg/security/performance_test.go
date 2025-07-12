// pkg/security/performance_test.go
// Performance benchmarks with large-scale malicious inputs

package security

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// BenchmarkLargeScaleMaliciousInputs tests performance with massive attack vectors
func BenchmarkLargeScaleMaliciousInputs(b *testing.B) {
	benchmarks := []struct {
		name  string
		input string
	}{
		{
			"Massive_CSI_Spam",
			strings.Repeat(string(rune(0x9b))+"6n", 10000),
		},
		{
			"Massive_ANSI_Spam",
			strings.Repeat("\x1b[31m\x1b[32m\x1b[33m\x1b[0m", 5000),
		},
		{
			"Large_Mixed_Attack",
			generateLargeMixedAttack(50000),
		},
		{
			"UTF8_Bombing",
			strings.Repeat("\xff\xfe\xc0\x80", 25000),
		},
		{
			"Control_Character_Flood",
			generateControlCharacterFlood(100000),
		},
		{
			"Complex_Nested_Sequences",
			generateComplexNestedSequences(20000),
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			sanitizer := NewInputSanitizer()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = sanitizer.SanitizeInput(bm.input)
			}
		})

		b.Run(bm.name+"_Strict", func(b *testing.B) {
			sanitizer := NewStrictSanitizer()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = sanitizer.SanitizeInput(bm.input)
			}
		})
	}
}

// BenchmarkSecureOutputPerformance tests output sanitization performance
func BenchmarkSecureOutputPerformance(b *testing.B) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	benchmarks := []struct {
		name string
		fn   func()
	}{
		{
			"Simple_Info_With_Malicious_Content",
			func() {
				output.Info("Operation completed with status: \x1b[31merror\x1b[0m"+string(rune(0x9b))+"6n",
					zap.String("user", "admin\xff\xfe"),
					zap.String("action", "deploy\x00"))
			},
		},
		{
			"Large_Table_With_Malicious_Data",
			func() {
				headers := []string{"Name\x1b[31m", "Status\x9b", "Path\x00"}
				rows := make([][]string, 1000)
				for i := range rows {
					rows[i] = []string{
						"user" + string(rune(0x9b)) + "name",
						"active\xff\xfe",
						"/path/to\x00/file",
					}
				}
				output.Table("Large Dataset\x1b[32m", headers, rows)
			},
		},
		{
			"Complex_Result_Data",
			func() {
				data := map[string]interface{}{
					"users\x1b[m": []string{"alice\x9b", "bob\xff\xfe", "charlie\x00"},
					"config\x00": map[string]string{
						"host\x1b[31m": "localhost\x9b",
						"port\xff":     "8080\x00",
					},
					"stats": generateLargeStatsMap(100),
				}
				output.Result("benchmark_operation\x1b[33m", data)
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bm.fn()
			}
		})
	}
}

// BenchmarkArgumentSanitization tests command argument sanitization performance
func BenchmarkArgumentSanitization(b *testing.B) {
	sanitizer := NewInputSanitizer()

	// Generate large argument sets with malicious content
	largeArgs := make([]string, 1000)
	for i := range largeArgs {
		largeArgs[i] = generateMaliciousArgument(i)
	}

	benchmarks := []struct {
		name string
		args []string
	}{
		{
			"Small_Clean_Args",
			[]string{"cmd", "arg1", "arg2", "arg3"},
		},
		{
			"Small_Malicious_Args",
			[]string{
				"cmd\x1b[31m",
				"arg\x9b1",
				"arg\xff\xfe2",
				"arg\x003",
			},
		},
		{
			"Medium_Mixed_Args",
			generateMixedArgs(100),
		},
		{
			"Large_Malicious_Args",
			largeArgs,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = sanitizer.SanitizeArguments(bm.args)
			}
		})
	}
}

// BenchmarkMemoryEfficiency tests memory usage with large inputs
func BenchmarkMemoryEfficiency(b *testing.B) {
	sanitizer := NewInputSanitizer()

	// Large input with diverse malicious content
	largeInput := generateDiverseMaliciousInput(1000000) // 1MB of malicious data

	b.Run("Large_Input_Memory", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			result, _ := sanitizer.SanitizeInput(largeInput)
			_ = result // Prevent optimization
		}
	})

	b.Run("Repeated_Small_Inputs", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		smallMalicious := "user\x1b[31m\x9btest\xff\xfe"
		for i := 0; i < b.N; i++ {
			result, _ := sanitizer.SanitizeInput(smallMalicious)
			_ = result
		}
	})
}

// BenchmarkWorstCaseScenarios tests performance under worst-case conditions
func BenchmarkWorstCaseScenarios(b *testing.B) {
	benchmarks := []struct {
		name  string
		input string
		desc  string
	}{
		{
			"Maximum_Length_Attack",
			generateMaxLengthAttack(),
			"Input at maximum allowed length with dense malicious content",
		},
		{
			"Regex_Bombing_ANSI",
			generateRegexBombingANSI(),
			"ANSI sequences designed to stress regex engine",
		},
		{
			"UTF8_Edge_Cases",
			generateUTF8EdgeCases(),
			"Complex UTF-8 sequences at Unicode boundaries",
		},
		{
			"Nested_Sequence_Bomb",
			generateNestedSequenceBomb(),
			"Deeply nested control sequences",
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			sanitizer := NewInputSanitizer()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				result, err := sanitizer.SanitizeInput(bm.input)
				if err != nil {
					b.Logf("Expected failure for %s: %v", bm.desc, err)
				}
				_ = result
			}
		})
	}
}

// Helper functions for generating test data

func generateLargeMixedAttack(size int) string {
	var builder strings.Builder
	builder.Grow(size)

	patterns := []string{
		string(rune(0x9b)) + "6n",
		"\x1b[31m",
		"\xff\xfe",
		"\x00",
		"\x1b]0;title\x07",
		"\x1b[2J",
		"normal text ",
	}

	for builder.Len() < size {
		for _, pattern := range patterns {
			if builder.Len()+len(pattern) > size {
				break
			}
			builder.WriteString(pattern)
		}
	}

	return builder.String()
}

func generateControlCharacterFlood(size int) string {
	var builder strings.Builder
	builder.Grow(size)

	controlChars := []rune{0x00, 0x01, 0x02, 0x07, 0x08, 0x0B, 0x0C, 0x7F, 0x9B}

	for i := 0; i < size; i++ {
		builder.WriteRune(controlChars[i%len(controlChars)])
	}

	return builder.String()
}

func generateComplexNestedSequences(count int) string {
	var builder strings.Builder

	for i := 0; i < count; i++ {
		switch i % 4 {
		case 0:
			builder.WriteString("\x1b]0;\x1b[31m\x1b]0;nested\x07\x07")
		case 1:
			builder.WriteString("\x1b[\x1b[31m1m")
		case 2:
			builder.WriteString(string(rune(0x9b)) + "\x1b[32mtext")
		case 3:
			builder.WriteString("\x1bP\x1b_test\x1b\\\x1b\\")
		}
	}

	return builder.String()
}

func generateMaliciousArgument(index int) string {
	patterns := []string{
		"arg%d\x1b[31m",
		"arg%d\x9b",
		"arg%d\xff\xfe",
		"arg%d\x00end",
		"arg%d$(whoami)",
	}

	pattern := patterns[index%len(patterns)]
	return fmt.Sprintf(pattern, index)
}

func generateMixedArgs(count int) []string {
	args := make([]string, count)

	for i := 0; i < count; i++ {
		if i%3 == 0 {
			args[i] = fmt.Sprintf("clean_arg_%d", i)
		} else {
			args[i] = generateMaliciousArgument(i)
		}
	}

	return args
}

func generateLargeStatsMap(size int) map[string]interface{} {
	stats := make(map[string]interface{})

	for i := 0; i < size; i++ {
		key := fmt.Sprintf("metric_%d\x1b[31m", i)
		value := fmt.Sprintf("value_%d\x9b", i)
		stats[key] = value
	}

	return stats
}

func generateDiverseMaliciousInput(size int) string {
	var builder strings.Builder
	builder.Grow(size)

	// Mix of different attack vectors
	patterns := []string{
		// CSI attacks
		string(rune(0x9b)) + "6n",
		string(rune(0x9b)) + "[31m",

		// ANSI attacks
		"\x1b[2J\x1b[H",
		"\x1b[31;41;5;1m",
		"\x1b]0;title\x07",

		// UTF-8 attacks
		"\xff\xfe\xfd",
		"\xc0\x80\xc1\xbf",
		"\xe0\x80\x80",

		// Control characters
		"\x00\x01\x02\x07\x08",
		"\x0B\x0C\x7F",

		// Normal text
		"normal text here ",
		"more normal content ",
	}

	patternIndex := 0
	for builder.Len() < size {
		pattern := patterns[patternIndex%len(patterns)]
		if builder.Len()+len(pattern) <= size {
			builder.WriteString(pattern)
		} else {
			// Fill remaining space
			remaining := size - builder.Len()
			builder.WriteString(pattern[:remaining])
			break
		}
		patternIndex++
	}

	return builder.String()
}

func generateMaxLengthAttack() string {
	// Generate input at maximum allowed length with dense malicious content
	size := MaxInputLength
	var builder strings.Builder
	builder.Grow(size)

	// High density of malicious sequences
	maliciousPattern := string(rune(0x9b)) + "6n\x1b[31m\xff\xfe\x00"

	for builder.Len() < size {
		remaining := size - builder.Len()
		if len(maliciousPattern) <= remaining {
			builder.WriteString(maliciousPattern)
		} else {
			builder.WriteString(maliciousPattern[:remaining])
		}
	}

	return builder.String()
}

func generateRegexBombingANSI() string {
	// Generate ANSI sequences that could stress the regex engine
	var builder strings.Builder

	// Patterns that could cause backtracking
	for i := 0; i < 10000; i++ {
		builder.WriteString("\x1b[")
		// Add many parameters
		for j := 0; j < 100; j++ {
			builder.WriteString(fmt.Sprintf("%d;", j))
		}
		builder.WriteString("m")
	}

	return builder.String()
}

func generateUTF8EdgeCases() string {
	var builder strings.Builder

	// UTF-8 edge cases and boundary conditions
	edgeCases := []string{
		// Boundary values
		"\x7F",             // Last ASCII
		"\xC2\x80",         // First 2-byte
		"\xDF\xBF",         // Last 2-byte
		"\xE0\xA0\x80",     // First 3-byte
		"\xEF\xBF\xBF",     // Last 3-byte
		"\xF0\x90\x80\x80", // First 4-byte
		"\xF4\x8F\xBF\xBF", // Last valid 4-byte

		// Invalid sequences
		"\xC0\x80",         // Overlong 2-byte
		"\xE0\x80\x80",     // Overlong 3-byte
		"\xF0\x80\x80\x80", // Overlong 4-byte
		"\xF5\x80\x80\x80", // Beyond Unicode range

		// Incomplete sequences
		"\xC2",         // Incomplete 2-byte
		"\xE0\xA0",     // Incomplete 3-byte
		"\xF0\x90\x80", // Incomplete 4-byte
	}

	// Repeat edge cases many times
	for i := 0; i < 1000; i++ {
		for _, edgeCase := range edgeCases {
			builder.WriteString(edgeCase)
		}
	}

	return builder.String()
}

func generateNestedSequenceBomb() string {
	var builder strings.Builder

	// Deeply nested control sequences
	depth := 1000

	// Start with many opening sequences
	for i := 0; i < depth; i++ {
		builder.WriteString("\x1b]0;")
		builder.WriteString("\x1b[")
		builder.WriteString(string(rune(0x9b)))
	}

	// Add content
	builder.WriteString("nested_content")

	// Close with terminators
	for i := 0; i < depth; i++ {
		builder.WriteString("\x07")
		builder.WriteString("m")
	}

	return builder.String()
}
