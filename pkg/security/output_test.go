// pkg/security/output_test.go

package security

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.uber.org/zap"
)

func TestSecureOutput_Info(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	testCases := []struct {
		name     string
		message  string
		fields   []zap.Field
		expected string // We can't easily test log output, but we can test the sanitization
	}{
		{
			name:     "safe message",
			message:  "Operation completed successfully",
			fields:   []zap.Field{zap.String("user", "alice")},
			expected: "Operation completed successfully",
		},
		{
			name:     "message with CSI",
			message:  "User " + string(rune(0x9b)) + "test logged in",
			fields:   []zap.Field{zap.String("action", "login")},
			expected: "User test logged in",
		},
		{
			name:     "message with ANSI",
			message:  "Status: \x1b[31merror\x1b[0m",
			fields:   []zap.Field{zap.String("level", "error")},
			expected: "Status: error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that the function doesn't panic
			output.Info(tc.message, tc.fields...)
			
			// Test the sanitization directly
			sanitized := EscapeOutput(tc.message)
			if sanitized != tc.expected {
				t.Errorf("expected sanitized message %q, got %q", tc.expected, sanitized)
			}
		})
	}
}

func TestSecureOutput_Success(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	// Test basic success logging
	output.Success("Operation completed", zap.String("operation", "test"))
	
	// Test with dangerous content
	output.Success("Completed \x1b[32msuccessfully\x1b[0m", 
		zap.String("result", "data\x9bwith\x00control"))
}

func TestSecureOutput_Warning(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	// Test warning with dangerous content
	output.Warning("Warning: \x1b[33mcheck configuration\x1b[0m",
		zap.String("config_file", "/etc/test\x00.conf"))
}

func TestSecureOutput_Error(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	// Test error with dangerous content in both message and error
	dangerousErr := errors.New("failed: \x1b[31merror\x1b[0m with CSI " + string(rune(0x9b)))
	output.Error("Operation failed", dangerousErr,
		zap.String("cause", "network\x07timeout"))
}

func TestSecureOutput_Result(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	testCases := []struct {
		name      string
		operation string
		data      interface{}
	}{
		{
			name:      "string result",
			operation: "file_read",
			data:      "content\x1b[31mwith\x1b[0mformatting",
		},
		{
			name:      "slice result",
			operation: "list_files",
			data:      []string{"file1.txt", "file\x9b2.txt", "file\x003.txt"},
		},
		{
			name:      "map result",
			operation: "get_config",
			data: map[string]string{
				"host\x00":     "localhost",
				"port":         "8080",
				"status\x1b[m": "active\x9b",
			},
		},
		{
			name:      "nested map result",
			operation: "complex_data",
			data: map[string]interface{}{
				"users": []string{"alice\x1b[31m", "bob\x9b"},
				"config": map[string]string{
					"timeout\x00": "30s",
				},
				"count": 42,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output.Result(tc.operation, tc.data)
		})
	}
}

func TestSecureOutput_Progress(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	// Test progress with dangerous content
	output.Progress("Processing file\x1b[32m test.txt\x1b[0m", 5, 10,
		zap.String("file", "test\x9b.txt"))
}

func TestSecureOutput_List(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	// Test list with dangerous content
	dangerousItems := []string{
		"item1\x1b[31m",
		"item\x9b2",
		"item3\x00end",
		"normal_item",
	}

	output.List("Available items\x1b[32m", dangerousItems,
		zap.String("source", "database\x07"))
}

func TestSecureOutput_Table(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	// Test table with dangerous content
	headers := []string{"Name\x1b[31m", "Status\x9b", "Count\x00"}
	rows := [][]string{
		{"alice\x1b[32m", "active\x9b", "5\x00"},
		{"bob\x07", "inactive\x1b[31m", "0"},
		{"charlie", "pending\x9b\x00", "3"},
	}

	output.Table("User Statistics\x1b[33m", headers, rows,
		zap.String("report_type", "daily\x00"))
}

func TestSanitizeFields(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	originalFields := []zap.Field{
		zap.String("message", "test\x1b[31mwith\x1b[0mcolors"),
		zap.String("user", "admin\x9b"),
		zap.Error(errors.New("error\x00message")),
		zap.Int("count", 42), // Should remain unchanged
		zap.Bool("active", true), // Should remain unchanged
		zap.Any("data", "string\x1b[32mdata"),
	}

	sanitized := output.sanitizeFields(originalFields)

	if len(sanitized) != len(originalFields) {
		t.Errorf("expected %d fields, got %d", len(originalFields), len(sanitized))
	}

	// Test that string fields are sanitized
	if sanitized[0].String != "testwithcolors" {
		t.Errorf("expected sanitized string field, got %q", sanitized[0].String)
	}

	// Test that non-string fields are preserved
	if sanitized[3].Integer != 42 {
		t.Errorf("expected integer field preserved, got %d", sanitized[3].Integer)
	}
}

func TestSanitizeData(t *testing.T) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)

	testCases := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "string data",
			input:    "test\x1b[31mdata\x1b[0m",
			expected: "testdata",
		},
		{
			name:     "string slice",
			input:    []string{"item1\x9b", "item2\x00", "item3"},
			expected: []string{"item1", "item2", "item3"},
		},
		{
			name:     "string map",
			input:    map[string]string{"key\x1b[m": "value\x9b"},
			expected: map[string]string{"key": "value"},
		},
		{
			name:     "integer data",
			input:    42,
			expected: 42,
		},
		{
			name:     "boolean data",
			input:    true,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := output.sanitizeData(tc.input)
			
			switch expected := tc.expected.(type) {
			case string:
				if result != expected {
					t.Errorf("expected %q, got %q", expected, result)
				}
			case []string:
				resultSlice, ok := result.([]string)
				if !ok {
					t.Errorf("expected []string, got %T", result)
					return
				}
				if len(resultSlice) != len(expected) {
					t.Errorf("expected slice length %d, got %d", len(expected), len(resultSlice))
					return
				}
				for i, expectedItem := range expected {
					if resultSlice[i] != expectedItem {
						t.Errorf("expected slice item %d to be %q, got %q", i, expectedItem, resultSlice[i])
					}
				}
			case map[string]string:
				resultMap, ok := result.(map[string]string)
				if !ok {
					t.Errorf("expected map[string]string, got %T", result)
					return
				}
				for key, expectedValue := range expected {
					if resultMap[key] != expectedValue {
						t.Errorf("expected map[%q] = %q, got %q", key, expectedValue, resultMap[key])
					}
				}
			default:
				if result != expected {
					t.Errorf("expected %v, got %v", expected, result)
				}
			}
		})
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	ctx := context.Background()

	// Test all package-level functions don't panic
	LogInfo(ctx, "info\x1b[31mmessage", zap.String("field", "value\x9b"))
	LogSuccess(ctx, "success\x1b[32mmessage", zap.String("result", "ok\x00"))
	LogWarning(ctx, "warning\x1b[33mmessage", zap.String("issue", "minor\x07"))
	LogError(ctx, "error\x1b[31mmessage", fmt.Errorf("test\x9berror"), zap.String("cause", "test\x00"))
	LogResult(ctx, "operation\x1b[m", "result\x9bdata", zap.String("type", "test\x00"))
	LogProgress(ctx, "step\x1b[32m", 3, 5, zap.String("file", "test\x9b.txt"))
	LogList(ctx, "title\x1b[33m", []string{"item1\x9b", "item2\x00"}, zap.String("source", "db\x07"))
	LogTable(ctx, "table\x1b[35m", []string{"col1\x9b", "col2\x00"}, 
		[][]string{{"val1\x1b[31m", "val2\x9b"}}, zap.String("format", "csv\x00"))
}

// Benchmark tests
func BenchmarkSecureOutput_Info(b *testing.B) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)
	message := "test message with some \x1b[31mdangerous\x1b[0m content"
	fields := []zap.Field{zap.String("user", "test\x9buser")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		output.Info(message, fields...)
	}
}

func BenchmarkSecureOutput_Result(b *testing.B) {
	ctx := context.Background()
	output := NewSecureOutput(ctx)
	data := map[string]interface{}{
		"users": []string{"alice\x1b[31m", "bob\x9b"},
		"config": map[string]string{
			"timeout\x00": "30s",
		},
		"count": 42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		output.Result("test_operation", data)
	}
}

func BenchmarkSecureEscapeOutput(b *testing.B) {
	input := "test message with \x1b[31mdangerous\x1b[0m content and CSI " + string(rune(0x9b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EscapeOutput(input)
	}
}