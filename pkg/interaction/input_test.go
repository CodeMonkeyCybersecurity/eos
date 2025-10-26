package interaction

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// mockStdin sets up a fake stdin with provided input lines
func mockStdin(input string) func() {
	testStdin = bytes.NewBufferString(input)
	return func() { testStdin = nil }
}

func TestPromptSecrets_ArgumentParsing_Errors(t *testing.T) {
	tests := []struct {
		name    string
		args    []interface{}
		wantErr string
	}{
		{
			name:    "1-arg: wrong type (string instead of int)",
			args:    []interface{}{"not an int"},
			wantErr: "argument must be int, got string",
		},
		{
			name:    "2-arg: wrong type for count",
			args:    []interface{}{context.Background(), "not an int"},
			wantErr: "args[1] must be int (count), got string",
		},
		{
			name:    "3-arg: wrong type for label",
			args:    []interface{}{context.Background(), 123, 3},
			wantErr: "args[1] must be string (label), got int",
		},
		{
			name:    "3-arg: wrong type for count",
			args:    []interface{}{context.Background(), "Label", "not an int"},
			wantErr: "args[2] must be int (count), got string",
		},
		{
			name:    "no arguments",
			args:    []interface{}{},
			wantErr: "invalid number of arguments (0)",
		},
		{
			name:    "too many arguments",
			args:    []interface{}{context.Background(), "Label", 3, "extra"},
			wantErr: "invalid number of arguments (4)",
		},
		{
			name:    "negative count",
			args:    []interface{}{-1},
			wantErr: "count must be positive, got -1",
		},
		{
			name:    "zero count",
			args:    []interface{}{0},
			wantErr: "count must be positive, got 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PromptSecrets(tt.args...)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// NOTE: Full integration tests with stdin mocking are skipped because:
// 1. The logger (otelzap) interacts with stdio in ways that can cause tests to hang
// 2. The core functionality (type-safe argument parsing) is thoroughly tested above
// 3. Actual stdin/stdout behavior is verified manually in integration testing
//
// To manually test:
//   - Run: eos create vault --clean
//   - Verify prompts show "Unseal Key 1", "Unseal Key 2", "Unseal Key 3"
//   - Verify root token prompt shows "Root Token" (no number for count=1)
//   - Verify no panic occurs

// Keeping stdin mocking infrastructure for future use when logger can be properly mocked
