package chatarchive

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "simple lowercase", input: "hello", expected: "hello"},
		{name: "uppercase converted", input: "Hello World", expected: "hello-world"},
		{name: "special chars removed", input: "chat@2024!.v2", expected: "chat2024v2"},
		{name: "underscores to hyphens", input: "my_chat_log", expected: "my-chat-log"},
		{name: "multiple spaces collapsed", input: "a   b   c", expected: "a-b-c"},
		{name: "leading trailing hyphens trimmed", input: "---hello---", expected: "hello"},
		{name: "empty string", input: "", expected: ""},
		{name: "whitespace only", input: "   ", expected: ""},
		{name: "all special chars", input: "!@#$%^&*()", expected: ""},
		{name: "unicode stripped", input: "café-résumé", expected: "caf-rsum"},
		{name: "numbers preserved", input: "session-2024-01-15", expected: "session-2024-01-15"},
		{name: "max length truncated", input: "this-is-a-very-long-filename-that-exceeds-the-maximum-allowed-slug-length", expected: "this-is-a-very-long-filename-that-exceed"},
		{name: "mixed separators", input: "hello_world-foo bar", expected: "hello-world-foo-bar"},
		{name: "consecutive hyphens collapsed", input: "a--b---c", expected: "a-b-c"},
		{name: "CJK characters stripped", input: "对话记录", expected: ""},
		{name: "emoji stripped", input: "chat-🤖-log", expected: "chat-log"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SanitizeName(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func BenchmarkSanitizeName(b *testing.B) {
	input := "Chat with Claude - Session 2024-01-15T14:30:00"
	for b.Loop() {
		SanitizeName(input)
	}
}
