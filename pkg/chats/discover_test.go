package chats

import (
	"testing"
)

func TestAvailableToolNames(t *testing.T) {
	names := AvailableToolNames()
	if len(names) == 0 {
		t.Fatal("expected at least one tool name")
	}

	// Verify known tools are present
	expected := map[string]bool{
		ToolClaudeCode: false,
		ToolCodex:      false,
		ToolWindsurf:   false,
		ToolCursor:     false,
	}

	for _, name := range names {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}

	for tool, found := range expected {
		if !found {
			t.Errorf("expected tool %q in AvailableToolNames()", tool)
		}
	}
}

func TestFilterByTools_Empty(t *testing.T) {
	result := &DiscoveryResult{
		Tools: []ToolInfo{
			{Name: ToolClaudeCode, Found: true},
			{Name: ToolCodex, Found: false},
			{Name: ToolWindsurf, Found: true},
		},
	}

	// Empty filter returns all found tools
	filtered := FilterByTools(result, nil)
	if len(filtered) != 2 {
		t.Errorf("expected 2 found tools, got %d", len(filtered))
	}
}

func TestFilterByTools_Specific(t *testing.T) {
	result := &DiscoveryResult{
		Tools: []ToolInfo{
			{Name: ToolClaudeCode, Found: true},
			{Name: ToolCodex, Found: true},
			{Name: ToolWindsurf, Found: true},
		},
	}

	filtered := FilterByTools(result, []string{ToolClaudeCode, ToolCodex})
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered tools, got %d", len(filtered))
	}
	if filtered[0].Name != ToolClaudeCode {
		t.Errorf("expected first tool to be %q, got %q", ToolClaudeCode, filtered[0].Name)
	}
}

func TestFilterByTools_NotFound(t *testing.T) {
	result := &DiscoveryResult{
		Tools: []ToolInfo{
			{Name: ToolClaudeCode, Found: false},
			{Name: ToolCodex, Found: false},
		},
	}

	filtered := FilterByTools(result, []string{ToolClaudeCode})
	if len(filtered) != 0 {
		t.Errorf("expected 0 tools (none found), got %d", len(filtered))
	}
}
