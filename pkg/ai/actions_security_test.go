package ai

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestValidateActionRejectsTraversal(t *testing.T) {
	baseDir := t.TempDir()
	policy := &ActionExecutionPolicy{
		WorkspaceAllowlist: []string{baseDir},
		AllowedCommands:    append([]string{}, defaultAllowedCommands...),
		DeniedArguments:    append([]string{}, defaultDeniedArguments...),
		MaxArguments:       defaultMaxArguments,
		MaxCommandLength:   defaultMaxCommandLength,
	}
	executor := NewActionExecutor(baseDir, true, policy)
	action := &Action{
		Type:       ActionTypeFileCreate,
		Target:     "../etc/passwd",
		Content:    "test",
		Validation: &ActionValidation{ValidationProfile: "test-profile"},
	}
	err := executor.validateAction(action)
	require.Error(t, err)
}

func TestValidateActionRejectsSymlinkTraversal(t *testing.T) {
	baseDir := t.TempDir()
	linkedDir := filepath.Join(baseDir, "link")
	require.NoError(t, os.Symlink("/etc", linkedDir))
	policy := &ActionExecutionPolicy{
		WorkspaceAllowlist: []string{baseDir},
		AllowedCommands:    append([]string{}, defaultAllowedCommands...),
		DeniedArguments:    append([]string{}, defaultDeniedArguments...),
		MaxArguments:       defaultMaxArguments,
		MaxCommandLength:   defaultMaxCommandLength,
	}
	executor := NewActionExecutor(baseDir, true, policy)
	action := &Action{
		Type:       ActionTypeFileModify,
		Target:     filepath.Join("link", "passwd"),
		Content:    "test",
		Validation: &ActionValidation{ValidationProfile: "test-profile"},
	}
	err := executor.validateAction(action)
	require.Error(t, err)
}

func TestParseActionsRequiresMetadata(t *testing.T) {
	response := "```json\n[{\"type\":\"command\",\"description\":\"demo\",\"command\":\"ls\"}]\n```"
	_, err := ParseActionsFromResponse(response)
	require.Error(t, err)
}

func TestParseActionsWithValidationMetadata(t *testing.T) {
	response := "```json\n[{\"type\":\"command\",\"description\":\"demo\",\"command\":\"ls\",\"validation\":{\"validation_profile\":\"llm\"}}]\n```"
	actions, err := ParseActionsFromResponse(response)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	require.Equal(t, "llm", actions[0].Validation.ValidationProfile)
}

func TestInjectValidationProfileOverridesLLMMetadata(t *testing.T) {
	actions := []*Action{{
		Type:        ActionTypeCommand,
		Description: "cmd",
		Command:     "ls",
		Validation:  &ActionValidation{ValidationProfile: "remote"},
	}}
	policy := &ActionExecutionPolicy{
		WorkspaceAllowlist: []string{"/tmp"},
		AllowedCommands:    []string{"ls"},
		DeniedArguments:    []string{"rm"},
		MaxArguments:       5,
		MaxCommandLength:   100,
	}
	InjectValidationProfile(actions, "local", policy)
	require.Equal(t, "local", actions[0].Validation.ValidationProfile)
	require.Equal(t, []string{"ls"}, actions[0].Validation.AllowedCommands)
	require.Equal(t, 5, actions[0].Validation.MaxArguments)
	require.Equal(t, 100, actions[0].Validation.MaxCommandLength)
}

func TestActionExecutorCommandPolicy(t *testing.T) {
	baseDir := t.TempDir()
	policy := &ActionExecutionPolicy{
		WorkspaceAllowlist: []string{baseDir},
		AllowedCommands:    []string{"ls"},
		DeniedArguments:    []string{"--force"},
		MaxArguments:       1,
		MaxCommandLength:   10,
	}
	executor := NewActionExecutor(baseDir, true, policy)
	action := &Action{
		Type:        ActionTypeCommand,
		Description: "bad",
		Command:     "rm",
		Arguments:   []string{"-rf"},
		Validation:  &ActionValidation{ValidationProfile: "cli"},
	}
	err := executor.validateAction(action)
	require.Error(t, err)
}

func TestActionExecutorAuditLogging(t *testing.T) {
	baseDir := t.TempDir()
	policy := &ActionExecutionPolicy{
		WorkspaceAllowlist: []string{baseDir},
		AllowedCommands:    []string{"echo"},
		DeniedArguments:    []string{"--bad"},
		MaxArguments:       defaultMaxArguments,
		MaxCommandLength:   defaultMaxCommandLength,
	}
	executor := NewActionExecutor(baseDir, true, policy)
	action := &Action{
		Type:        ActionTypeCommand,
		Description: "ok",
		Command:     "echo",
		Arguments:   []string{"test"},
		Validation:  &ActionValidation{ValidationProfile: "cli"},
	}
	_, _ = executor.ExecuteAction(testutil.TestRuntimeContext(t), action)
	entries, err := os.ReadFile(filepath.Join(baseDir, ".eos-ai-audit", "actions.log"))
	require.NoError(t, err)
	require.Contains(t, string(entries), "\"description\":\"ok\"")
}
