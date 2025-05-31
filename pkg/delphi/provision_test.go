package delphi

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Dummy or mock rc for testing. Adjust as needed for your test context.
func newTestRuntimeContext() *eos_io.RuntimeContext {
	return &eos_io.RuntimeContext{}
}

func TestResolveWazuhUserID(t *testing.T) {
	rc := newTestRuntimeContext()
	id, err := ResolveWazuhUserID(rc, "alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty user ID")
	}
}

func TestResolveWazuhRoleID(t *testing.T) {
	rc := newTestRuntimeContext()
	id, err := ResolveWazuhRoleID(rc, "role_alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty role ID")
	}
}

func TestResolveWazuhPolicyID(t *testing.T) {
	rc := newTestRuntimeContext()
	id, err := ResolveWazuhPolicyID(rc, "policy_alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty policy ID")
	}
}
