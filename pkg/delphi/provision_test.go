// pkg/delphi/provision_test.go

package delphi

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestResolveWazuhUserID(rc *eos_io.RuntimeContext, t *testing.T) {
	id, err := ResolveWazuhUserID(rc, "alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty user ID")
	}
}

func TestResolveWazuhRoleID(rc *eos_io.RuntimeContext, t *testing.T) {
	id, err := ResolveWazuhRoleID(rc, "role_alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty role ID")
	}
}

func TestResolveWazuhPolicyID(rc *eos_io.RuntimeContext, t *testing.T) {
	id, err := ResolveWazuhPolicyID(rc, "policy_alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty policy ID")
	}
}
