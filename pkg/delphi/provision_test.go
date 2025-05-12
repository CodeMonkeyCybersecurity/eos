// pkg/delphi/provision_test.go

package delphi

import (
	"testing"
)

func TestResolveWazuhUserID(t *testing.T) {
	id, err := ResolveWazuhUserID("alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty user ID")
	}
}

func TestResolveWazuhRoleID(t *testing.T) {
	id, err := ResolveWazuhRoleID("role_alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty role ID")
	}
}

func TestResolveWazuhPolicyID(t *testing.T) {
	id, err := ResolveWazuhPolicyID("policy_alice")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if id == "" {
		t.Fatal("Expected non-empty policy ID")
	}
}
