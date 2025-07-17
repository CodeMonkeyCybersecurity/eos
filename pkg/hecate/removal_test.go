// pkg/hecate/removal_test.go

package hecate

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestAssessHecateComponents(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Component: "test",
	}

	// Test assess function (should not fail even if no components exist)
	err := assessHecateComponents(rc)
	if err != nil {
		t.Errorf("assessHecateComponents() error = %v, want nil", err)
	}
}

func TestRemoveHecateVaultSecrets(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Component: "test",
	}

	// Test removing vault secrets (should not fail even if vault is not running)
	err := removeHecateVaultSecrets(rc)
	if err != nil {
		t.Errorf("removeHecateVaultSecrets() error = %v, want nil", err)
	}
}

func TestRemoveHecateDirectories(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Component: "test",
	}

	// Test removing directories (should not fail even if directories don't exist)
	err := removeHecateDirectories(rc, false)
	if err != nil {
		t.Errorf("removeHecateDirectories() error = %v, want nil", err)
	}

	// Test with keepData=true
	err = removeHecateDirectories(rc, true)
	if err != nil {
		t.Errorf("removeHecateDirectories(keepData=true) error = %v, want nil", err)
	}
}

func TestStopHecateNomadJobs(t *testing.T) {
	// Create test runtime context  
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Component: "test",
	}

	// Test stopping nomad jobs (should not fail even if nomad is not running)
	err := stopHecateNomadJobs(rc)
	if err != nil {
		t.Errorf("stopHecateNomadJobs() error = %v, want nil", err)
	}
}

func TestRemoveHecateSystemdServices(t *testing.T) {
	// Create test runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)  
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Component: "test",
	}

	// Test removing systemd services (should not fail even if services don't exist)
	err := removeHecateSystemdServices(rc)
	if err != nil {
		t.Errorf("removeHecateSystemdServices() error = %v, want nil", err)
	}
}