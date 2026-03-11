package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap/zaptest"
)

func TestHandleTLSValidationFailure_InteractiveConsentAccepted(t *testing.T) {
	t.Setenv("Eos_ALLOW_INSECURE_VAULT", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_ADDR", "")

	origPrompt := vaultPromptYesNo
	origInteractive := vaultIsInteractive
	origAuditPath := vaultInsecureAuditLogPath
	t.Cleanup(func() {
		vaultPromptYesNo = origPrompt
		vaultIsInteractive = origInteractive
		vaultInsecureAuditLogPath = origAuditPath
	})
	vaultInsecureAuditLogPath = filepath.Join(t.TempDir(), "vault-insecure-tls-audit.log")

	vaultIsInteractive = func() bool { return true }
	vaultPromptYesNo = func(rc *eos_io.RuntimeContext, question string, defaultYes bool) (bool, error) {
		return true, nil
	}

	addr, err := handleTLSValidationFailure(testRuntimeContext(t), "https://vault.example.com:8200")
	if err != nil {
		t.Fatalf("handleTLSValidationFailure() error = %v", err)
	}

	if got := addr; got != "https://vault.example.com:8200" {
		t.Fatalf("returned addr = %q, want %q", got, "https://vault.example.com:8200")
	}
	if got := getenvOrEmpty("VAULT_SKIP_VERIFY"); got != "1" {
		t.Fatalf("VAULT_SKIP_VERIFY = %q, want 1", got)
	}
	if _, err := os.Stat(vaultInsecureAuditLogPath); err != nil {
		t.Fatalf("expected persistent audit log entry, stat error = %v", err)
	}
}

func TestHandleTLSValidationFailure_InteractiveConsentDeclined(t *testing.T) {
	t.Setenv("Eos_ALLOW_INSECURE_VAULT", "")

	origPrompt := vaultPromptYesNo
	origInteractive := vaultIsInteractive
	t.Cleanup(func() {
		vaultPromptYesNo = origPrompt
		vaultIsInteractive = origInteractive
	})

	vaultIsInteractive = func() bool { return true }
	vaultPromptYesNo = func(rc *eos_io.RuntimeContext, question string, defaultYes bool) (bool, error) {
		return false, nil
	}

	if _, err := handleTLSValidationFailure(testRuntimeContext(t), "https://vault.example.com:8200"); err == nil {
		t.Fatal("expected error when user declines insecure TLS")
	}
}

func TestHandleTLSValidationFailure_NonInteractive_Unit(t *testing.T) {
	t.Setenv("Eos_ALLOW_INSECURE_VAULT", "")

	origInteractive := vaultIsInteractive
	t.Cleanup(func() { vaultIsInteractive = origInteractive })

	vaultIsInteractive = func() bool { return false }

	_, err := handleTLSValidationFailure(testRuntimeContext(t), "https://vault.example.com:8200")
	if err == nil {
		t.Fatal("expected error in non-interactive mode")
	}
	// Verify error contains remediation guidance
	errMsg := err.Error()
	if !testContains(errMsg, "Remediation") {
		t.Fatalf("error should contain remediation steps, got: %s", errMsg)
	}
}

func TestHandleTLSValidationFailure_DevModeOverride(t *testing.T) {
	t.Setenv("Eos_ALLOW_INSECURE_VAULT", "true")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_ADDR", "")
	origAuditPath := vaultInsecureAuditLogPath
	t.Cleanup(func() { vaultInsecureAuditLogPath = origAuditPath })
	vaultInsecureAuditLogPath = filepath.Join(t.TempDir(), "vault-insecure-tls-audit.log")

	addr, err := handleTLSValidationFailure(testRuntimeContext(t), "https://vault.example.com:8200")
	if err != nil {
		t.Fatalf("handleTLSValidationFailure() error = %v", err)
	}
	if addr != "https://vault.example.com:8200" {
		t.Fatalf("returned addr = %q, want %q", addr, "https://vault.example.com:8200")
	}
	if got := getenvOrEmpty("VAULT_SKIP_VERIFY"); got != "1" {
		t.Fatalf("VAULT_SKIP_VERIFY = %q, want 1", got)
	}
	if _, err := os.Stat(vaultInsecureAuditLogPath); err != nil {
		t.Fatalf("expected persistent audit log entry, stat error = %v", err)
	}
}

func TestHandleTLSValidationFailure_PromptDefaultsToNo(t *testing.T) {
	t.Setenv("Eos_ALLOW_INSECURE_VAULT", "")

	origPrompt := vaultPromptYesNo
	origInteractive := vaultIsInteractive
	t.Cleanup(func() {
		vaultPromptYesNo = origPrompt
		vaultIsInteractive = origInteractive
	})

	var capturedDefaultYes bool
	vaultIsInteractive = func() bool { return true }
	vaultPromptYesNo = func(rc *eos_io.RuntimeContext, question string, defaultYes bool) (bool, error) {
		capturedDefaultYes = defaultYes
		return false, nil // decline
	}

	_, _ = handleTLSValidationFailure(testRuntimeContext(t), "https://vault.example.com:8200")
	if capturedDefaultYes {
		t.Fatal("TLS consent prompt should default to NO (defaultYes=false) for safety")
	}
}

func TestHandleTLSValidationFailure_AuditFailureBlocksInsecureFallback(t *testing.T) {
	t.Setenv("Eos_ALLOW_INSECURE_VAULT", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_ADDR", "")

	origPrompt := vaultPromptYesNo
	origInteractive := vaultIsInteractive
	origAuditPath := vaultInsecureAuditLogPath
	t.Cleanup(func() {
		vaultPromptYesNo = origPrompt
		vaultIsInteractive = origInteractive
		vaultInsecureAuditLogPath = origAuditPath
	})

	vaultIsInteractive = func() bool { return true }
	vaultPromptYesNo = func(rc *eos_io.RuntimeContext, question string, defaultYes bool) (bool, error) {
		return true, nil
	}
	vaultInsecureAuditLogPath = t.TempDir()

	_, err := handleTLSValidationFailure(testRuntimeContext(t), "https://vault.example.com:8200")
	if err == nil {
		t.Fatal("expected audit trail failure to block insecure fallback")
	}
	if !testContains(err.Error(), "audit trail") {
		t.Fatalf("expected audit trail error, got: %v", err)
	}
}

func testRuntimeContext(t *testing.T) *eos_io.RuntimeContext {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return &eos_io.RuntimeContext{
		Ctx:        ctx,
		Log:        zaptest.NewLogger(t),
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    "test",
		Attributes: map[string]string{},
	}
}

func getenvOrEmpty(key string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return ""
	}
	return val
}

// testContains checks if haystack contains needle.
// Named to avoid collision with contains() in discovery.go.
func testContains(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
