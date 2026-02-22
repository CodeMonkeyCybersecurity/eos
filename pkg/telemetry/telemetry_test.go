package telemetry

import (
	"strings"
	"testing"
)

func TestSanitizeTagValueSensitiveKey(t *testing.T) {
	t.Parallel()

	got := sanitizeTagValue("vault_token", "hvs.supersecret")
	if got != "[REDACTED]" {
		t.Fatalf("expected redacted token, got %q", got)
	}
}

func TestSanitizeTagValueURLRedaction(t *testing.T) {
	t.Parallel()

	in := "https://alice:secret@example.com/path?token=abc123&mode=ok"
	got := sanitizeTagValue("endpoint", in)

	if got == in {
		t.Fatalf("expected URL to be sanitized")
	}
	if strings.Contains(got, "alice") || strings.Contains(got, "secret") || strings.Contains(got, "abc123") {
		t.Fatalf("expected credentials and token to be removed, got %q", got)
	}
	if !strings.Contains(got, "mode=ok") {
		t.Fatalf("expected non-sensitive query params to remain, got %q", got)
	}
}

func TestSanitizeRawSecretsAssignment(t *testing.T) {
	t.Parallel()

	in := "token=abc password=s3cr3t api_key=xyz safe=value"
	got := sanitizeRawSecrets(in)

	if strings.Contains(got, "abc") || strings.Contains(got, "s3cr3t") || strings.Contains(got, "xyz") {
		t.Fatalf("expected secret values to be redacted, got %q", got)
	}
	if !strings.Contains(got, "safe=value") {
		t.Fatalf("expected non-secret fields to remain, got %q", got)
	}
}

func TestTruncateOrHashArgsRedactsSecretsAndTruncates(t *testing.T) {
	t.Parallel()

	in := []string{"--token=abcdef", "--mode=test", "--payload=" + strings.Repeat("x", 300)}
	got := TruncateOrHashArgs(in)

	if strings.Contains(got, "abcdef") {
		t.Fatalf("expected token value to be redacted, got %q", got)
	}
	if len(got) > 259 {
		t.Fatalf("expected truncated output length <= 259, got %d", len(got))
	}
}
