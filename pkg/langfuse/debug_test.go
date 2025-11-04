package langfuse

import (
	"strings"
	"testing"
)

func TestNormalizeConfig(t *testing.T) {
	cfg := normalizeConfig(&Config{})
	if cfg.LangfuseContainer != defaultLangfuseContainer {
		t.Fatalf("expected default Langfuse container %q, got %q", defaultLangfuseContainer, cfg.LangfuseContainer)
	}
	if cfg.DatabaseContainer != defaultDatabaseContainer {
		t.Fatalf("expected default database container %q, got %q", defaultDatabaseContainer, cfg.DatabaseContainer)
	}
	if cfg.DatabaseUser != defaultDatabaseUser {
		t.Fatalf("expected default database user %q, got %q", defaultDatabaseUser, cfg.DatabaseUser)
	}
	if cfg.DatabaseName != defaultDatabaseName {
		t.Fatalf("expected default database name %q, got %q", defaultDatabaseName, cfg.DatabaseName)
	}
	if cfg.LangfuseURL != defaultLangfuseURL {
		t.Fatalf("expected default Langfuse URL %q, got %q", defaultLangfuseURL, cfg.LangfuseURL)
	}
	if cfg.LogTailLines != 200 {
		t.Fatalf("expected default log tail lines 200, got %d", cfg.LogTailLines)
	}

	custom := normalizeConfig(&Config{
		LangfuseContainer: "custom-app",
		DatabaseContainer: "custom-db",
		LangfuseURL:       "http://example.com",
		DatabaseUser:      "user",
		DatabaseName:      "dbname",
		LogTailLines:      50,
	})

	if custom.LangfuseContainer != "custom-app" {
		t.Fatalf("custom container name overridden unexpectedly")
	}
	if custom.LogTailLines != 50 {
		t.Fatalf("custom log tail lines overridden unexpectedly")
	}
}

func TestEnvSliceToMap(t *testing.T) {
	env := []string{"FOO=bar", "BAZ=qux", "INVALID"}
	result := envSliceToMap(env)

	if result["FOO"] != "bar" {
		t.Fatalf("expected FOO=bar, got %q", result["FOO"])
	}
	if _, ok := result["INVALID"]; ok {
		t.Fatalf("expected INVALID to be skipped")
	}
}

func TestRedactEnvValue(t *testing.T) {
	secret := redactEnvValue("SECRET_KEY", "abcdef")
	if secret != "ab**ef" {
		t.Fatalf("expected redacted secret, got %q", secret)
	}

	token := redactEnvValue("access_token", "abcd")
	if token != "****" {
		t.Fatalf("expected total redaction for short token, got %q", token)
	}

	normal := redactEnvValue("NORMAL", "value")
	if normal != "value" {
		t.Fatalf("expected value unchanged, got %q", normal)
	}
}

func TestDetectLogFindings(t *testing.T) {
	logs := `
		error creating user
		next-auth warning detected
		dial tcp: connect: connection refused
	`
	findings := detectLogFindings(logs)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	empty := detectLogFindings("all good")
	if len(empty) != 0 {
		t.Fatalf("expected no findings for clean logs")
	}
}

func TestIndentBlock(t *testing.T) {
	text := "line1\nline2"
	indented := indentBlock(text)
	expected := "  line1\n  line2"
	if indented != expected {
		t.Fatalf("unexpected indentation: %q", indented)
	}
}

func TestSanitizePreview(t *testing.T) {
	short := sanitizePreview("hello\nworld")
	if short != "hello world" {
		t.Fatalf("unexpected preview for short text: %q", short)
	}

	long := strings.Repeat("a", 200)
	sanitized := sanitizePreview(long)
	if len(sanitized) != 120 {
		t.Fatalf("expected preview trimmed to 120 chars, got %d", len(sanitized))
	}
}
