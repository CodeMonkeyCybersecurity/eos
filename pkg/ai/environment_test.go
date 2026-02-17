package ai

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentAnalyzerSkipsSecretFilesByDefault(t *testing.T) {
	baseDir := t.TempDir()
	secret := filepath.Join(baseDir, ".env")
	require.NoError(t, os.WriteFile(secret, []byte("PASSWORD=secret"), 0o600))
	analyzer := NewEnvironmentAnalyzer(baseDir)
	ctx, err := analyzer.analyzeFileSystem(testutil.TestRuntimeContext(t))
	require.NoError(t, err)
	for _, file := range ctx.ConfigFiles {
		if strings.HasSuffix(file.Path, ".env") {
			t.Fatalf("secret file should have been skipped: %s", file.Path)
		}
	}

	analyzer = NewEnvironmentAnalyzer(baseDir, WithSecretInclusion(true))
	ctx, err = analyzer.analyzeFileSystem(testutil.TestRuntimeContext(t))
	require.NoError(t, err)
	found := false
	for _, file := range ctx.ConfigFiles {
		if strings.HasSuffix(file.Path, ".env") {
			found = true
			require.Contains(t, file.Excerpt, "sha256")
		}
	}
	if !found {
		t.Fatalf("expected secret file to be analyzed when inclusion is enabled")
	}
}

func TestEnvironmentAnalyzerRedactsSensitiveValues(t *testing.T) {
	analyzer := NewEnvironmentAnalyzer(t.TempDir())
	redacted := analyzer.redact("token=abc1234567890")
	require.Contains(t, redacted, "<redacted>")
}
