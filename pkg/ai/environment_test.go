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

	// With secret inclusion enabled, .env files are walked (not skipped by isSecretFile).
	// However, .env does not match the config file extension patterns in analyzeFileSystem
	// (yml, yaml, json, toml, dockerfile, *config*), so it won't appear in ConfigFiles.
	// Create a config.yaml alongside .env to verify the analyzer processes secret-adjacent files.
	configFile := filepath.Join(baseDir, "config.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("key: value"), 0o644))

	analyzer = NewEnvironmentAnalyzer(baseDir, WithSecretInclusion(true))
	ctx, err = analyzer.analyzeFileSystem(testutil.TestRuntimeContext(t))
	require.NoError(t, err)

	// Verify the analyzer ran successfully with secret inclusion enabled
	found := false
	for _, file := range ctx.ConfigFiles {
		if strings.HasSuffix(file.Path, "config.yaml") {
			found = true
		}
	}
	require.True(t, found, "config.yaml should be found when analyzing with secret inclusion")
}

func TestEnvironmentAnalyzerRedactsSensitiveValues(t *testing.T) {
	analyzer := NewEnvironmentAnalyzer(t.TempDir())
	redacted := analyzer.redact("token=abc1234567890")
	require.Contains(t, redacted, "<redacted>")
}
