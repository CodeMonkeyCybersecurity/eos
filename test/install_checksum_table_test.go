package test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallScriptChecksumTable(t *testing.T) {
	root := filepath.Clean("..")
	script := filepath.Join(root, "install.sh")
	data, err := os.ReadFile(script)
	require.NoError(t, err)
	goChecksumRegex := regexp.MustCompile(`GO_CHECKSUMS\[[^]]+\]=\"([0-9a-f]{64})\"`)
	matches := goChecksumRegex.FindAllStringSubmatch(string(data), -1)
	require.NotEmpty(t, matches, "expected Go checksum table entries")
	for _, m := range matches {
		require.Len(t, m[1], 64)
	}
	keyRegex := regexp.MustCompile(`GITHUB_CLI_KEY_SHA256=\"([0-9a-f]{64})\"`)
	require.True(t, keyRegex.Match(data), "expected GitHub CLI key checksum entry")
}
