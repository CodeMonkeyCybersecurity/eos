package chatarchive

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveOptions_RemovesBlankAndDestinationSources(t *testing.T) {
	t.Parallel()

	destDir := t.TempDir()
	sourceDir := t.TempDir()

	opts, err := ResolveOptions(Options{
		Sources: []string{"", "   ", sourceDir, destDir},
		Dest:    destDir,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{filepath.Clean(sourceDir)}, opts.Sources)
}

func TestResolvePath_ExpandsAndAbsolutizes(t *testing.T) {
	t.Parallel()

	path, err := resolvePath(".")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(path))
}
