package backup

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveHomeDirForUser_CurrentUser(t *testing.T) {
	expected, err := os.UserHomeDir()
	require.NoError(t, err)

	actual, err := resolveHomeDirForUser("")
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestResolveHomeDirForUser_Root(t *testing.T) {
	actual, err := resolveHomeDirForUser("root")
	require.NoError(t, err)
	assert.Equal(t, "/root", actual)
}
