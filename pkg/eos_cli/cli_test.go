// pkg/eos_cli/cli_test.go

package eos_cli

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// newTestContext creates a RuntimeContext suitable for testing
func newTestContext(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()

	return &eos_io.RuntimeContext{
		Ctx:        ctx,
		Log:        logger,
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    t.Name(),
		Attributes: make(map[string]string),
	}
}

func TestCLI_ExecString(t *testing.T) {
	rc := newTestContext(t)
	cli := New(rc)

	// Test successful command
	output, err := cli.ExecString("echo", "hello")
	require.NoError(t, err)
	assert.Equal(t, "hello", output)

	// Test command not found
	_, err = cli.ExecString("command-that-does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed")
}

func TestCLI_ExecToSuccess(t *testing.T) {
	rc := newTestContext(t)
	cli := New(rc)

	// Test successful command
	err := cli.ExecToSuccess("true")
	require.NoError(t, err)

	// Test failing command
	err = cli.ExecToSuccess("false")
	require.Error(t, err)
}

func TestCLI_Which(t *testing.T) {
	rc := newTestContext(t)
	cli := New(rc)

	// Test finding a common command
	path, err := cli.Which("ls")
	require.NoError(t, err)
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "ls")

	// Test command not found
	_, err = cli.Which("command-that-does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCLI_WithTimeout(t *testing.T) {
	rc := newTestContext(t)
	cli := New(rc)

	// Create a CLI with custom timeout
	customCLI := cli.WithTimeout(5 * time.Second)
	assert.NotNil(t, customCLI)
	assert.Equal(t, 5*time.Second, customCLI.timeout)
}
