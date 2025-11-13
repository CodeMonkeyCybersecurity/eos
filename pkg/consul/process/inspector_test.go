// pkg/consul/process/inspector_test.go
//
// Tests for Consul process inspector.
//
// Last Updated: 2025-10-25

package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractDataDirFromCommandLine_EqualsSyntax tests -data-dir=/path format
func TestExtractDataDirFromCommandLine_EqualsSyntax(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -data-dir=/opt/consul -config-dir=/etc/consul.d"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}

// TestExtractDataDirFromCommandLine_SpaceSyntax tests -data-dir /path format
func TestExtractDataDirFromCommandLine_SpaceSyntax(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -data-dir /var/lib/consul -server"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/var/lib/consul", dataDir)
}

// TestExtractDataDirFromCommandLine_DoubleDash tests --data-dir format
func TestExtractDataDirFromCommandLine_DoubleDash(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent --data-dir=/opt/consul/data"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul/data", dataDir)
}

// TestExtractDataDirFromCommandLine_DoubleDashSpace tests --data-dir /path format
func TestExtractDataDirFromCommandLine_DoubleDashSpace(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent --data-dir /var/consul"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/var/consul", dataDir)
}

// TestExtractDataDirFromCommandLine_NoDataDir tests command without data-dir flag
func TestExtractDataDirFromCommandLine_NoDataDir(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -server -bootstrap-expect=1"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data-dir flag not found")
	assert.Empty(t, dataDir)
}

// TestExtractDataDirFromCommandLine_ConfigDirOnly tests command with only config-dir
func TestExtractDataDirFromCommandLine_ConfigDirOnly(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -config-dir=/etc/consul.d"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data-dir may be in config file")
	assert.Empty(t, dataDir)
}

// TestExtractDataDirFromCommandLine_SystemdExecStart tests systemd ExecStart format
func TestExtractDataDirFromCommandLine_SystemdExecStart(t *testing.T) {
	cmdLine := "ExecStart=/usr/local/bin/consul agent -data-dir=/opt/consul -config-dir=/etc/consul.d"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}

// TestExtractDataDirFromCommandLine_PathWithSpaces tests path containing spaces
func TestExtractDataDirFromCommandLine_PathWithSpaces(t *testing.T) {
	// Note: In practice, paths with spaces should be quoted, but our regex handles
	// the unquoted case (extracts until next space)
	cmdLine := `/usr/local/bin/consul agent -data-dir="/opt/consul data" -server`

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	// Will extract until first space or quote
	assert.Contains(t, dataDir, "/opt/consul")
}

// TestExtractDataDirFromCommandLine_MultipleFlags tests extraction with many flags
func TestExtractDataDirFromCommandLine_MultipleFlags(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -server -bootstrap-expect=3 -data-dir=/opt/consul -bind=192.168.1.10 -client=0.0.0.0 -ui"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}

// TestExtractDataDirFromCommandLine_RelativePath tests relative path
func TestExtractDataDirFromCommandLine_RelativePath(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -data-dir=./consul-data"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "./consul-data", dataDir)
}

// TestExtractDataDirFromCommandLine_EmptyCommand tests empty command line
func TestExtractDataDirFromCommandLine_EmptyCommand(t *testing.T) {
	cmdLine := ""

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.Error(t, err)
	assert.Empty(t, dataDir)
}

// TestExtractDataDirFromCommandLine_RealWorldExample tests actual ps aux output
func TestExtractDataDirFromCommandLine_RealWorldExample(t *testing.T) {
	// Realistic ps aux line
	cmdLine := "root      1234  0.5  1.2 123456 67890 ?        Ssl  10:30   0:05 /usr/local/bin/consul agent -server -bootstrap-expect=1 -data-dir=/opt/consul -config-dir=/etc/consul.d -bind={{ GetPrivateIP }}"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/opt/consul", dataDir)
}

// TestExtractDataDirFromCommandLine_DockerizedConsul tests Docker container format
func TestExtractDataDirFromCommandLine_DockerizedConsul(t *testing.T) {
	// Docker might show different format
	cmdLine := "consul agent -data-dir=/consul/data -client=0.0.0.0"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	assert.Equal(t, "/consul/data", dataDir)
}

// TestExtractDataDirFromCommandLine_TrailingSlash tests path with trailing slash
func TestExtractDataDirFromCommandLine_TrailingSlash(t *testing.T) {
	cmdLine := "/usr/local/bin/consul agent -data-dir=/opt/consul/ -server"

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	// Should preserve trailing slash
	assert.Equal(t, "/opt/consul/", dataDir)
}

// TestExtractDataDirFromCommandLine_WindowsStylePath tests Windows-style path
func TestExtractDataDirFromCommandLine_WindowsStylePath(t *testing.T) {
	// Although Eos is Linux-only, test robustness
	cmdLine := `consul.exe agent -data-dir=C:\consul\data`

	dataDir, err := extractDataDirFromCommandLine(cmdLine)

	assert.NoError(t, err)
	// Will extract Windows path
	assert.Contains(t, dataDir, "C:")
}

// Note: Integration tests for GetDataDirFromRunningProcess() require actual
// running processes or mocking, so they're covered in the integration test suite.
// These unit tests focus on the command line parsing logic which is deterministic.
