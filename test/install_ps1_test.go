package test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readInstallPS1 reads the install.ps1 script content.
// Shared helper to avoid repeated file reads across tests.
func readInstallPS1(t *testing.T) string {
	t.Helper()
	root := filepath.Clean("..")
	script := filepath.Join(root, "install.ps1")
	data, err := os.ReadFile(script)
	require.NoError(t, err, "install.ps1 must exist and be readable")
	return string(data)
}

// --- Unit Tests (70%) ---

func TestInstallPS1_Exists(t *testing.T) {
	root := filepath.Clean("..")
	script := filepath.Join(root, "install.ps1")
	_, err := os.Stat(script)
	require.NoError(t, err, "install.ps1 must exist in repository root")
}

func TestInstallPS1_RequiresVersion51(t *testing.T) {
	// Regression: original script used PS 7+ expression-if syntax
	// that crashes on default Windows PowerShell 5.1.
	// The #Requires directive ensures PS 5.1 compatibility.
	content := readInstallPS1(t)
	assert.Contains(t, content, "#Requires -Version 5.1",
		"install.ps1 must declare PS 5.1 minimum via #Requires directive")
}

func TestInstallPS1_NoEmojis(t *testing.T) {
	// CLAUDE.md rule: no emojis in code or documentation
	content := readInstallPS1(t)
	// Common emoji ranges: U+1F300-1F9FF, U+2600-26FF, U+2700-27BF
	emojiPattern := regexp.MustCompile(`[\x{1F300}-\x{1F9FF}]|[\x{2600}-\x{26FF}]|[\x{2700}-\x{27BF}]`)
	matches := emojiPattern.FindAllString(content, -1)
	assert.Empty(t, matches,
		"install.ps1 must not contain emojis (CLAUDE.md rule); found: %v", matches)
}

func TestInstallPS1_BuildsPackageNotMainGo(t *testing.T) {
	// Regression: original used 'go build -o ... main.go' which can miss
	// files in the same package. Go best practice is to build '.' (package).
	content := readInstallPS1(t)

	// Must NOT contain 'go build ... main.go'
	mainGoPattern := regexp.MustCompile(`go build\s+.*\s+main\.go`)
	assert.False(t, mainGoPattern.MatchString(content),
		"install.ps1 must build package (.) not main.go; found main.go build target")

	// Must contain 'go build -o ... .'
	assert.Regexp(t, `go build\s+-o\s+\S+\s+\.`, content,
		"install.ps1 must use package-level build target '.'")
}

func TestInstallPS1_StructuredLogging(t *testing.T) {
	content := readInstallPS1(t)

	// Must have Write-Log function with structured format
	assert.Contains(t, content, "function Write-Log",
		"install.ps1 must define Write-Log function for structured logging")

	// Must include ISO 8601 timestamp format
	assert.Contains(t, content, "yyyy-MM-ddTHH:mm:ssZ",
		"install.ps1 must use ISO 8601 timestamps matching install.sh")

	// Must include component field for machine-parseable output
	assert.Contains(t, content, "component=",
		"install.ps1 must include component field in log output")

	// Must include level field
	assert.Contains(t, content, "level=",
		"install.ps1 must include level field in log output")
}

func TestInstallPS1_NoFmtPrintEquivalent(t *testing.T) {
	// P0 rule: no unstructured Write-Host calls outside Write-Log
	content := readInstallPS1(t)

	// Track function scope using brace depth to correctly handle
	// nested blocks (switch/if) inside Write-Log function body.
	lines := strings.Split(content, "\n")
	inWriteLogFunc := false
	braceDepth := 0
	badLines := []int{}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "function Write-Log") {
			inWriteLogFunc = true
			braceDepth = 0
		}

		if inWriteLogFunc {
			braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			// Function body ends when brace depth returns to 0 after opening
			if braceDepth <= 0 && strings.Count(trimmed, "}") > 0 {
				inWriteLogFunc = false
			}
			continue
		}

		// Skip comments and empty lines
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "<#") || trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "Write-Host") {
			badLines = append(badLines, i+1)
		}
	}

	assert.Empty(t, badLines,
		"install.ps1 must not use Write-Host outside Write-Log function (found on lines: %v)", badLines)
}

func TestInstallPS1_AdminCheck(t *testing.T) {
	// Regression: original had no admin check, silently failed writing to Program Files
	content := readInstallPS1(t)
	assert.Contains(t, content, "WindowsBuiltInRole",
		"install.ps1 must check for administrator privileges")
	assert.Contains(t, content, "Assert-Administrator",
		"install.ps1 must have Assert-Administrator function")
}

func TestInstallPS1_GoVersionCheck(t *testing.T) {
	// Regression: original used any Go version without validation
	content := readInstallPS1(t)
	assert.Contains(t, content, "MinGoVersion",
		"install.ps1 must define minimum Go version constant")
	assert.Contains(t, content, "Assert-GoVersion",
		"install.ps1 must validate Go version")
	// Version must match install.sh's GO_VERSION
	assert.Contains(t, content, "1.25.6",
		"install.ps1 MinGoVersion must match install.sh GO_VERSION (1.25.6)")
}

func TestInstallPS1_BinaryValidation(t *testing.T) {
	// Regression: original had no binary validation post-build
	content := readInstallPS1(t)

	// Size check
	assert.Contains(t, content, "1048576",
		"install.ps1 must check binary size against 1MB minimum (matching install.sh)")

	// Smoke test
	assert.Contains(t, content, "--help",
		"install.ps1 must smoke test binary with --help (matching install.sh)")
}

func TestInstallPS1_BackupBeforeOverwrite(t *testing.T) {
	// Regression: original had no backup, destroying previous working binary
	content := readInstallPS1(t)
	assert.Contains(t, content, "Backup-ExistingBinary",
		"install.ps1 must backup existing binary before overwrite")
	assert.Contains(t, content, ".backup.",
		"install.ps1 must use timestamped backup naming convention")
}

func TestInstallPS1_PostCopyIntegrityCheck(t *testing.T) {
	content := readInstallPS1(t)
	// Must verify copied file matches source
	assert.Contains(t, content, "Post-copy integrity",
		"install.ps1 must verify SHA256 after copying binary to install location")
}

func TestInstallPS1_CGOWarning(t *testing.T) {
	// Windows builds lack CGO features - must inform user
	content := readInstallPS1(t)
	assert.Contains(t, content, "CGO",
		"install.ps1 must warn about CGO/feature limitations on Windows")
	assert.Contains(t, content, "libvirt",
		"install.ps1 must mention libvirt unavailability on Windows")
	assert.Contains(t, content, "Ceph",
		"install.ps1 must mention Ceph unavailability on Windows")
}

func TestInstallPS1_ErrorActionPreference(t *testing.T) {
	content := readInstallPS1(t)
	assert.Contains(t, content, `$ErrorActionPreference = "Stop"`,
		"install.ps1 must set ErrorActionPreference to Stop for fail-fast behaviour")
}

func TestInstallPS1_StrictMode(t *testing.T) {
	content := readInstallPS1(t)
	assert.Contains(t, content, "Set-StrictMode",
		"install.ps1 must enable StrictMode for early error detection")
}

func TestInstallPS1_TopLevelErrorHandler(t *testing.T) {
	content := readInstallPS1(t)
	assert.Contains(t, content, "catch",
		"install.ps1 must have top-level try/catch for error handling")
}

func TestInstallPS1_IdempotentDirectoryCreation(t *testing.T) {
	content := readInstallPS1(t)
	// Must check Test-Path before New-Item
	assert.Contains(t, content, "Test-Path $dir",
		"install.ps1 must check directory existence before creation (idempotency)")
}

func TestInstallPS1_IdempotentPathUpdate(t *testing.T) {
	content := readInstallPS1(t)
	assert.Contains(t, content, "-notlike",
		"install.ps1 must check PATH before modification (idempotency)")
}

func TestInstallPS1_RemediationMessages(t *testing.T) {
	// Human-centric design: errors must include remediation
	content := readInstallPS1(t)
	remediationCount := strings.Count(content, "Remediation:")
	assert.GreaterOrEqual(t, remediationCount, 3,
		"install.ps1 must include remediation guidance in error messages (found %d, want >= 3)", remediationCount)
}

func TestInstallPS1_ExitCodes(t *testing.T) {
	content := readInstallPS1(t)
	// Must use distinct exit codes for different failure modes
	for _, code := range []string{"exit 0", "exit 1", "exit 2", "exit 3", "exit 4"} {
		assert.Contains(t, content, code,
			"install.ps1 must use exit code %s for differentiated error handling", code)
	}
}

func TestInstallPS1_NoHardcodedPaths(t *testing.T) {
	// CLAUDE.md P0 rule: no hardcoded values, use constants
	content := readInstallPS1(t)
	lines := strings.Split(content, "\n")

	// Check that key paths are defined as script-scope variables, not inline
	requiredConstants := []string{
		"$script:EosBinaryName",
		"$script:InstallDir",
		"$script:InstallPath",
		"$script:SecretsDir",
		"$script:ConfigDir",
		"$script:LogDir",
	}
	for _, constant := range requiredConstants {
		found := false
		for _, line := range lines {
			if strings.Contains(line, constant) && strings.Contains(line, "=") {
				found = true
				break
			}
		}
		assert.True(t, found,
			"install.ps1 must define %s as a script-scope constant", constant)
	}
}

func TestInstallPS1_NoCertUtilDependency(t *testing.T) {
	// Regression: CertUtil output parsing is locale-dependent.
	// Use Get-FileHash (.NET) instead for locale independence.
	content := readInstallPS1(t)
	assert.NotContains(t, content, "CertUtil",
		"install.ps1 must use Get-FileHash instead of CertUtil (locale-independent)")
}

func TestInstallPS1_GetFileHash(t *testing.T) {
	content := readInstallPS1(t)
	assert.Contains(t, content, "Get-FileHash",
		"install.ps1 must use Get-FileHash for SHA256 computation (PS 5.1+ native)")
}

// --- Integration Tests (20%) ---

func TestInstallPS1_ParityWithInstallSh(t *testing.T) {
	// Verify key features present in install.sh are also in install.ps1
	ps1Content := readInstallPS1(t)

	shRoot := filepath.Clean("..")
	shScript := filepath.Join(shRoot, "install.sh")
	shData, err := os.ReadFile(shScript)
	require.NoError(t, err, "install.sh must exist")
	shContent := string(shData)

	// Feature parity checks
	parityFeatures := []struct {
		name      string
		shMarker  string
		ps1Marker string
	}{
		{"structured logging", "log()", "Write-Log"},
		{"binary validation", "Binary validation failed", "smoke test"},
		{"backup mechanism", "backup_existing_binary", "Backup-ExistingBinary"},
		{"Go version check", "GO_VERSION", "MinGoVersion"},
		{"SHA256 verification", "sha256sum", "Get-FileHash"},
		{"binary size check", "1048576", "1048576"},
		{"help smoke test", `--help`, `--help`},
	}

	for _, f := range parityFeatures {
		shHas := strings.Contains(shContent, f.shMarker)
		ps1Has := strings.Contains(ps1Content, f.ps1Marker)
		assert.True(t, shHas, "install.sh should have feature: %s (marker: %s)", f.name, f.shMarker)
		assert.True(t, ps1Has, "install.ps1 should have feature: %s (marker: %s)", f.name, f.ps1Marker)
	}
}

func TestInstallPS1_GoVersionMatchesInstallSh(t *testing.T) {
	// The minimum Go version in install.ps1 must match install.sh
	ps1Content := readInstallPS1(t)
	shRoot := filepath.Clean("..")
	shScript := filepath.Join(shRoot, "install.sh")
	shData, err := os.ReadFile(shScript)
	require.NoError(t, err)

	// Extract GO_VERSION from install.sh
	shVersionRegex := regexp.MustCompile(`GO_VERSION="(\d+\.\d+\.\d+)"`)
	shMatch := shVersionRegex.FindStringSubmatch(string(shData))
	require.NotNil(t, shMatch, "install.sh must define GO_VERSION")
	shVersion := shMatch[1]

	// Verify install.ps1 contains the same version
	assert.Contains(t, ps1Content, shVersion,
		"install.ps1 MinGoVersion must match install.sh GO_VERSION (%s)", shVersion)
}

func TestInstallPS1_LogFormatMatchesInstallSh(t *testing.T) {
	// Both scripts should produce machine-parseable structured logs
	ps1Content := readInstallPS1(t)

	// install.sh format: TIMESTAMP level=LEVEL component=install.sh msg="MSG"
	// install.ps1 must match this format
	assert.Contains(t, ps1Content, "level=",
		"install.ps1 log format must include level= field (matching install.sh)")
	assert.Contains(t, ps1Content, "component=",
		"install.ps1 log format must include component= field (matching install.sh)")
	assert.Contains(t, ps1Content, `msg="`,
		"install.ps1 log format must include msg= field (matching install.sh)")
}

// --- E2E Tests (10%) - Script syntax validation ---

func TestInstallPS1_ValidPowerShellSyntax(t *testing.T) {
	// Validate that the script doesn't use PS 7+ only syntax
	content := readInstallPS1(t)

	// PS 7+ ternary operator: condition ? true : false
	ternaryPattern := regexp.MustCompile(`\?\s+[^=].*\s*:\s*`)
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and strings
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "<#") {
			continue
		}
		if ternaryPattern.MatchString(line) && !strings.Contains(line, "http") {
			// Exclude URLs which contain ?: patterns
			t.Errorf("line %d may use PS 7+ ternary operator: %s", i+1, trimmed)
		}
	}
}

func TestInstallPS1_NoInlineIfExpression(t *testing.T) {
	// Regression: the original install.ps1 used '$color = if (...) { ... }'
	// which is PS 7+ syntax. PS 5.1 requires separate if/else statements.
	content := readInstallPS1(t)

	// Pattern: '$variable = if (' - this is PS 7+ expression-if
	expressionIfPattern := regexp.MustCompile(`\$\w+\s*=\s*if\s*\(`)
	matches := expressionIfPattern.FindAllString(content, -1)
	assert.Empty(t, matches,
		"install.ps1 must not use PS 7+ expression-if syntax (breaks PS 5.1); found: %v", matches)
}

func TestInstallPS1_DocumentedExitCodes(t *testing.T) {
	content := readInstallPS1(t)
	// Header comments should document exit codes
	exitCodeDocs := []string{
		"0 - Success",
		"1 - General failure",
		"2 - Prerequisites",
		"3 - Build failure",
		"4 - Installation failure",
	}
	for _, doc := range exitCodeDocs {
		assert.Contains(t, content, doc,
			"install.ps1 header must document exit code: %s", doc)
	}
}
