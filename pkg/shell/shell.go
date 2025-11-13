//pkg/shell/shell.go

package shell

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/shell"
)

// SplitFields splits a shell command line into fields, respecting quotes and escapes.
// Example: SplitFields(`echo "hello world" && ls -l`) → []string{"echo", "hello world", "&&", "ls", "-l"}
func SplitFields(cmdline string) ([]string, error) {
	return shell.Fields(cmdline, nil)
}

// ShellQuote quotes a single argument for shell safety.
// Example: ShellQuote(`foo bar`) → "'foo bar'"
func ShellQuote(arg string) string {
	// Wrap in single quotes and escape any single quotes inside
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// ShellQuoteAll quotes and joins multiple args for shell use.
// Example: ShellQuoteAll([]string{"echo", "foo bar"}) → "echo 'foo bar'"
func ShellQuoteAll(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = ShellQuote(a)
	}
	return strings.Join(quoted, " ")
}

// JoinArgsForDisplay is a readable way to display command args, using quoting as needed.
func JoinArgsForDisplay(args []string) string {
	return ShellQuoteAll(args)
}

// IsShellSafe returns true if the string contains no shell metacharacters.
func IsShellSafe(s string) bool {
	return !strings.ContainsAny(s, "$`&|;<>*?()[]{}\\\"'")
}

// DetectShellMeta returns true if the string appears to use shell metacharacters.
func DetectShellMeta(s string) bool {
	return !IsShellSafe(s)
}

// ParseAssignment parses shell-style KEY=VALUE assignments.
// Example: ParseAssignment(`FOO=bar`) → "FOO", "bar", nil
func ParseAssignment(s string) (key, value string, err error) {
	i := strings.Index(s, "=")
	if i <= 0 {
		return "", "", fmt.Errorf("invalid assignment: %s", s)
	}
	key = s[:i]
	value = s[i+1:]
	return key, value, nil
}
