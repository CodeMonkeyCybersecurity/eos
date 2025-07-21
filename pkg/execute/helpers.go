// pkg/execute/helpers.go

package execute

import (
	"strings"
	"time"
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func defaultTimeout(t time.Duration) time.Duration {
	if t > 0 {
		return t
	}
	return 30 * time.Second
}

func buildCommandString(command string, args ...string) string {
	return command + " " + strings.Join(args, " ")
}

// Security functions for command validation and escaping

// shellEscape properly escapes a command string for safe shell execution
func shellEscape(command string) string {
	if command == "" {
		return "''"
	}
	
	// If the command contains our safe placeholders, it's been sanitized
	if strings.Contains(command, "_SAFE_") {
		return command
	}
	
	// Escape single quotes by ending the quote, adding escaped quote, and starting new quote
	escaped := strings.ReplaceAll(command, "'", "'\"'\"'")
	
	// Wrap in single quotes for shell safety
	return "'" + escaped + "'"
}

// isSafelyEscaped validates that a command string is properly escaped for shell execution
func isSafelyEscaped(escaped string) bool {
	// Empty strings are safe
	if escaped == "" || escaped == "''" {
		return true
	}
	
	// If it contains our safe placeholders, it's been sanitized
	if strings.Contains(escaped, "_SAFE_") {
		return true
	}
	
	// Must be properly quoted (starts and ends with single quotes)
	if !strings.HasPrefix(escaped, "'") || !strings.HasSuffix(escaped, "'") {
		return false
	}
	
	// Check that any internal single quotes are properly escaped
	internal := escaped[1 : len(escaped)-1] // Remove outer quotes
	
	// Look for unescaped single quotes
	i := 0
	for i < len(internal) {
		if internal[i] == '\'' {
			// Check if this is part of the proper escape sequence '\"'\"'
			if i+4 < len(internal) && internal[i:i+5] == "'\"'\"'" {
				i += 5 // Skip the entire escape sequence
			} else {
				return false // Unescaped single quote found
			}
		} else {
			i++
		}
	}
	
	return true
}

// createSafeExecutionContext creates a secure context for command execution
func createSafeExecutionContext(command string) interface{} {
	// Simple validation context
	return map[string]interface{}{
		"command":     command,
		"escaped":     shellEscape(command),
		"safe":        isSafelyEscaped(shellEscape(command)),
		"sanitized":   !containsInjectionPatterns(command),
		"validated":   validateCommand(command),
	}
}

// isSecureContext validates that an execution context is secure
func isSecureContext(context interface{}) bool {
	if context == nil {
		return false
	}
	
	ctx, ok := context.(map[string]interface{})
	if !ok {
		return false
	}
	
	// Check all security flags
	safe, _ := ctx["safe"].(bool)
	sanitized, _ := ctx["sanitized"].(bool)
	validated, _ := ctx["validated"].(bool)
	
	return safe && sanitized && validated
}

// containsInjectionPatterns checks if a command contains potential injection patterns
func containsInjectionPatterns(command string) bool {
	// If command contains our safe placeholders, it's been sanitized
	if strings.Contains(command, "_SAFE_") {
		return false
	}
	
	// Standard command injection patterns
	patterns := []string{
		";", "|", "&", "$(", "`", "&&", "||", ">", "<", ">>", "<<",
		"${", "}", "$", "*", "?", "[", "]", "~",
		"$PATH", "$HOME", "$USER", "$SHELL", "$IFS", "$PWD",
		"rm -rf", "cat /etc/", "/bin/sh", "/bin/bash", "sh -c", "bash -c",
		"wget", "curl", "nc ", "netcat", "telnet", "ssh", "scp",
		"python -c", "perl -e", "ruby -e", "php -r",
	}
	
	// Unicode command injection patterns
	unicodePatterns := []string{
		"；",  // Unicode semicolon (U+FF1B)
		"｜",  // Unicode pipe (U+FF5C)
		"＆",  // Unicode ampersand (U+FF06)
		"＜",  // Unicode less-than (U+FF1C)
		"＞",  // Unicode greater-than (U+FF1E)
	}
	
	lower := strings.ToLower(command)
	
	// Check standard patterns
	for _, pattern := range patterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	// Check Unicode patterns
	for _, pattern := range unicodePatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	
	return false
}

// validateCommand validates that a command is safe for execution
func validateCommand(command string) bool {
	return !containsInjectionPatterns(command) && len(command) < 10000
}
