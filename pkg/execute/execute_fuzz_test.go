// pkg/execute/execute_fuzz_test.go
package execute

import (
	"context"
	"strings"
	"testing"
	"time"
)

// FuzzRun tests command execution with potentially malicious inputs
func FuzzRun(f *testing.F) {
	// Seed with safe commands
	f.Add("echo", []string{"hello"})
	f.Add("ls", []string{"-la"})
	f.Add("true", []string{})
	
	// Seed with potentially dangerous patterns
	f.Add("echo", []string{"$(id)"})      // Command substitution
	f.Add("cat", []string{"/etc/passwd"}) // Sensitive file access
	f.Add("sh", []string{"-c", "echo test"}) // Shell invocation
	
	f.Fuzz(func(t *testing.T, command string, args []string) {
		// Skip empty commands
		if command == "" {
			return
		}
		
		// Skip obviously dangerous commands in fuzzing
		dangerousCommands := []string{"rm", "mkfs", "dd", "format", "del", "deltree"}
		for _, dangerous := range dangerousCommands {
			if strings.Contains(strings.ToLower(command), dangerous) {
				return
			}
		}
		
		// Create context with timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		// Test command execution
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Run panicked on command '%s' with args %v: %v", command, args, r)
			}
		}()
		
		// Test with Options struct
		options := Options{
			Ctx:     ctx,
			Command: command,
			Args:    args,
			Capture: true,
			Timeout: 1 * time.Second,
		}
		
		// Execute command - expect most to fail, we're testing for crashes/hangs
		Run(ctx, options)
	})
}

// FuzzShellMode tests shell command execution for injection vulnerabilities
func FuzzShellMode(f *testing.F) {
	f.Add("echo hello")
	f.Add("ls -la")
	
	// Injection patterns
	f.Add("echo test; id")
	f.Add("ls $(whoami)")
	f.Add("echo `id`")
	f.Add("echo $USER")
	f.Add("echo test\nid")
	
	f.Fuzz(func(t *testing.T, shellCommand string) {
		if shellCommand == "" {
			return
		}
		
		// Skip obviously dangerous commands
		dangerousPatterns := []string{"rm -rf", "mkfs", "format", "dd if=", ">/dev/", "chmod 777"}
		for _, dangerous := range dangerousPatterns {
			if strings.Contains(strings.ToLower(shellCommand), dangerous) {
				return
			}
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Shell execution panicked on command '%s': %v", shellCommand, r)
			}
		}()
		
		// Test shell mode execution
		options := Options{
			Ctx:     ctx,
			Command: shellCommand,
			Shell:   true,
			Capture: true,
			Timeout: 1 * time.Second,
		}
		
		Run(ctx, options)
	})
}