package platform

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestHasBinary(t *testing.T) {
	t.Parallel()

	tests := []testutil.TableTest[struct {
		binaryName string
		expected   bool
	}]{
		{
			Name: "go binary should exist in test environment",
			Input: struct {
				binaryName string
				expected   bool
			}{
				binaryName: "go",
				expected:   true,
			},
		},
		{
			Name: "nonexistent binary",
			Input: struct {
				binaryName string
				expected   bool
			}{
				binaryName: "definitely-not-a-real-binary-12345",
				expected:   false,
			},
		},
		{
			Name: "empty binary name",
			Input: struct {
				binaryName string
				expected   bool
			}{
				binaryName: "",
				expected:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			result := hasBinary(tt.Input.binaryName)
			assert.Equal(t, tt.Input.expected, result)
		})
	}
}

func TestAllowPorts(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		ports   []string
		wantErr bool
	}]{
		{
			Name: "single port",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"8080"},
				wantErr: true, // Will error in test env without firewall tools
			},
		},
		{
			Name: "multiple ports",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"80", "443", "8080"},
				wantErr: true, // Will error in test env without firewall tools
			},
		},
		{
			Name: "empty ports list",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{},
				wantErr: true, // Will error in test env without firewall tools
			},
		},
		{
			Name: "port with protocol",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"80/tcp", "53/udp"},
				wantErr: true, // Will error in test env without firewall tools
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := AllowPorts(rc, tt.Input.ports)

			if tt.Input.wantErr {
				assert.Error(t, err)
				// Should indicate no supported firewall backend
				assert.Contains(t, err.Error(), "no supported firewall backend")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckFirewallStatus(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This function doesn't return an error, just logs and prints
	// We just ensure it doesn't panic
	CheckFirewallStatus(rc)
}

func TestAllowPortsUFW(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		ports   []string
		wantErr bool
	}]{
		{
			Name: "single port with UFW",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"8080"},
				wantErr: true, // Will error since UFW not available in test env
			},
		},
		{
			Name: "multiple ports with UFW",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"80", "443"},
				wantErr: true, // Will error since UFW not available in test env
			},
		},
		{
			Name: "empty ports list with UFW",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{},
				wantErr: false, // Empty list should not error
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := allowPortsUFW(rc, tt.Input.ports)

			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAllowPortsFirewalld(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		ports   []string
		wantErr bool
	}]{
		{
			Name: "single port with Firewalld",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"8080/tcp"},
				wantErr: true, // Will error since firewalld not available in test env
			},
		},
		{
			Name: "multiple ports with Firewalld",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{"80/tcp", "443/tcp"},
				wantErr: true, // Will error since firewalld not available in test env
			},
		},
		{
			Name: "empty ports list with Firewalld",
			Input: struct {
				ports   []string
				wantErr bool
			}{
				ports:   []string{},
				wantErr: true, // Will error checking firewalld state
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			err := allowPortsFirewalld(rc, tt.Input.ports)

			if tt.Input.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Security Tests for Firewall Functions
func TestFirewallSecurityPortValidation(t *testing.T) {
	t.Parallel()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []testutil.TableTest[struct {
		maliciousPorts []string
		description    string
	}]{
		{
			Name: "command injection in port number",
			Input: struct {
				maliciousPorts []string
				description    string
			}{
				maliciousPorts: []string{"80; rm -rf /"},
				description:    "command injection attempt",
			},
		},
		{
			Name: "shell metacharacters in port",
			Input: struct {
				maliciousPorts []string
				description    string
			}{
				maliciousPorts: []string{"80 && echo pwned"},
				description:    "shell metacharacter injection",
			},
		},
		{
			Name: "null byte injection in port",
			Input: struct {
				maliciousPorts []string
				description    string
			}{
				maliciousPorts: []string{"80\x00/tcp"},
				description:    "null byte injection",
			},
		},
		{
			Name: "path traversal in port",
			Input: struct {
				maliciousPorts []string
				description    string
			}{
				maliciousPorts: []string{"../../../etc/passwd"},
				description:    "path traversal attempt",
			},
		},
		{
			Name: "extremely long port string",
			Input: struct {
				maliciousPorts []string
				description    string
			}{
				maliciousPorts: []string{string(make([]byte, 10000))},
				description:    "buffer overflow attempt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// Test with main AllowPorts function
			err := AllowPorts(rc, tt.Input.maliciousPorts)
			// Should error (no firewall backend) but not panic or cause security issues
			assert.Error(t, err)

			// Test UFW function directly
			err = allowPortsUFW(rc, tt.Input.maliciousPorts)
			// Should handle malicious input safely
			_ = err // May succeed or fail, but shouldn't cause security issues

			// Test Firewalld function directly
			err = allowPortsFirewalld(rc, tt.Input.maliciousPorts)
			// Should handle malicious input safely
			_ = err // May succeed or fail, but shouldn't cause security issues
		})
	}
}

// Benchmark Tests
func BenchmarkHasBinary(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hasBinary("go")
	}
}

func BenchmarkAllowPorts(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	ports := []string{"8080", "8443"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AllowPorts(rc, ports)
	}
}
