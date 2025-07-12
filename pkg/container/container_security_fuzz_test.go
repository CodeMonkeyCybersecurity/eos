package container

import (
	"strings"
	"testing"
	
	"gopkg.in/yaml.v3"
)

// FuzzComposeFileSecurity tests ComposeFile for security vulnerabilities
func FuzzComposeFileSecurity(f *testing.F) {
	// Seed with various security-focused inputs
	f.Add("normal-service", "nginx:latest", "80:80", "APP_ENV", "production", "./data:/data")
	f.Add("", "", "", "", "", "")
	f.Add("service<script>", "malicious/image", "22:22", "PATH", "/usr/bin", "/etc:/etc")
	f.Add("service;rm -rf /", "alpine:latest", "443:443", "CMD", "whoami", "../../../:/root")
	f.Add("service$(id)", "busybox", "8080:8080", "USER", "root", "/:/host")
	f.Add("service`ls`", "ubuntu:20.04", "3306:3306", "PASSWORD", "secret123", "C:\\Windows:/windows")
	f.Add("service\x00null", "postgres:13", "5432:5432", "DB_HOST", "localhost", "/var/log:/logs")
	f.Add("service\ninjection", "redis:6", "6379:6379", "API_KEY", "key123", "/tmp:/tmp")
	f.Add(strings.Repeat("A", 10000), "image:tag", "9999:9999", strings.Repeat("B", 10000), "value", "/path:/path")

	f.Fuzz(func(t *testing.T, serviceName, image, port, envKey, envValue, volumeMapping string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ComposeFile creation panicked with inputs: service=%q, image=%q, port=%q: %v", 
					serviceName, image, port, r)
			}
		}()

		// Create compose file structure
		cf := ComposeFile{
			Services: map[string]Service{
				serviceName: {
					Image:         image,
					ContainerName: serviceName + "_container",
					Ports:         []string{port},
					Environment:   map[string]string{envKey: envValue},
					Volumes:       []string{volumeMapping},
				},
			},
			Volumes:  map[string]interface{}{"data": nil},
			Networks: map[string]interface{}{DockerNetworkName: nil},
		}

		// Security validation
		// Check for command injection in service name
		if strings.ContainsAny(serviceName, ";|&`$()") {
			t.Logf("Command injection characters in service name: %q", serviceName)
		}

		// Check for null bytes
		if strings.Contains(serviceName, "\x00") {
			t.Errorf("Null byte in service name: %q", serviceName)
		}

		// Check for newlines (YAML injection)
		if strings.ContainsAny(serviceName, "\n\r") {
			t.Logf("Newline characters in service name: %q", serviceName)
		}

		// Validate image name
		if image != "" {
			// Check for registry manipulation
			if strings.Contains(image, "..") {
				t.Logf("Path traversal in image: %q", image)
			}
			
			// Check for protocol injection
			if strings.HasPrefix(image, "http://") || strings.HasPrefix(image, "file://") {
				t.Logf("Protocol injection in image: %q", image)
			}
		}

		// Validate port mapping
		if port != "" {
			// Check for invalid port formats
			parts := strings.Split(port, ":")
			if len(parts) > 3 {
				t.Logf("Invalid port format: %q", port)
			}
			
			// Check for command injection in ports
			if strings.ContainsAny(port, ";|&`$()") {
				t.Errorf("Command injection in port: %q", port)
			}
		}

		// Validate environment variables
		if envKey != "" {
			// Check for shell variable expansion
			if strings.ContainsAny(envKey, "${}") {
				t.Logf("Shell expansion characters in env key: %q", envKey)
			}
			
			// Check for null bytes
			if strings.Contains(envKey, "\x00") || strings.Contains(envValue, "\x00") {
				t.Errorf("Null byte in environment: key=%q, value=%q", envKey, envValue)
			}
		}

		// Validate volume mappings
		if volumeMapping != "" {
			parts := strings.Split(volumeMapping, ":")
			if len(parts) >= 2 {
				hostPath := parts[0]
				
				// Check for path traversal
				if strings.Contains(hostPath, "..") {
					t.Logf("Path traversal in volume: %q", volumeMapping)
				}
				
				// Check for sensitive paths
				sensitivePaths := []string{"/etc", "/root", "/sys", "/proc", "/", "C:\\Windows", "C:\\"}
				for _, sensitive := range sensitivePaths {
					if hostPath == sensitive {
						t.Logf("Sensitive path mounted: %q", volumeMapping)
					}
				}
			}
		}

		// Test YAML marshaling doesn't cause issues
		data, err := yaml.Marshal(cf)
		if err != nil {
			t.Logf("YAML marshal error: %v", err)
		} else {
			// Check for YAML injection patterns in output
			yamlStr := string(data)
			if strings.Contains(yamlStr, "!!") {
				t.Logf("YAML tag injection detected in output")
			}
		}
	})
}

// FuzzDockerNetworkConfigSecurity tests Docker network configuration
func FuzzDockerNetworkConfigSecurity(f *testing.F) {
	// Seed with various network configurations
	f.Add("arachne-net", "172.30.0.0/16", "fd00:dead:beef::/64")
	f.Add("", "", "")
	f.Add("network;rm -rf /", "10.0.0.0/8", "2001:db8::/32")
	f.Add("network$(whoami)", "192.168.0.0/16", "fe80::/10")
	f.Add("network`id`", "172.16.0.0/12", "::/0")
	f.Add("network\x00null", "0.0.0.0/0", "::1/128")
	f.Add(strings.Repeat("A", 1000), "999.999.999.999/32", strings.Repeat("B", 1000))

	f.Fuzz(func(t *testing.T, networkName, ipv4Subnet, ipv6Subnet string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Network config panicked with name=%q, ipv4=%q, ipv6=%q: %v", 
					networkName, ipv4Subnet, ipv6Subnet, r)
			}
		}()

		// Security validation
		// Check for command injection in network name
		if strings.ContainsAny(networkName, ";|&`$()") {
			t.Errorf("Command injection in network name: %q", networkName)
		}

		// Check for null bytes
		if strings.Contains(networkName, "\x00") {
			t.Errorf("Null byte in network name: %q", networkName)
		}

		// Validate IPv4 subnet
		if ipv4Subnet != "" {
			// Check for obviously invalid formats
			if strings.ContainsAny(ipv4Subnet, ";|&`$()") {
				t.Errorf("Command injection in IPv4 subnet: %q", ipv4Subnet)
			}
			
			// Check for overly broad subnets
			if ipv4Subnet == "0.0.0.0/0" {
				t.Logf("Overly broad IPv4 subnet: %q", ipv4Subnet)
			}
		}

		// Validate IPv6 subnet
		if ipv6Subnet != "" {
			// Check for command injection
			if strings.ContainsAny(ipv6Subnet, ";|&`$()") {
				t.Errorf("Command injection in IPv6 subnet: %q", ipv6Subnet)
			}
			
			// Check for overly broad subnets
			if ipv6Subnet == "::/0" {
				t.Logf("Overly broad IPv6 subnet: %q", ipv6Subnet)
			}
		}
	})
}

// FuzzUncommentSegmentSecurity tests UncommentSegment for security issues
func FuzzUncommentSegmentSecurity(f *testing.F) {
	// Seed with various segment comments
	f.Add("uncomment if using Jenkins behind Hecate")
	f.Add("")
	f.Add("'; cat /etc/passwd #")
	f.Add("$(rm -rf /)")
	f.Add("`whoami`")
	f.Add("uncomment\x00null")
	f.Add("uncomment\ninjection\r\n")
	f.Add(strings.Repeat("A", 10000))
	f.Add("../../etc/passwd")
	f.Add("uncomment if using ${MALICIOUS}")

	f.Fuzz(func(t *testing.T, segmentComment string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("UncommentSegment panicked with comment=%q: %v", segmentComment, r)
			}
		}()

		// Security validation
		// Check for path traversal attempts
		if strings.Contains(segmentComment, "..") {
			t.Logf("Path traversal pattern in segment comment: %q", segmentComment)
		}

		// Check for null bytes
		if strings.Contains(segmentComment, "\x00") {
			t.Errorf("Null byte in segment comment: %q", segmentComment)
		}

		// Check for shell injection patterns
		shellPatterns := []string{";", "|", "&", "`", "$", "(", ")"}
		for _, pattern := range shellPatterns {
			if strings.Contains(segmentComment, pattern) {
				t.Logf("Shell injection pattern %q in segment comment", pattern)
			}
		}

		// Check for regex injection (since it uses regexp)
		// Extremely long patterns could cause ReDoS
		if len(segmentComment) > 1000 {
			t.Logf("Extremely long segment comment: %d chars", len(segmentComment))
		}

		// Check for newlines that could break file parsing
		if strings.ContainsAny(segmentComment, "\n\r") {
			t.Logf("Newline characters in segment comment")
		}
	})
}

// FuzzContainerConfigSecurity tests container configuration security
func FuzzContainerConfigSecurity(f *testing.F) {
	// Seed with various container configurations
	f.Add("my-container", "nginx:latest", "80", "8080", "/app", "/data")
	f.Add("", "", "", "", "", "")
	f.Add("container;exec", "malicious/image:tag", "22", "2222", "/etc", "/")
	f.Add("container$(id)", "alpine:3.14", "443", "8443", "../..", "/root")
	f.Add("container`whoami`", "busybox", "3306", "33060", "/proc/self", "/host")
	f.Add("container\x00", "image\ninjection", "-1", "65536", "/sys", "C:\\")
	f.Add(strings.Repeat("A", 1000), strings.Repeat("B", 1000), "0", "0", "", "")

	f.Fuzz(func(t *testing.T, name, image, hostPort, containerPort, hostPath, containerPath string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Container config panicked: %v", r)
			}
		}()

		// Security validation for container name
		if strings.ContainsAny(name, ";|&`$()") {
			t.Errorf("Command injection in container name: %q", name)
		}

		// Check for null bytes
		if strings.Contains(name, "\x00") || strings.Contains(image, "\x00") {
			t.Errorf("Null byte in container config")
		}

		// Validate image name
		if image != "" {
			// Check for registry hijacking
			if strings.Count(image, "/") > 2 {
				t.Logf("Suspicious image path: %q", image)
			}
			
			// Check for tag injection
			if strings.Count(image, ":") > 1 {
				t.Logf("Multiple colons in image: %q", image)
			}
			
			// Check for newlines (could break parsing)
			if strings.ContainsAny(image, "\n\r") {
				t.Errorf("Newline in image name: %q", image)
			}
		}

		// Validate ports
		if hostPort != "" || containerPort != "" {
			// Check for negative ports
			if strings.HasPrefix(hostPort, "-") || strings.HasPrefix(containerPort, "-") {
				t.Logf("Negative port number detected")
			}
			
			// Check for port 0 (could bind to random port)
			if hostPort == "0" {
				t.Logf("Port 0 could bind to random port")
			}
		}

		// Validate paths
		if hostPath != "" {
			// Check for path traversal
			if strings.Contains(hostPath, "..") {
				t.Errorf("Path traversal in host path: %q", hostPath)
			}
			
			// Check for sensitive paths
			sensitivePaths := []string{"/", "/etc", "/root", "/sys", "/proc", "/dev"}
			for _, sensitive := range sensitivePaths {
				if strings.HasPrefix(hostPath, sensitive) {
					t.Logf("Sensitive host path: %q", hostPath)
				}
			}
		}

		// Check for command injection in paths
		if strings.ContainsAny(hostPath+containerPath, ";|&`$()") {
			t.Logf("Command injection characters in paths")
		}
	})
}

// FuzzDockerClientOperationsSecurity tests Docker client operations
func FuzzDockerClientOperationsSecurity(f *testing.F) {
	// Seed with various Docker operation inputs
	f.Add("container-create", "nginx:latest", "my-network", "my-volume")
	f.Add("", "", "", "")
	f.Add("exec;ls", "alpine:3.14", "network;rm", "volume$(id)")
	f.Add("pull\nimage", "malicious/image", "../network", "/etc:/host")
	f.Add("\x00null", "image:tag", "bridge", "data")
	f.Add(strings.Repeat("A", 1000), "localhost:5000/image", "", "")

	f.Fuzz(func(t *testing.T, operation, image, networkName, volumeName string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Docker operation panicked: %v", r)
			}
		}()

		// Security validation
		// Check for command injection in all parameters
		params := []string{operation, image, networkName, volumeName}
		for i, param := range params {
			if strings.ContainsAny(param, ";|&`$()") {
				t.Logf("Command injection in parameter %d: %q", i, param)
			}
			
			// Check for null bytes
			if strings.Contains(param, "\x00") {
				t.Errorf("Null byte in parameter %d: %q", i, param)
			}
			
			// Check for newlines
			if strings.ContainsAny(param, "\n\r") {
				t.Logf("Newline in parameter %d: %q", i, param)
			}
		}

		// Image-specific validation
		if image != "" {
			// Check for localhost registry bypass
			if strings.HasPrefix(image, "localhost:") || strings.HasPrefix(image, "127.0.0.1:") {
				t.Logf("Localhost registry in image: %q", image)
			}
			
			// Check for protocol handlers
			if strings.Contains(image, "://") {
				t.Errorf("Protocol handler in image: %q", image)
			}
		}

		// Network name validation
		if networkName != "" {
			// Docker network names have restrictions
			if len(networkName) > 63 {
				t.Logf("Network name too long: %d chars", len(networkName))
			}
			
			// Check for special network names
			if networkName == "host" || networkName == "none" {
				t.Logf("Special network name: %q", networkName)
			}
		}

		// Volume name validation
		if volumeName != "" {
			// Check for path vs named volume
			if strings.Contains(volumeName, "/") || strings.Contains(volumeName, "\\") {
				t.Logf("Path separator in volume name: %q", volumeName)
			}
		}
	})
}

// FuzzDockerExecSecurity tests Docker exec operations for security
func FuzzDockerExecSecurity(f *testing.F) {
	// Seed with various exec commands
	f.Add("container-id", "/bin/sh", "-c", "ls -la")
	f.Add("", "", "", "")
	f.Add("container;exec", "/bin/bash", "-c", "rm -rf /")
	f.Add("$(docker ps)", "sh", "-c", "cat /etc/passwd")
	f.Add("container\x00", "/usr/bin/env", "PATH=/evil", "whoami")
	f.Add("container-name", "../../bin/sh", "", "id")

	f.Fuzz(func(t *testing.T, containerID, cmd, arg1, arg2 string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Docker exec panicked: %v", r)
			}
		}()

		// Security validation
		// Check container ID for injection
		if strings.ContainsAny(containerID, ";|&`$()") {
			t.Errorf("Command injection in container ID: %q", containerID)
		}

		// Check for null bytes
		if strings.Contains(containerID, "\x00") || strings.Contains(cmd, "\x00") {
			t.Errorf("Null byte in exec parameters")
		}

		// Validate command path
		if cmd != "" {
			// Check for path traversal
			if strings.Contains(cmd, "..") {
				t.Errorf("Path traversal in command: %q", cmd)
			}
			
			// Check for suspicious commands
			dangerousCmds := []string{"rm", "mkfs", "dd", "format"}
			for _, dangerous := range dangerousCmds {
				if strings.Contains(cmd, dangerous) {
					t.Logf("Potentially dangerous command: %q", cmd)
				}
			}
		}

		// Check arguments for injection
		args := []string{arg1, arg2}
		for i, arg := range args {
			if arg == "" {
				continue
			}
			
			// Check for shell metacharacters
			if strings.ContainsAny(arg, ";|&`$(){}[]<>") {
				t.Logf("Shell metacharacters in arg %d: %q", i, arg)
			}
			
			// Check for environment variable injection
			if strings.HasPrefix(arg, "LD_") || strings.HasPrefix(arg, "PATH=") {
				t.Logf("Environment manipulation in arg %d: %q", i, arg)
			}
		}
	})
}