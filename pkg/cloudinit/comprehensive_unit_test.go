package cloudinit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSystemInfo_AllFields(t *testing.T) {
	t.Run("complete system info", func(t *testing.T) {
		sysInfo := &SystemInfo{
			Hostname:          "test-host",
			Username:          "testuser",
			SSHPublicKey:      "ssh-rsa AAAAB3... user@host",
			InstalledPackages: []string{"vim", "git", "nginx"},
			UserGroups:        []string{"sudo", "docker", "admin"},
		}

		assert.Equal(t, "test-host", sysInfo.Hostname)
		assert.Equal(t, "testuser", sysInfo.Username)
		assert.Equal(t, "ssh-rsa AAAAB3... user@host", sysInfo.SSHPublicKey)
		assert.Len(t, sysInfo.InstalledPackages, 3)
		assert.Contains(t, sysInfo.InstalledPackages, "vim")
		assert.Len(t, sysInfo.UserGroups, 3)
		assert.Contains(t, sysInfo.UserGroups, "sudo")
	})

	t.Run("empty system info", func(t *testing.T) {
		sysInfo := &SystemInfo{}

		assert.Empty(t, sysInfo.Hostname)
		assert.Empty(t, sysInfo.Username)
		assert.Empty(t, sysInfo.SSHPublicKey)
		assert.Empty(t, sysInfo.InstalledPackages)
		assert.Empty(t, sysInfo.UserGroups)
	})
}

func TestGeneratorGenerateConfig_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		sysInfo  *SystemInfo
		validate func(t *testing.T, config *CloudInitConfig)
	}{
		{
			name: "full system info",
			sysInfo: &SystemInfo{
				Hostname:          "prod-server",
				Username:          "admin",
				SSHPublicKey:      "ssh-rsa AAAAB3... admin@server",
				InstalledPackages: []string{"nginx", "postgresql", "redis"},
				UserGroups:        []string{"sudo", "docker", "www-data"},
			},
			validate: func(t *testing.T, config *CloudInitConfig) {
				assert.Equal(t, "prod-server", config.Hostname)
				assert.True(t, config.ManageEtcHosts)

				require.Len(t, config.Users, 1)
				assert.Equal(t, "admin", config.Users[0].Name)
				assert.Contains(t, config.Users[0].Groups, "sudo")
				assert.Contains(t, config.Users[0].SSHAuthorizedKeys, "ssh-rsa AAAAB3... admin@server")
				assert.Equal(t, "ALL=(ALL) NOPASSWD:ALL", config.Users[0].Sudo)

				assert.Equal(t, []string{"nginx", "postgresql", "redis"}, config.Packages)

				// With network included by default
				assert.Equal(t, 2, config.Network.Version)
			},
		},
		{
			name: "minimal system info",
			sysInfo: &SystemInfo{
				Hostname: "min-host",
				Username: "user",
			},
			validate: func(t *testing.T, config *CloudInitConfig) {
				assert.Equal(t, "min-host", config.Hostname)
				require.Len(t, config.Users, 1)
				assert.Equal(t, "user", config.Users[0].Name)
				assert.Empty(t, config.Users[0].SSHAuthorizedKeys)
				assert.Empty(t, config.Packages)
			},
		},
		{
			name: "no SSH key",
			sysInfo: &SystemInfo{
				Hostname:          "no-ssh",
				Username:          "user",
				InstalledPackages: []string{"vim"},
				UserGroups:        []string{"admin"},
			},
			validate: func(t *testing.T, config *CloudInitConfig) {
				require.Len(t, config.Users, 1)
				assert.Empty(t, config.Users[0].SSHAuthorizedKeys)
				assert.Contains(t, config.Users[0].Groups, "admin")
			},
		},
		{
			name:    "empty system info",
			sysInfo: &SystemInfo{},
			validate: func(t *testing.T, config *CloudInitConfig) {
				assert.Empty(t, config.Hostname)
				// Generator adds a default user even with empty sysInfo
				assert.Len(t, config.Users, 1)
				assert.Empty(t, config.Packages)
			},
		},
		{
			name: "special characters in fields",
			sysInfo: &SystemInfo{
				Hostname:          "host-name.example.com",
				Username:          "user-name_123",
				SSHPublicKey:      "ssh-rsa AAAAB3...= user@host",
				InstalledPackages: []string{"package-1.0", "lib_test2"},
				UserGroups:        []string{"group-1", "group_2"},
			},
			validate: func(t *testing.T, config *CloudInitConfig) {
				assert.Equal(t, "host-name.example.com", config.Hostname)
				assert.Equal(t, "user-name_123", config.Users[0].Name)
				assert.Contains(t, config.Packages, "package-1.0")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			generator := NewGenerator(rc)
			config, err := generator.GenerateConfig(tt.sysInfo)
			require.NoError(t, err)
			tt.validate(t, config)
		})
	}
}

func TestGeneratorValidateConfig_Comprehensive(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	generator := NewGenerator(rc)

	tests := []struct {
		name    string
		config  *CloudInitConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid complete config",
			config: &CloudInitConfig{
				Hostname:       "valid-host",
				ManageEtcHosts: true,
				Users: []UserConf{
					{
						Name:              "user1",
						Groups:            []string{"sudo"},
						SSHAuthorizedKeys: []string{"ssh-rsa AAAA..."},
						Sudo:              "ALL=(ALL) NOPASSWD:ALL",
					},
				},
				Packages: []string{"vim", "git"},
				Network: NetworkConf{
					Version: 2,
					Ethernets: map[string]EthConf{
						"eth0": {DHCP4: true},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty hostname",
			config: &CloudInitConfig{
				Hostname: "",
			},
			wantErr: true,
			errMsg:  "hostname is required",
		},
		{
			name: "hostname too long",
			config: &CloudInitConfig{
				Hostname: strings.Repeat("a", 256),
			},
			wantErr: true,
			errMsg:  "hostname too long",
		},
		{
			name: "invalid hostname characters",
			config: &CloudInitConfig{
				Hostname: "host@name",
			},
			wantErr: true,
			errMsg:  "hostname contains invalid characters",
		},
		{
			name: "empty username",
			config: &CloudInitConfig{
				Hostname: "host",
				Users: []UserConf{
					{Name: ""},
				},
			},
			wantErr: true,
			errMsg:  "username is required",
		},
		{
			name: "invalid network version",
			config: &CloudInitConfig{
				Hostname: "host",
				Network: NetworkConf{
					Version: 3,
				},
			},
			wantErr: true,
			errMsg:  "unsupported network version",
		},
		{
			name: "empty write file path",
			config: &CloudInitConfig{
				Hostname: "host",
				WriteFiles: []WriteFile{
					{Path: "", Content: "content"},
				},
			},
			wantErr: true,
			errMsg:  "file path is required",
		},
		{
			name: "valid minimal config",
			config: &CloudInitConfig{
				Hostname: "minimal",
				Users: []UserConf{
					{Name: "user"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := generator.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWriteFile_Structure(t *testing.T) {
	tests := []struct {
		name     string
		file     WriteFile
		validate func(t *testing.T, wf WriteFile)
	}{
		{
			name: "complete write file",
			file: WriteFile{
				Path:        "/etc/myapp/config.yaml",
				Content:     "key: value\nother: data",
				Permissions: "0644",
				Owner:       "root:root",
			},
			validate: func(t *testing.T, wf WriteFile) {
				assert.Equal(t, "/etc/myapp/config.yaml", wf.Path)
				assert.Equal(t, "key: value\nother: data", wf.Content)
				assert.Equal(t, "0644", wf.Permissions)
				assert.Equal(t, "root:root", wf.Owner)
			},
		},
		{
			name: "minimal write file",
			file: WriteFile{
				Path:    "/tmp/test.txt",
				Content: "test",
			},
			validate: func(t *testing.T, wf WriteFile) {
				assert.Equal(t, "/tmp/test.txt", wf.Path)
				assert.Equal(t, "test", wf.Content)
				assert.Empty(t, wf.Permissions)
				assert.Empty(t, wf.Owner)
			},
		},
		{
			name: "file with base64 content",
			file: WriteFile{
				Path:        "/etc/ssl/cert.pem",
				Content:     "LS0tLS1CRUdJTi...",
				Permissions: "0600",
				Owner:       "root:root",
			},
			validate: func(t *testing.T, wf WriteFile) {
				assert.Equal(t, "/etc/ssl/cert.pem", wf.Path)
				assert.Equal(t, "LS0tLS1CRUdJTi...", wf.Content)
				assert.Equal(t, "0600", wf.Permissions)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.file)
		})
	}
}

func TestUserConf_Structure(t *testing.T) {
	tests := []struct {
		name     string
		user     UserConf
		validate func(t *testing.T, u UserConf)
	}{
		{
			name: "complete user",
			user: UserConf{
				Name:              "admin",
				Groups:            []string{"sudo", "docker", "admin"},
				SSHAuthorizedKeys: []string{"ssh-rsa AAAA...", "ssh-ed25519 AAAA..."},
				Sudo:              "ALL=(ALL) NOPASSWD:ALL",
			},
			validate: func(t *testing.T, u UserConf) {
				assert.Equal(t, "admin", u.Name)
				assert.Len(t, u.Groups, 3)
				assert.Contains(t, u.Groups, "sudo")
				assert.Len(t, u.SSHAuthorizedKeys, 2)
				assert.Equal(t, "ALL=(ALL) NOPASSWD:ALL", u.Sudo)
			},
		},
		{
			name: "minimal user",
			user: UserConf{
				Name: "user",
			},
			validate: func(t *testing.T, u UserConf) {
				assert.Equal(t, "user", u.Name)
				assert.Empty(t, u.Groups)
				assert.Empty(t, u.SSHAuthorizedKeys)
				assert.Empty(t, u.Sudo)
			},
		},
		{
			name: "user with shell and home",
			user: UserConf{
				Name:   "operator",
				Groups: []string{"wheel"},
				Shell:  "/bin/zsh",
				Home:   "/home/operator",
			},
			validate: func(t *testing.T, u UserConf) {
				assert.Equal(t, "operator", u.Name)
				assert.Equal(t, "/bin/zsh", u.Shell)
				assert.Equal(t, "/home/operator", u.Home)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.user)
		})
	}
}

func TestNetworkConf_Structure(t *testing.T) {
	t.Run("dhcp network config", func(t *testing.T) {
		netConf := NetworkConf{
			Version: 2,
			Ethernets: map[string]EthConf{
				"eth0": {
					DHCP4: true,
					DHCP6: false,
				},
			},
		}

		assert.Equal(t, 2, netConf.Version)
		assert.Contains(t, netConf.Ethernets, "eth0")
		assert.True(t, netConf.Ethernets["eth0"].DHCP4)
		assert.False(t, netConf.Ethernets["eth0"].DHCP6)
	})

	t.Run("static network config", func(t *testing.T) {
		netConf := NetworkConf{
			Version: 2,
			Ethernets: map[string]EthConf{
				"eth0": {
					Addresses: []string{"192.168.1.100/24", "10.0.0.50/8"},
					Gateway4:  "192.168.1.1",
					Nameservers: &NSConf{
						Addresses: []string{"8.8.8.8", "8.8.4.4"},
					},
				},
			},
		}

		eth0 := netConf.Ethernets["eth0"]
		assert.Len(t, eth0.Addresses, 2)
		assert.Equal(t, "192.168.1.1", eth0.Gateway4)
		assert.NotNil(t, eth0.Nameservers)
		assert.Len(t, eth0.Nameservers.Addresses, 2)
		assert.Contains(t, eth0.Nameservers.Addresses, "8.8.8.8")
	})

	t.Run("multiple interfaces", func(t *testing.T) {
		netConf := NetworkConf{
			Version: 2,
			Ethernets: map[string]EthConf{
				"eth0": {DHCP4: true},
				"eth1": {
					Addresses: []string{"10.0.0.10/24"},
					Gateway4:  "10.0.0.1",
				},
			},
		}

		assert.Len(t, netConf.Ethernets, 2)
		assert.Contains(t, netConf.Ethernets, "eth0")
		assert.Contains(t, netConf.Ethernets, "eth1")
	})
}

func TestYAMLGeneration_Safety(t *testing.T) {
	t.Run("special characters in strings", func(t *testing.T) {
		config := &CloudInitConfig{
			Hostname: "host-with-special: characters",
			Users: []UserConf{
				{
					Name:              "user:with:colons",
					SSHAuthorizedKeys: []string{"ssh-rsa AAA...= user@host"},
				},
			},
			WriteFiles: []WriteFile{
				{
					Path:    "/tmp/file-with-special.txt",
					Content: "content with\nnewlines and\ttabs",
				},
			},
		}

		yamlData, err := yaml.Marshal(config)
		require.NoError(t, err)

		// Verify YAML is valid
		var decoded CloudInitConfig
		err = yaml.Unmarshal(yamlData, &decoded)
		require.NoError(t, err)

		// Verify data integrity
		assert.Equal(t, config.Hostname, decoded.Hostname)
		assert.Equal(t, config.Users[0].Name, decoded.Users[0].Name)
		assert.Equal(t, config.WriteFiles[0].Content, decoded.WriteFiles[0].Content)
	})

	t.Run("empty and nil values", func(t *testing.T) {
		config := &CloudInitConfig{
			Hostname: "host",
			Users: []UserConf{
				{
					Name:              "user",
					Groups:            nil,
					SSHAuthorizedKeys: nil,
					Sudo:              "",
				},
			},
			Packages:   nil,
			WriteFiles: []WriteFile{},
		}

		yamlData, err := yaml.Marshal(config)
		require.NoError(t, err)

		yamlStr := string(yamlData)
		assert.Contains(t, yamlStr, "hostname: host")
		assert.Contains(t, yamlStr, "name: user")

		// Empty slices should be omitted or rendered as []
		var decoded CloudInitConfig
		err = yaml.Unmarshal(yamlData, &decoded)
		require.NoError(t, err)
	})

	t.Run("unicode in content", func(t *testing.T) {
		config := &CloudInitConfig{
			Hostname: "unicode-test",
			WriteFiles: []WriteFile{
				{
					Path:    "/tmp/unicode.txt",
					Content: "Hello 世界  Мир",
				},
			},
		}

		yamlData, err := yaml.Marshal(config)
		require.NoError(t, err)

		var decoded CloudInitConfig
		err = yaml.Unmarshal(yamlData, &decoded)
		require.NoError(t, err)

		assert.Equal(t, config.WriteFiles[0].Content, decoded.WriteFiles[0].Content)
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("extremely long strings", func(t *testing.T) {
		longString := strings.Repeat("a", 10000)
		config := &CloudInitConfig{
			Hostname: "host",
			WriteFiles: []WriteFile{
				{
					Path:    "/tmp/long.txt",
					Content: longString,
				},
			},
		}

		yamlData, err := yaml.Marshal(config)
		assert.NoError(t, err)
		assert.Contains(t, string(yamlData), longString[:100]) // Check at least part of it
	})

	t.Run("deeply nested structures", func(t *testing.T) {
		config := &CloudInitConfig{
			Hostname: "nested",
			Network: NetworkConf{
				Version: 2,
				Ethernets: map[string]EthConf{
					"eth0": {
						Addresses: []string{"10.0.0.1/24"},
						Nameservers: &NSConf{
							Addresses: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"},
						},
					},
				},
			},
		}

		yamlData, err := yaml.Marshal(config)
		assert.NoError(t, err)

		var decoded CloudInitConfig
		err = yaml.Unmarshal(yamlData, &decoded)
		assert.NoError(t, err)
		assert.Equal(t, 3, len(decoded.Network.Ethernets["eth0"].Nameservers.Addresses))
	})

	t.Run("config with all fields populated", func(t *testing.T) {
		config := &CloudInitConfig{
			Hostname:       "complete-host",
			ManageEtcHosts: true,
			Users: []UserConf{
				{
					Name:              "admin",
					Groups:            []string{"sudo", "docker"},
					SSHAuthorizedKeys: []string{"ssh-rsa AAA..."},
					Sudo:              "ALL=(ALL) NOPASSWD:ALL",
				},
				{
					Name:   "operator",
					Groups: []string{"users"},
				},
			},
			PackageUpdate:  true,
			PackageUpgrade: true,
			Packages:       []string{"vim", "git", "htop", "curl", "wget"},
			WriteFiles: []WriteFile{
				{
					Path:        "/etc/app.conf",
					Content:     "config=value",
					Permissions: "0644",
					Owner:       "root:root",
				},
				{
					Path:        "/tmp/script.sh",
					Content:     "#!/bin/bash\necho hello",
					Permissions: "0755",
				},
			},
			RunCmd: []string{
				"apt-get update",
				"systemctl restart nginx",
			},
			Network: NetworkConf{
				Version: 2,
				Ethernets: map[string]EthConf{
					"eth0": {DHCP4: true},
					"eth1": {
						Addresses: []string{"10.0.0.10/24"},
						Gateway4:  "10.0.0.1",
					},
				},
			},
			FinalMessage: "Cloud-init completed",
		}

		// Should marshal and unmarshal without loss
		yamlData, err := yaml.Marshal(config)
		require.NoError(t, err)

		var decoded CloudInitConfig
		err = yaml.Unmarshal(yamlData, &decoded)
		require.NoError(t, err)

		// Spot check some fields
		assert.Equal(t, config.Hostname, decoded.Hostname)
		assert.Len(t, decoded.Users, 2)
		assert.Len(t, decoded.Packages, 5)
		assert.Len(t, decoded.WriteFiles, 2)
		assert.Len(t, decoded.RunCmd, 2)
		assert.Len(t, decoded.Network.Ethernets, 2)
		assert.Equal(t, config.FinalMessage, decoded.FinalMessage)
	})
}

func TestGeneratorGenerateTemplate(t *testing.T) {
	t.Run("generates correct template structure", func(t *testing.T) {
		// Create temp file for template output
		tmpDir := t.TempDir()
		templatePath := filepath.Join(tmpDir, "template.yaml")

		rc := testutil.TestRuntimeContext(t)
		generator := NewGenerator(rc)

		err := generator.GenerateTemplate(templatePath)
		require.NoError(t, err)

		// Read and verify template
		content, err := os.ReadFile(templatePath)
		require.NoError(t, err)

		// Parse YAML to verify structure
		var template CloudInitConfig
		err = yaml.Unmarshal(content, &template)
		require.NoError(t, err)

		// Check basic structure
		assert.Equal(t, "your-hostname", template.Hostname)
		assert.True(t, template.ManageEtcHosts)

		// Check users
		require.Len(t, template.Users, 1)
		assert.Equal(t, "yourusername", template.Users[0].Name)
		assert.Contains(t, template.Users[0].Groups, "sudo")
		assert.Contains(t, template.Users[0].SSHAuthorizedKeys, "ssh-rsa YOUR_PUBLIC_KEY")

		// Check packages
		assert.Contains(t, template.Packages, "git")
		assert.Contains(t, template.Packages, "vim")

		// Check write files
		require.Len(t, template.WriteFiles, 1)
		assert.Equal(t, "/etc/example.conf", template.WriteFiles[0].Path)

		// Check network
		assert.Equal(t, 2, template.Network.Version)
		assert.Contains(t, template.Network.Ethernets, "eth0")
		assert.True(t, template.Network.Ethernets["eth0"].DHCP4)
	})
}

// Commented out until we can access private helper functions
// func TestHelperFunctions(t *testing.T) {
// 	t.Run("parsePackageList", func(t *testing.T) {
// 		// Test would go here if parsePackageList was accessible
// 	})
// 	t.Run("parseGroupsList", func(t *testing.T) {
// 		// Test would go here if parseGroupsList was accessible
// 	})
// }

func TestGeneratorWriteConfig(t *testing.T) {
	t.Run("writes config to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "cloud-init.yaml")

		rc := testutil.TestRuntimeContext(t)
		generator := NewGenerator(rc)

		config := &CloudInitConfig{
			Hostname: "test-host",
			Users: []UserConf{
				{
					Name:   "testuser",
					Groups: []string{"sudo"},
				},
			},
			Packages: []string{"vim", "git"},
		}

		err := generator.WriteConfig(config, outputPath)
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(outputPath)
		require.NoError(t, err)

		// Verify content
		content, err := os.ReadFile(outputPath)
		require.NoError(t, err)

		// Parse back to verify
		var decoded CloudInitConfig
		err = yaml.Unmarshal(content, &decoded)
		require.NoError(t, err)

		assert.Equal(t, config.Hostname, decoded.Hostname)
		assert.Len(t, decoded.Users, 1)
		assert.Equal(t, config.Users[0].Name, decoded.Users[0].Name)
	})

	t.Run("creates parent directory if needed", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "subdir", "cloud-init.yaml")

		rc := testutil.TestRuntimeContext(t)
		generator := NewGenerator(rc)

		config := &CloudInitConfig{
			Hostname: "test-host",
		}

		err := generator.WriteConfig(config, outputPath)
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(outputPath)
		require.NoError(t, err)
	})
}

func TestValidation_SecurityChecks(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	generator := NewGenerator(rc)

	t.Run("hostname validation", func(t *testing.T) {
		tests := []struct {
			hostname string
			valid    bool
		}{
			{"valid-hostname", true},
			{"host.example.com", true},
			{"host123", true},
			{"123host", true},
			{"", false},
			{strings.Repeat("a", 255), false},
			{"host@name", false},
			{"host name", false},
			{"host;name", false},
			{"host|name", false},
			{"host&name", false},
			{"host$name", false},
		}

		for _, tt := range tests {
			config := &CloudInitConfig{Hostname: tt.hostname}
			err := generator.ValidateConfig(config)
			if tt.valid {
				assert.NoError(t, err, "Hostname %q should be valid", tt.hostname)
			} else {
				assert.Error(t, err, "Hostname %q should be invalid", tt.hostname)
			}
		}
	})

	t.Run("username validation", func(t *testing.T) {
		tests := []struct {
			username string
			valid    bool
		}{
			{"validuser", true},
			{"user123", true},
			{"user-name", true},
			{"user_name", true},
			{"", false},
			{"user name", false},
			{"user;name", false},
			{"user|name", false},
			{"user&name", false},
			{"user$name", false},
			{"root", true}, // root is technically valid
		}

		for _, tt := range tests {
			config := &CloudInitConfig{
				Hostname: "host",
				Users:    []UserConf{{Name: tt.username}},
			}
			err := generator.ValidateConfig(config)
			if tt.valid {
				assert.NoError(t, err, "Username %q should be valid", tt.username)
			} else {
				assert.Error(t, err, "Username %q should be invalid", tt.username)
			}
		}
	})

	t.Run("file path validation", func(t *testing.T) {
		tests := []struct {
			path  string
			valid bool
		}{
			{"/etc/app.conf", true},
			{"/tmp/test.txt", true},
			{"/home/user/.config", true},
			{"", false},
			{"relative/path", false},
			{"../../../etc/passwd", false},
			{"/etc/../etc/passwd", true}, // Currently allowed, might want to restrict
			{"/tmp/file;rm -rf /", true}, // Currently allowed, might want to restrict
		}

		for _, tt := range tests {
			config := &CloudInitConfig{
				Hostname:   "host",
				WriteFiles: []WriteFile{{Path: tt.path, Content: "test"}},
			}
			err := generator.ValidateConfig(config)
			if tt.valid {
				assert.NoError(t, err, "Path %q should be valid", tt.path)
			} else {
				assert.Error(t, err, "Path %q should be invalid", tt.path)
			}
		}
	})
}
