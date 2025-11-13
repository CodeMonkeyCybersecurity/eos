// pkg/cloudinit/generator_test.go
package cloudinit

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerator_ValidateConfig(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")
	generator := NewGenerator(rc)

	tests := []struct {
		name    string
		config  *CloudInitConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &CloudInitConfig{
				Hostname: "test-host",
				Users: []UserConf{
					{Name: "testuser"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty hostname",
			config: &CloudInitConfig{
				Hostname: "",
				Users: []UserConf{
					{Name: "testuser"},
				},
			},
			wantErr: true,
		},
		{
			name: "no users",
			config: &CloudInitConfig{
				Hostname: "test-host",
				Users:    []UserConf{},
			},
			wantErr: true,
		},
		{
			name: "user without name",
			config: &CloudInitConfig{
				Hostname: "test-host",
				Users: []UserConf{
					{Name: ""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := generator.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerator_GenerateConfig(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")
	generator := NewGenerator(rc)

	info := &SystemInfo{
		Hostname:          "test-host",
		Username:          "testuser",
		SSHPublicKey:      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... test@test",
		InstalledPackages: []string{"curl", "wget", "vim"},
		UserHome:          "/home/testuser",
		UserGroups:        []string{"sudo", "adm"},
	}

	config, err := generator.GenerateConfig(info)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, "test-host", config.Hostname)
	assert.True(t, config.ManageEtcHosts)
	assert.True(t, config.PackageUpdate)
	assert.True(t, config.PackageUpgrade)

	require.Len(t, config.Users, 1)
	user := config.Users[0]
	assert.Equal(t, "testuser", user.Name)
	assert.Equal(t, "ALL=(ALL) NOPASSWD:ALL", user.Sudo)
	assert.Equal(t, "/bin/bash", user.Shell)
	assert.Equal(t, "/home/testuser", user.Home)
	assert.Contains(t, user.SSHAuthorizedKeys, info.SSHPublicKey)
	assert.Equal(t, info.UserGroups, user.Groups)

	assert.Equal(t, info.InstalledPackages, config.Packages)
	assert.Contains(t, config.RunCmd[0], "Cloud-init finished successfully!")
}

func TestGenerator_GenerateConfigNoSSHKey(t *testing.T) {
	ctx := context.Background()
	rc := eos_io.NewContext(ctx, "test")
	generator := NewGenerator(rc)

	info := &SystemInfo{
		Hostname:          "test-host",
		Username:          "testuser",
		SSHPublicKey:      "", // No SSH key
		InstalledPackages: []string{"curl", "wget"},
		UserHome:          "/home/testuser",
		UserGroups:        []string{"sudo"},
	}

	config, err := generator.GenerateConfig(info)
	require.NoError(t, err)
	require.NotNil(t, config)

	require.Len(t, config.Users, 1)
	user := config.Users[0]
	assert.Empty(t, user.SSHAuthorizedKeys)
}

// Fuzz test for config generation
func FuzzGenerateConfig(f *testing.F) {
	f.Add("test-host", "testuser", "/home/testuser")
	f.Add("", "user", "/home/user")
	f.Add("host-name-123", "admin", "/root")

	f.Fuzz(func(t *testing.T, hostname, username, userHome string) {
		ctx := context.Background()
		rc := eos_io.NewContext(ctx, "test")
		generator := NewGenerator(rc)

		info := &SystemInfo{
			Hostname:          hostname,
			Username:          username,
			SSHPublicKey:      "ssh-rsa test-key",
			InstalledPackages: []string{"curl"},
			UserHome:          userHome,
			UserGroups:        []string{"sudo"},
		}

		// Should not panic
		config, err := generator.GenerateConfig(info)
		if err == nil {
			assert.NotNil(t, config)
		}
	})
}
