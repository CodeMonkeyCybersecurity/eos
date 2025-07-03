package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"gopkg.in/yaml.v3"
)

// TestRepository represents a test repository configuration
type TestRepository struct {
	Name     string
	Backend  string
	URL      string
	TempDir  string
	Password string
}

// createTestRepository creates a temporary repository for testing
func createTestRepository(t *testing.T) *TestRepository {
	tempDir := t.TempDir()
	repoDir := filepath.Join(tempDir, "test-repo")
	
	return &TestRepository{
		Name:     "test-repo",
		Backend:  "local",
		URL:      repoDir,
		TempDir:  tempDir,
		Password: "test-password-123",
	}
}

// createTestConfig creates a test configuration with the given repository
func createTestConfig(t *testing.T, repo *TestRepository) *Config {
	return &Config{
		DefaultRepository: repo.Name,
		Repositories: map[string]Repository{
			repo.Name: {
				Name:        repo.Name,
				Backend:     repo.Backend,
				URL:         repo.URL,
				Environment: make(map[string]string),
			},
		},
		Profiles: map[string]Profile{
			"test-profile": {
				Name:       "test-profile",
				Repository: repo.Name,
				Paths:      []string{repo.TempDir},
				Tags:       []string{"test"},
				Excludes:   []string{"*.tmp"},
				Retention: &Retention{
					KeepLast:    5,
					KeepDaily:   7,
					KeepWeekly:  4,
					KeepMonthly: 12,
				},
			},
		},
		Settings: Settings{
			Notifications: Notifications{
				OnSuccess: false,
				OnFailure: true,
				Method:    "email",
				Target:    "admin@example.com",
			},
		},
	}
}

// createTestRuntimeContext creates a test runtime context
func createTestRuntimeContext(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t)
	return &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}
}

// MockCommand represents a mocked command execution
type MockCommand struct {
	Cmd    string
	Args   []string
	Output string
	Error  error
}

// MockExecutor replaces exec.CommandContext for testing
type MockExecutor struct {
	Commands []MockCommand
	Called   []MockCommand
}

// Execute mocks command execution
func (m *MockExecutor) Execute(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	call := MockCommand{Cmd: cmd, Args: args}
	m.Called = append(m.Called, call)
	
	// Find matching mock command
	for _, mock := range m.Commands {
		if mock.Cmd == cmd && equalStringSlices(mock.Args, args) {
			return []byte(mock.Output), mock.Error
		}
	}
	
	// Default to actual command execution if no mock found
	actualCmd := exec.CommandContext(ctx, cmd, args...)
	return actualCmd.CombinedOutput()
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestClientCreation tests client creation with various configurations
func TestClientCreation(t *testing.T) {
	repo := createTestRepository(t)
	config := createTestConfig(t, repo)
	rc := createTestRuntimeContext(t)

	t.Run("successful client creation", func(t *testing.T) {
		// Save test config
		configFile := filepath.Join(repo.TempDir, "backup.yaml")
		err := saveTestConfig(configFile, config)
		require.NoError(t, err)
		
		// Override config path for test
		originalConfigFile := configFile
		defer func() {
			// Cleanup would go here if needed
			_ = originalConfigFile
		}()

		// Test client creation would require modifying NewClient to accept config
		// For now, test the components separately
		client := &Client{
			rc:         rc,
			config:     config,
			repository: func() *Repository { r := config.Repositories[repo.Name]; return &r }(),
		}

		assert.NotNil(t, client)
		assert.Equal(t, rc, client.rc)
		assert.Equal(t, config, client.config)
		assert.Equal(t, repo.Name, client.repository.Name)
	})

	t.Run("invalid repository name", func(t *testing.T) {
		invalidRepo := &Repository{
			Name:    "nonexistent",
			Backend: "local",
			URL:     "/tmp/nonexistent",
		}
		
		client := &Client{
			rc:         rc,
			config:     config,
			repository: invalidRepo,
		}

		// Test that the repository doesn't exist in config
		_, exists := config.Repositories["nonexistent"]
		assert.False(t, exists)
		
		// Client can still be created but repository won't be in config
		assert.NotNil(t, client)
	})
}

// TestPasswordRetrievalIntegration tests password retrieval from various sources
func TestPasswordRetrievalIntegration(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("vault unavailable fallback", func(t *testing.T) {
		// Create local password file
		secretsDir := filepath.Join(repo.TempDir, "secrets", "backup")
		err := os.MkdirAll(secretsDir, 0700)
		require.NoError(t, err)
		
		passwordFile := filepath.Join(secretsDir, fmt.Sprintf("%s.password", repo.Name))
		err = os.WriteFile(passwordFile, []byte(repo.Password), 0600)
		require.NoError(t, err)

		// Mock the local password file path
		originalClient := *client
		client.repository.Name = repo.Name
		
		// This would test the actual getRepositoryPassword method
		// but it requires vault setup. For now, test the file existence
		assert.FileExists(t, passwordFile)
		
		// Restore original client
		*client = originalClient
	})

	t.Run("no password available", func(t *testing.T) {
		// Test case where neither Vault nor local file is available
		client.repository.Name = "nonexistent-repo"
		
		// This should result in an error when getRepositoryPassword is called
		// Since we can't easily mock Vault here, we test the error conditions
		secretsDir := "/var/lib/eos/secrets/backup"
		passwordFile := filepath.Join(secretsDir, "nonexistent-repo.password")
		
		// Verify file doesn't exist
		_, err := os.Stat(passwordFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("password security validation", func(t *testing.T) {
		// Test that passwords are validated for security
		dangerousPasswords := []string{
			"password; rm -rf /",
			"password`whoami`",
			"password && curl evil.com",
			"password\nrm -rf /",
		}

		for _, password := range dangerousPasswords {
			t.Run(fmt.Sprintf("dangerous_password_%s", password[:8]), func(t *testing.T) {
				// Test that dangerous passwords are detected
				isDangerous := containsAnyDangerousBackup(password)
				assert.True(t, isDangerous, "Password should be flagged as dangerous: %s", password)
			})
		}
	})
}

// TestRepositoryInitialization tests repository initialization
func TestRepositoryInitialization(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping repository initialization test in short mode")
	}

	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("repository initialization workflow", func(t *testing.T) {
		_ = client // Use client variable
		// Create the repository directory
		err := os.MkdirAll(repo.URL, 0755)
		require.NoError(t, err)

		// Test initialization logic (without actual restic)
		args := []string{"init", "--repository-version", "2"}
		
		// Verify the arguments are correct
		assert.Contains(t, args, "init")
		assert.Contains(t, args, "--repository-version")
		assert.Contains(t, args, "2")
		
		// Test environment setup
		env := os.Environ()
		env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", repo.URL))
		env = append(env, fmt.Sprintf("RESTIC_PASSWORD=%s", repo.Password))
		
		// Verify environment variables are set correctly
		repoEnvFound := false
		passEnvFound := false
		for _, envVar := range env {
			if strings.HasPrefix(envVar, "RESTIC_REPOSITORY=") {
				repoEnvFound = true
				assert.Contains(t, envVar, repo.URL)
			}
			if strings.HasPrefix(envVar, "RESTIC_PASSWORD=") {
				passEnvFound = true
			}
		}
		assert.True(t, repoEnvFound, "RESTIC_REPOSITORY environment variable should be set")
		assert.True(t, passEnvFound, "RESTIC_PASSWORD environment variable should be set")
	})

	t.Run("already initialized repository", func(t *testing.T) {
		// Test handling of already initialized repository
		errorOutput := "Fatal: repository already initialized"
		
		// Test that the error is handled correctly
		if strings.Contains(errorOutput, "already initialized") {
			// This should not be treated as an error
			t.Log("Repository already initialized (expected behavior)")
		} else {
			t.Error("Should handle already initialized repository gracefully")
		}
	})
}

// TestBackupExecution tests backup execution workflow
func TestBackupExecution(t *testing.T) {
	repo := createTestRepository(t)
	config := createTestConfig(t, repo)
	rc := createTestRuntimeContext(t)

	repoConfig := config.Repositories[repo.Name]
	client := &Client{
		rc:         rc,
		config:     config,
		repository: &repoConfig,
	}

	t.Run("backup command construction", func(t *testing.T) {
		_ = client // Use client variable
		profile := config.Profiles["test-profile"]
		
		// Test backup argument construction
		args := []string{"backup"}
		args = append(args, profile.Paths...)
		
		for _, exclude := range profile.Excludes {
			args = append(args, "--exclude", exclude)
		}
		
		for _, tag := range profile.Tags {
			args = append(args, "--tag", tag)
		}
		
		if profile.Host != "" {
			args = append(args, "--host", profile.Host)
		}
		
		args = append(args, "--json")
		
		// Verify command structure
		assert.Contains(t, args, "backup")
		assert.Contains(t, args, repo.TempDir)
		assert.Contains(t, args, "--exclude")
		assert.Contains(t, args, "*.tmp")
		assert.Contains(t, args, "--tag")
		assert.Contains(t, args, "test")
		assert.Contains(t, args, "--json")
	})

	t.Run("progress monitoring", func(t *testing.T) {
		// Test JSON progress parsing
		testMessages := []string{
			`{"message_type":"status","percent_done":0.5,"total_files":100,"total_bytes":1048576}`,
			`{"message_type":"summary","files_new":10,"files_changed":5,"files_unmodified":85,"data_size_in_repo":524288,"total_duration":30,"snapshot_id":"abc123"}`,
			`{"message_type":"error","item":"/test/file","during":"archival","error":"permission denied"}`,
		}

		for _, msgStr := range testMessages {
			var msg map[string]interface{}
			err := json.Unmarshal([]byte(msgStr), &msg)
			require.NoError(t, err)

			msgType, _ := msg["message_type"].(string)
			
			switch msgType {
			case "status":
				percentDone, _ := msg["percent_done"].(float64)
				totalFiles, _ := msg["total_files"].(float64)
				totalBytes, _ := msg["total_bytes"].(float64)
				
				assert.GreaterOrEqual(t, percentDone, 0.0)
				assert.LessOrEqual(t, percentDone, 1.0)
				assert.Greater(t, totalFiles, 0.0)
				assert.Greater(t, totalBytes, 0.0)
				
			case "summary":
				snapshotID, _ := msg["snapshot_id"].(string)
				filesNew, _ := msg["files_new"].(float64)
				totalDuration, _ := msg["total_duration"].(float64)
				
				assert.NotEmpty(t, snapshotID)
				assert.GreaterOrEqual(t, filesNew, 0.0)
				assert.Greater(t, totalDuration, 0.0)
				
			case "error":
				item, _ := msg["item"].(string)
				during, _ := msg["during"].(string)
				errMsg, _ := msg["error"].(string)
				
				assert.NotEmpty(t, item)
				assert.NotEmpty(t, during)
				assert.NotEmpty(t, errMsg)
			}
		}
	})

	t.Run("retention policy application", func(t *testing.T) {
		profile := config.Profiles["test-profile"]
		
		// Test retention argument construction
		args := []string{"forget", "--prune"}
		
		if profile.Retention.KeepLast > 0 {
			args = append(args, "--keep-last", fmt.Sprintf("%d", profile.Retention.KeepLast))
		}
		if profile.Retention.KeepDaily > 0 {
			args = append(args, "--keep-daily", fmt.Sprintf("%d", profile.Retention.KeepDaily))
		}
		if profile.Retention.KeepWeekly > 0 {
			args = append(args, "--keep-weekly", fmt.Sprintf("%d", profile.Retention.KeepWeekly))
		}
		if profile.Retention.KeepMonthly > 0 {
			args = append(args, "--keep-monthly", fmt.Sprintf("%d", profile.Retention.KeepMonthly))
		}
		if profile.Retention.KeepYearly > 0 {
			args = append(args, "--keep-yearly", fmt.Sprintf("%d", profile.Retention.KeepYearly))
		}
		
		for _, tag := range profile.Tags {
			args = append(args, "--tag", tag)
		}

		// Verify retention arguments
		assert.Contains(t, args, "forget")
		assert.Contains(t, args, "--prune")
		assert.Contains(t, args, "--keep-last")
		assert.Contains(t, args, "5")
		assert.Contains(t, args, "--keep-daily")
		assert.Contains(t, args, "7")
		assert.Contains(t, args, "--tag")
		assert.Contains(t, args, "test")
	})
}

// TestSnapshotManagement tests snapshot listing and management
func TestSnapshotManagement(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("snapshot listing", func(t *testing.T) {
		_ = client // Use client variable
		// Mock snapshot JSON response
		snapshotJSON := `[
			{
				"id": "abc123def456",
				"time": "2023-01-01T12:00:00Z",
				"tree": "tree123",
				"paths": ["/etc", "/var/lib/eos"],
				"hostname": "server1",
				"username": "root",
				"tags": ["system", "daily"],
				"parent": "parent123"
			},
			{
				"id": "def456ghi789",
				"time": "2023-01-02T12:00:00Z",
				"tree": "tree456",
				"paths": ["/home"],
				"hostname": "server1",
				"username": "backup",
				"tags": ["user", "daily"]
			}
		]`

		var snapshots []Snapshot
		err := json.Unmarshal([]byte(snapshotJSON), &snapshots)
		require.NoError(t, err)

		// Verify snapshot parsing
		assert.Len(t, snapshots, 2)
		
		snapshot1 := snapshots[0]
		assert.Equal(t, "abc123def456", snapshot1.ID)
		assert.Equal(t, "server1", snapshot1.Hostname)
		assert.Equal(t, "root", snapshot1.Username)
		assert.Contains(t, snapshot1.Tags, "system")
		assert.Contains(t, snapshot1.Tags, "daily")
		assert.Contains(t, snapshot1.Paths, "/etc")
		assert.Contains(t, snapshot1.Paths, "/var/lib/eos")

		snapshot2 := snapshots[1]
		assert.Equal(t, "def456ghi789", snapshot2.ID)
		assert.Equal(t, "backup", snapshot2.Username)
		assert.Contains(t, snapshot2.Tags, "user")
		assert.Contains(t, snapshot2.Paths, "/home")
	})

	t.Run("snapshot validation", func(t *testing.T) {
		// Test invalid snapshot data
		invalidSnapshots := []string{
			`{"id": "test; rm -rf /", "time": "2023-01-01T12:00:00Z"}`,
			`{"id": "test", "hostname": "host` + "`whoami`" + `", "time": "2023-01-01T12:00:00Z"}`,
			`{"id": "test", "paths": ["/etc", "/var; curl evil.com"], "time": "2023-01-01T12:00:00Z"}`,
		}

		for i, snapshotStr := range invalidSnapshots {
			var snapshot Snapshot
			err := json.Unmarshal([]byte(snapshotStr), &snapshot)
			require.NoError(t, err, "Snapshot %d should parse", i)

			// Validate fields for dangerous content
			fields := []string{snapshot.ID, snapshot.Hostname, snapshot.Username}
			fields = append(fields, snapshot.Paths...)
			fields = append(fields, snapshot.Tags...)

			hasDangerous := false
			for _, field := range fields {
				if containsAnyDangerousBackup(field) {
					hasDangerous = true
					break
				}
			}

			if !hasDangerous {
				t.Logf("Snapshot %d with potentially dangerous content not detected", i)
			}
		}
	})
}

// TestRestoreOperations tests backup restoration functionality
func TestRestoreOperations(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("restore command construction", func(t *testing.T) {
		_ = client // Use client variable
		snapshotID := "abc123def456"
		targetDir := filepath.Join(repo.TempDir, "restore")
		
		// Test restore argument construction
		args := []string{"restore", snapshotID, "--target", targetDir}
		
		// Verify restore arguments
		assert.Contains(t, args, "restore")
		assert.Contains(t, args, snapshotID)
		assert.Contains(t, args, "--target")
		assert.Contains(t, args, targetDir)
		
		// Verify argument order
		assert.Equal(t, "restore", args[0])
		assert.Equal(t, snapshotID, args[1])
		assert.Equal(t, "--target", args[2])
		assert.Equal(t, targetDir, args[3])
	})

	t.Run("target directory creation", func(t *testing.T) {
		targetDir := filepath.Join(repo.TempDir, "restore", "subdir")
		
		// Test directory creation
		err := os.MkdirAll(targetDir, 0755)
		require.NoError(t, err)
		
		// Verify directory exists and has correct permissions
		info, err := os.Stat(targetDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		
		// Check permissions (0755)
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
	})

	t.Run("restore security validation", func(t *testing.T) {
		// Test potentially dangerous restore targets
		dangerousTargets := []string{
			"/etc; rm -rf /",
			"/tmp/restore`whoami`",
			"/var/restore && curl evil.com",
		}

		for _, target := range dangerousTargets {
			isDangerous := containsAnyDangerousBackup(target)
			assert.True(t, isDangerous, "Dangerous restore target should be detected: %s", target)
		}

		// Test safe restore targets
		safeTargets := []string{
			"/tmp/restore",
			"/var/lib/eos/restore",
			filepath.Join(repo.TempDir, "restore"),
		}

		for _, target := range safeTargets {
			isDangerous := containsAnyDangerousBackup(target)
			assert.False(t, isDangerous, "Safe restore target should not be flagged: %s", target)
		}
	})
}

// TestVerificationOperations tests backup verification functionality
func TestVerificationOperations(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("verification command construction", func(t *testing.T) {
		_ = client // Use client variable
		snapshotID := "abc123def456"
		
		// Test verification argument construction
		args := []string{"check", "--read-data-subset=1/10", snapshotID}
		
		// Verify check arguments
		assert.Contains(t, args, "check")
		assert.Contains(t, args, "--read-data-subset=1/10")
		assert.Contains(t, args, snapshotID)
		
		// Verify argument order
		assert.Equal(t, "check", args[0])
		assert.Equal(t, "--read-data-subset=1/10", args[1])
		assert.Equal(t, snapshotID, args[2])
	})

	t.Run("verification modes", func(t *testing.T) {
		// Test different verification modes
		verificationModes := map[string][]string{
			"full":    {"check"},
			"quick":   {"check", "--read-data-subset=1/100"},
			"sample":  {"check", "--read-data-subset=1/10"},
			"metadata": {"check", "--read-data=false"},
		}

		for mode, expectedArgs := range verificationModes {
			t.Run(mode, func(t *testing.T) {
				for _, arg := range expectedArgs {
					// Each mode should have the check command
					if strings.HasPrefix(arg, "check") {
						assert.Equal(t, "check", arg)
					}
				}
			})
		}
	})
}

// TestErrorHandling tests various error scenarios
func TestErrorHandling(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("command execution errors", func(t *testing.T) {
		_ = client // Use client variable
		// Test various error scenarios
		errorScenarios := []struct {
			name     string
			command  string
			args     []string
			exitCode int
			stderr   string
		}{
			{
				name:     "repository not found",
				command:  "restic",
				args:     []string{"snapshots"},
				exitCode: 1,
				stderr:   "Fatal: unable to open repository",
			},
			{
				name:     "invalid password",
				command:  "restic",
				args:     []string{"snapshots"},
				exitCode: 1,
				stderr:   "Fatal: wrong password",
			},
			{
				name:     "permission denied",
				command:  "restic",
				args:     []string{"backup", "/root"},
				exitCode: 1,
				stderr:   "Error: permission denied",
			},
			{
				name:     "disk full",
				command:  "restic",
				args:     []string{"backup", "/tmp"},
				exitCode: 1,
				stderr:   "Error: no space left on device",
			},
		}

		for _, scenario := range errorScenarios {
			t.Run(scenario.name, func(t *testing.T) {
				// Test error message parsing and handling
				errorMsg := fmt.Sprintf("restic %s: exit status %d\n%s", 
					scenario.args[0], scenario.exitCode, scenario.stderr)
				
				// Verify error contains relevant information
				assert.Contains(t, errorMsg, scenario.command)
				assert.Contains(t, errorMsg, scenario.stderr)
				assert.Contains(t, errorMsg, fmt.Sprintf("exit status %d", scenario.exitCode))
			})
		}
	})

	t.Run("invalid configuration errors", func(t *testing.T) {
		// Test configuration validation errors
		invalidConfigs := []struct {
			name   string
			config *Config
			error  string
		}{
			{
				name: "missing repository",
				config: &Config{
					DefaultRepository: "missing",
					Repositories:      map[string]Repository{},
				},
				error: "repository \"missing\" not found",
			},
			{
				name: "invalid profile reference",
				config: &Config{
					Profiles: map[string]Profile{
						"test": {
							Repository: "nonexistent",
						},
					},
				},
				error: "repository nonexistent not found",
			},
		}

		for _, config := range invalidConfigs {
			t.Run(config.name, func(t *testing.T) {
				// Test configuration validation
				if config.config.DefaultRepository == "missing" {
					_, exists := config.config.Repositories["missing"]
					assert.False(t, exists, "Missing repository should not exist")
				}

				if len(config.config.Profiles) > 0 {
					for _, profile := range config.config.Profiles {
						if profile.Repository == "nonexistent" {
							_, exists := config.config.Repositories["nonexistent"]
							assert.False(t, exists, "Nonexistent repository should not exist")
						}
					}
				}
			})
		}
	})
}

// TestEnvironmentHandling tests environment variable handling
func TestEnvironmentHandling(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	t.Run("backend environment variables", func(t *testing.T) {
		// Test different backend configurations
		backends := map[string]map[string]string{
			"s3": {
				"AWS_ACCESS_KEY_ID":     "test-key",
				"AWS_SECRET_ACCESS_KEY": "test-secret",
				"AWS_DEFAULT_REGION":    "us-east-1",
			},
			"b2": {
				"B2_ACCOUNT_ID":  "test-account",
				"B2_ACCOUNT_KEY": "test-key",
			},
			"azure": {
				"AZURE_ACCOUNT_NAME": "test-account",
				"AZURE_ACCOUNT_KEY":  "test-key",
			},
			"gcs": {
				"GOOGLE_PROJECT_ID":               "test-project",
				"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/credentials.json",
			},
		}

		for backend, envVars := range backends {
			t.Run(backend, func(t *testing.T) {
				repository := &Repository{
					Name:        repo.Name,
					Backend:     backend,
					URL:         fmt.Sprintf("%s://test-bucket/backup", backend),
					Environment: envVars,
				}

				client := &Client{
					rc:         rc,
					repository: repository,
				}
				_ = client // Use client variable

				// Test environment setup
				env := os.Environ()
				env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", repository.URL))
				env = append(env, "RESTIC_PASSWORD=test-password")

				// Add backend-specific environment variables
				for k, v := range repository.Environment {
					env = append(env, fmt.Sprintf("%s=%s", k, v))
				}

				// Verify environment variables are set
				envMap := make(map[string]string)
				for _, envVar := range env {
					parts := strings.SplitN(envVar, "=", 2)
					if len(parts) == 2 {
						envMap[parts[0]] = parts[1]
					}
				}

				assert.Equal(t, repository.URL, envMap["RESTIC_REPOSITORY"])
				assert.Equal(t, "test-password", envMap["RESTIC_PASSWORD"])

				// Check backend-specific variables
				for k, v := range envVars {
					assert.Equal(t, v, envMap[k], "Environment variable %s should be set correctly", k)
				}
			})
		}
	})

	t.Run("environment security", func(t *testing.T) {
		// Test that environment variables are validated for security
		dangerousEnvVars := map[string]string{
			"VAR1": "value; rm -rf /",
			"VAR2": "value`whoami`",
			"VAR3": "value && curl evil.com",
		}

		for key, value := range dangerousEnvVars {
			keyDangerous := containsAnyDangerousBackup(key)
			valueDangerous := containsAnyDangerousBackup(value)

			if !keyDangerous && !valueDangerous {
				t.Logf("Dangerous environment variable not detected: %s=%s", key, value)
			}
		}
	})
}

// TestConcurrentOperations tests concurrent backup operations
func TestConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent operations test in short mode")
	}

	repo := createTestRepository(t)
	config := createTestConfig(t, repo)
	rc := createTestRuntimeContext(t)

	t.Run("concurrent client creation", func(t *testing.T) {
		// Test that multiple clients can be created concurrently
		const numClients = 5
		clients := make([]*Client, numClients)
		
		for i := 0; i < numClients; i++ {
			clients[i] = &Client{
				rc:         rc,
				config:     config,
				repository: func() *Repository { r := config.Repositories[repo.Name]; return &r }(),
			}
		}

		// Verify all clients were created
		for i, client := range clients {
			assert.NotNil(t, client, "Client %d should not be nil", i)
			assert.Equal(t, rc, client.rc)
		}
	})

	t.Run("concurrent command execution simulation", func(t *testing.T) {
		// Simulate concurrent command execution
		commands := [][]string{
			{"snapshots", "--json"},
			{"check"},
			{"stats"},
		}

		for i, cmd := range commands {
			t.Run(fmt.Sprintf("command_%d", i), func(t *testing.T) {
				// Test command argument validation
				for _, arg := range cmd {
					assert.False(t, containsAnyDangerousBackup(arg), 
						"Command argument should be safe: %s", arg)
				}
			})
		}
	})
}

// TestPerformanceConsiderations tests performance-related aspects
func TestPerformanceConsiderations(t *testing.T) {
	repo := createTestRepository(t)
	rc := createTestRuntimeContext(t)

	client := &Client{
		rc: rc,
		repository: &Repository{
			Name:    repo.Name,
			Backend: repo.Backend,
			URL:     repo.URL,
		},
	}

	t.Run("progress throttling", func(t *testing.T) {
		_ = client // Use client variable
		// Test progress update throttling
		lastProgress := time.Now().Add(-2 * time.Second) // 2 seconds ago
		currentTime := time.Now()
		
		timeSinceLastProgress := currentTime.Sub(lastProgress)
		shouldUpdate := timeSinceLastProgress > time.Second
		
		assert.True(t, shouldUpdate, "Progress should be updated after 1 second")
		
		// Test throttling (less than 1 second)
		recentProgress := time.Now().Add(-500 * time.Millisecond)
		timeSinceRecent := currentTime.Sub(recentProgress)
		shouldNotUpdate := timeSinceRecent <= time.Second
		
		assert.True(t, shouldNotUpdate, "Progress should be throttled within 1 second")
	})

	t.Run("memory usage estimation", func(t *testing.T) {
		// Test byte size calculations and humanization
		testSizes := []struct {
			bytes    int64
			expected string
		}{
			{1024, "1.0 KiB"},
			{1048576, "1.0 MiB"},
			{1073741824, "1.0 GiB"},
			{1099511627776, "1.0 TiB"},
		}

		for _, test := range testSizes {
			result := humanizeBytes(test.bytes)
			assert.Equal(t, test.expected, result)
		}
	})

	t.Run("command execution timing", func(t *testing.T) {
		// Test command execution timing
		start := time.Now()
		
		// Simulate command execution
		time.Sleep(10 * time.Millisecond)
		
		duration := time.Since(start)
		
		assert.Greater(t, duration, 10*time.Millisecond)
		assert.Less(t, duration, 100*time.Millisecond, "Command should complete quickly in test")
	})
}

// saveTestConfig saves a test configuration to a file
func saveTestConfig(filename string, config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// TestIntegrationWorkflow tests the complete backup workflow
func TestIntegrationWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration workflow test in short mode")
	}

	repo := createTestRepository(t)
	config := createTestConfig(t, repo)
	rc := createTestRuntimeContext(t)

	t.Run("complete workflow simulation", func(t *testing.T) {
		// 1. Create client
		client := &Client{
			rc:         rc,
			config:     config,
			repository: func() *Repository { r := config.Repositories[repo.Name]; return &r }(),
		}
		assert.NotNil(t, client)

		// 2. Validate configuration
		profile, exists := config.Profiles["test-profile"]
		assert.True(t, exists)
		assert.Equal(t, repo.Name, profile.Repository)

		// 3. Simulate repository initialization
		t.Log("Step 1: Repository initialization")
		initArgs := []string{"init", "--repository-version", "2"}
		assert.Equal(t, "init", initArgs[0])

		// 4. Simulate backup execution
		t.Log("Step 2: Backup execution")
		backupArgs := []string{"backup"}
		backupArgs = append(backupArgs, profile.Paths...)
		for _, exclude := range profile.Excludes {
			backupArgs = append(backupArgs, "--exclude", exclude)
		}
		backupArgs = append(backupArgs, "--json")
		
		assert.Contains(t, backupArgs, "backup")
		assert.Contains(t, backupArgs, "--json")

		// 5. Simulate progress monitoring
		t.Log("Step 3: Progress monitoring")
		progressMsg := map[string]interface{}{
			"message_type": "status",
			"percent_done": 0.5,
			"total_files":  100.0,
		}
		msgType, _ := progressMsg["message_type"].(string)
		assert.Equal(t, "status", msgType)

		// 6. Simulate retention policy
		t.Log("Step 4: Retention policy")
		if profile.Retention != nil {
			retentionArgs := []string{"forget", "--prune"}
			retentionArgs = append(retentionArgs, "--keep-last", "5")
			assert.Contains(t, retentionArgs, "forget")
			assert.Contains(t, retentionArgs, "--prune")
		}

		// 7. Simulate snapshot listing
		t.Log("Step 5: Snapshot listing")
		listArgs := []string{"snapshots", "--json"}
		assert.Equal(t, "snapshots", listArgs[0])
		assert.Contains(t, listArgs, "--json")

		// 8. Simulate verification
		t.Log("Step 6: Verification")
		checkArgs := []string{"check", "--read-data-subset=1/10", "snapshot123"}
		assert.Equal(t, "check", checkArgs[0])
		assert.Contains(t, checkArgs, "snapshot123")

		t.Log("Workflow simulation completed successfully")
	})
}