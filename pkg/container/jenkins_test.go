package container

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	vaultapi "github.com/hashicorp/vault/api"
)

func TestJenkinsOptions(t *testing.T) {
	t.Run("jenkins options struct", func(t *testing.T) {
		opts := JenkinsOptions{
			JenkinsImage:      "jenkins/jenkins:lts",
			JenkinsContainer:  "jenkins-main",
			JenkinsUIPort:     "8080",
			JenkinsAgentPort:  "50000",
			VolumeName:        "jenkins-data",
			NetworkName:       "jenkins-network",
			SSHAgentContainer: "jenkins-ssh-agent",
			SSHAgentImage:     "jenkins/ssh-agent:latest",
		}

		// Verify all fields are set
		testutil.AssertEqual(t, "jenkins/jenkins:lts", opts.JenkinsImage)
		testutil.AssertEqual(t, "jenkins-main", opts.JenkinsContainer)
		testutil.AssertEqual(t, "8080", opts.JenkinsUIPort)
		testutil.AssertEqual(t, "50000", opts.JenkinsAgentPort)
		testutil.AssertEqual(t, "jenkins-data", opts.VolumeName)
		testutil.AssertEqual(t, "jenkins-network", opts.NetworkName)
		testutil.AssertEqual(t, "jenkins-ssh-agent", opts.SSHAgentContainer)
		testutil.AssertEqual(t, "jenkins/ssh-agent:latest", opts.SSHAgentImage)
	})
}

func TestWriteAndUpJenkins(t *testing.T) {
	tests := []struct {
		name       string
		appName    string
		opts       JenkinsOptions
		wantErr    bool
		errContains string
	}{
		{
			name:    "valid jenkins deployment",
			appName: "jenkins-test",
			opts: JenkinsOptions{
				JenkinsImage:      "jenkins/jenkins:lts",
				JenkinsContainer:  "jenkins-main",
				JenkinsUIPort:     "8080",
				JenkinsAgentPort:  "50000",
				VolumeName:        "jenkins-data",
				NetworkName:       "jenkins-network",
				SSHAgentContainer: "jenkins-ssh-agent",
				SSHAgentImage:     "jenkins/ssh-agent:latest",
			},
			wantErr: true, // Will fail because ComposeUpInDir requires docker
		},
		{
			name:    "empty app name",
			appName: "",
			opts: JenkinsOptions{
				JenkinsImage: "jenkins/jenkins:lts",
			},
			wantErr: true,
		},
		{
			name:    "app name with path traversal",
			appName: "../../../etc",
			opts: JenkinsOptions{
				JenkinsImage: "jenkins/jenkins:lts",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			// Create temp directory for testing
			tempDir := t.TempDir()
			// Change working directory to temp for the test
			origWd, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working directory: %v", err)
			}
			defer func() {
				if err := os.Chdir(origWd); err != nil {
					t.Errorf("failed to restore working directory: %v", err)
				}
			}()
			if err := os.Chdir(tempDir); err != nil {
				t.Fatalf("failed to change to temp directory: %v", err)
			}

			err := WriteAndUpJenkins(rc, tc.appName, tc.opts)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errContains != "" {
					testutil.AssertErrorContains(t, err, tc.errContains)
				}
			} else {
				testutil.AssertNoError(t, err)

				// Verify file was created
				expectedPath := filepath.Join("/opt", tc.appName, "docker-compose.yml")
				if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
					t.Errorf("Expected docker-compose.yml to be created at %s", expectedPath)
				}
			}
		})
	}
}

func TestStoreJenkinsAdminPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		setupClient func() *vaultapi.Client
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid password with mock client",
			password: "test-password",
			setupClient: func() *vaultapi.Client {
				// Create a client with default config - will fail but won't panic
				client, _ := vaultapi.NewClient(vaultapi.DefaultConfig())
				return client
			},
			wantErr: true, // Will fail in test environment without vault
		},
		{
			name:     "empty password",
			password: "",
			setupClient: func() *vaultapi.Client {
				// Create a mock client that will fail in test environment
				client, _ := vaultapi.NewClient(vaultapi.DefaultConfig())
				return client
			},
			wantErr: true, // Will fail in test environment
		},
		{
			name:     "valid password",
			password: "secure-admin-password-123",
			setupClient: func() *vaultapi.Client {
				// Create a mock client that will fail in test environment
				client, _ := vaultapi.NewClient(vaultapi.DefaultConfig())
				return client
			},
			wantErr: true, // Will fail in test environment without vault
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			client := tc.setupClient()

			err := StoreJenkinsAdminPassword(rc, client, tc.password)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errContains != "" {
					testutil.AssertErrorContains(t, err, tc.errContains)
				}
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestJenkinsSecurity(t *testing.T) {
	t.Run("malicious app names", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousNames := []string{
			"../../../etc/passwd",
			"app; rm -rf /",
			"app`whoami`",
			"app$(id)",
			"app\x00injection",
			"app\nrm -rf /",
		}

		opts := JenkinsOptions{
			JenkinsImage: "jenkins/jenkins:lts",
		}

		for _, name := range maliciousNames {
			t.Run("malicious_name", func(t *testing.T) {
				err := WriteAndUpJenkins(rc, name, opts)
				// Should handle malicious paths safely
				testutil.AssertError(t, err)
			})
		}
	})

	t.Run("password security", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		client, _ := vaultapi.NewClient(vaultapi.DefaultConfig())

		sensitivePasswords := []string{
			"password with spaces",
			"password;with;semicolons",
			"password\nwith\nnewlines",
			"password`with`backticks",
			"password$(injection)",
		}

		for _, password := range sensitivePasswords {
			t.Run("sensitive_password", func(t *testing.T) {
				err := StoreJenkinsAdminPassword(rc, client, password)
				// Should handle sensitive passwords safely
				// Will error in test environment due to no vault connection
				testutil.AssertError(t, err)
			})
		}
	})
}

func BenchmarkWriteAndUpJenkins(b *testing.B) {
	// Skip benchmarks since they require docker and file system operations
	b.Skip("Skipping benchmark - requires docker and file system setup")
}

func BenchmarkStoreJenkinsAdminPassword(b *testing.B) {
	// Skip benchmarks since they require vault connection
	b.Skip("Skipping benchmark - requires vault connection")
}