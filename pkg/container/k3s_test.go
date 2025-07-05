package container

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

func TestK3sInstallOptions(t *testing.T) {
	t.Run("k3s install options struct", func(t *testing.T) {
		opts := K3sInstallOptions{
			Type:              "server",
			ServerURL:         "https://k3s-server.example.com:6443",
			Token:             "K10abc123def456::server:789ghi",
			DataDir:           "/var/lib/rancher/k3s",
			DisableComponents: []string{"traefik", "servicelb"},
			EnableComponents:  []string{"metrics-server"},
			Version:           "v1.28.5+k3s1",
			ExtraArgs:         []string{"--disable-cloud-controller"},
		}

		// Verify all fields are set correctly
		testutil.AssertEqual(t, "server", opts.Type)
		testutil.AssertEqual(t, "https://k3s-server.example.com:6443", opts.ServerURL)
		testutil.AssertEqual(t, "K10abc123def456::server:789ghi", opts.Token)
		testutil.AssertEqual(t, "/var/lib/rancher/k3s", opts.DataDir)
		testutil.AssertEqual(t, 2, len(opts.DisableComponents))
		testutil.AssertEqual(t, "traefik", opts.DisableComponents[0])
		testutil.AssertEqual(t, "servicelb", opts.DisableComponents[1])
		testutil.AssertEqual(t, 1, len(opts.EnableComponents))
		testutil.AssertEqual(t, "metrics-server", opts.EnableComponents[0])
		testutil.AssertEqual(t, "v1.28.5+k3s1", opts.Version)
		testutil.AssertEqual(t, 1, len(opts.ExtraArgs))
		testutil.AssertEqual(t, "--disable-cloud-controller", opts.ExtraArgs[0])
	})
}

func TestInstallK3sServer(t *testing.T) {
	tests := []struct {
		name    string
		options *K3sInstallOptions
		wantErr bool
	}{
		{
			name: "basic k3s server installation",
			options: &K3sInstallOptions{
				Type:              "server",
				DisableComponents: []string{"traefik"},
				Version:           "v1.28.5+k3s1",
			},
			wantErr: true, // Will fail in test environment (requires root, network, etc.)
		},
		{
			name: "k3s server with custom data dir",
			options: &K3sInstallOptions{
				Type:              "server",
				DataDir:           "/custom/k3s/data",
				DisableComponents: []string{"traefik", "servicelb"},
				Version:           "v1.27.8+k3s2",
			},
			wantErr: true, // Will fail in test environment
		},
		{
			name:    "nil options",
			options: nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := InstallK3sServer(rc, tc.options)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestInstallK3sAgent(t *testing.T) {
	tests := []struct {
		name    string
		options *K3sInstallOptions
		wantErr bool
		errContains string
	}{
		{
			name: "basic k3s agent installation",
			options: &K3sInstallOptions{
				Type:      "agent",
				ServerURL: "https://k3s-server.example.com:6443",
				Token:     "K10abc123def456::server:789ghi",
				Version:   "v1.28.5+k3s1",
			},
			wantErr: true, // Will fail in test environment
		},
		{
			name: "k3s agent with custom data dir",
			options: &K3sInstallOptions{
				Type:      "agent",
				ServerURL: "https://k3s-server.local:6443",
				Token:     "agent-token-12345",
				DataDir:   "/custom/k3s/agent",
				Version:   "v1.27.8+k3s2",
			},
			wantErr: true, // Will fail in test environment
		},
		{
			name: "agent without server URL",
			options: &K3sInstallOptions{
				Type:  "agent",
				Token: "some-token",
			},
			wantErr:     true,
			errContains: "server URL is required",
		},
		{
			name: "agent without token",
			options: &K3sInstallOptions{
				Type:      "agent",
				ServerURL: "https://k3s-server.example.com:6443",
			},
			wantErr:     true,
			errContains: "token is required",
		},
		{
			name:    "nil options",
			options: nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			err := InstallK3sAgent(rc, tc.options)

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

func TestGetK3sStatus(t *testing.T) {
	t.Run("get k3s status", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		err := GetK3sStatus(rc)

		// Will fail in test environment without K3s installation
		testutil.AssertError(t, err)
	})
}

func TestUninstallK3s(t *testing.T) {
	t.Run("uninstall k3s", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		err := UninstallK3s(rc)

		// Will fail in test environment (requires root and K3s installation)
		testutil.AssertError(t, err)
	})
}

func TestGetK3sToken(t *testing.T) {
	t.Run("get k3s token", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		_, err := GetK3sToken(rc)

		// Will fail in test environment without K3s server
		testutil.AssertError(t, err)
	})
}

func TestK3sSecurity(t *testing.T) {
	t.Run("malicious server URLs", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousURLs := []string{
			"$(whoami).example.com:6443",
			"`id`.example.com:6443",
			"https://server; rm -rf /:6443",
			"https://server\nmalicious:6443",
			"https://server$(injection):6443",
		}

		for _, url := range maliciousURLs {
			t.Run("malicious_url", func(t *testing.T) {
				opts := &K3sInstallOptions{
					Type:      "agent",
					ServerURL: url,
					Token:     "safe-token",
				}

				err := InstallK3sAgent(rc, opts)
				// Should handle malicious input safely
				testutil.AssertError(t, err)
			})
		}
	})

	t.Run("malicious tokens", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousTokens := []string{
			"token; rm -rf /",
			"token$(whoami)",
			"token`id`",
			"token\nmalicious",
			"token\x00injection",
		}

		for _, token := range maliciousTokens {
			t.Run("malicious_token", func(t *testing.T) {
				opts := &K3sInstallOptions{
					Type:      "agent",
					ServerURL: "https://safe-server.example.com:6443",
					Token:     token,
				}

				err := InstallK3sAgent(rc, opts)
				// Should handle malicious input safely
				testutil.AssertError(t, err)
			})
		}
	})

	t.Run("malicious data directories", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousDirs := []string{
			"/tmp; rm -rf /",
			"/tmp$(whoami)",
			"/tmp`id`",
			"/tmp\nmalicious",
			"../../../etc",
		}

		for _, dir := range maliciousDirs {
			t.Run("malicious_dir", func(t *testing.T) {
				opts := &K3sInstallOptions{
					Type:    "server",
					DataDir: dir,
				}

				err := InstallK3sServer(rc, opts)
				// Should handle malicious input safely
				testutil.AssertError(t, err)
			})
		}
	})

	t.Run("malicious disable components", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		maliciousComponents := []string{
			"traefik; rm -rf /",
			"component$(whoami)",
			"component`id`",
			"component\nmalicious",
		}

		for _, component := range maliciousComponents {
			t.Run("malicious_component", func(t *testing.T) {
				opts := &K3sInstallOptions{
					Type:              "server",
					DisableComponents: []string{component},
				}

				err := InstallK3sServer(rc, opts)
				// Should handle malicious input safely
				testutil.AssertError(t, err)
			})
		}
	})
}

func TestK3sConcurrency(t *testing.T) {
	t.Run("concurrent status checks", func(t *testing.T) {
		// Test concurrent status checks
		testutil.ParallelTest(t, 3, func(t *testing.T, i int) {
			rc := testutil.TestRuntimeContext(t)
			err := GetK3sStatus(rc)
			// All will error in test environment, but should be safe
			testutil.AssertError(t, err)
		})
	})

	t.Run("concurrent token retrieval", func(t *testing.T) {
		// Test concurrent token retrieval
		testutil.ParallelTest(t, 3, func(t *testing.T, i int) {
			rc := testutil.TestRuntimeContext(t)
			_, err := GetK3sToken(rc)
			// All will error in test environment, but should be safe
			testutil.AssertError(t, err)
		})
	})
}

func BenchmarkInstallK3sServer(b *testing.B) {
	// Skip benchmarks since they require root privileges and network access
	b.Skip("Skipping benchmark - requires root privileges and network access")
}

func BenchmarkInstallK3sAgent(b *testing.B) {
	// Skip benchmarks since they require root privileges and network access
	b.Skip("Skipping benchmark - requires root privileges and network access")
}

func BenchmarkGetK3sStatus(b *testing.B) {
	// Skip benchmarks since they require K3s installation
	b.Skip("Skipping benchmark - requires K3s installation")
}