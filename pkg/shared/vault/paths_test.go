package vault

import (
	"testing"
)

// TestSecretPath tests the base secret path construction
func TestSecretPath(t *testing.T) {
	tests := []struct {
		name     string
		env      Environment
		svc      Service
		expected string
	}{
		{
			name:     "production consul",
			env:      EnvironmentProduction,
			svc:      ServiceConsul,
			expected: "services/production/consul",
		},
		{
			name:     "staging authentik",
			env:      EnvironmentStaging,
			svc:      ServiceAuthentik,
			expected: "services/staging/authentik",
		},
		{
			name:     "development bionicgpt",
			env:      EnvironmentDevelopment,
			svc:      ServiceBionicGPT,
			expected: "services/development/bionicgpt",
		},
		{
			name:     "review wazuh",
			env:      EnvironmentReview,
			svc:      ServiceWazuh,
			expected: "services/review/wazuh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecretPath(tt.env, tt.svc)
			if result != tt.expected {
				t.Errorf("SecretPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSecretDataPath tests the full API data path construction
func TestSecretDataPath(t *testing.T) {
	tests := []struct {
		name     string
		mount    string
		env      Environment
		svc      Service
		expected string
	}{
		{
			name:     "default mount production consul",
			mount:    "",
			env:      EnvironmentProduction,
			svc:      ServiceConsul,
			expected: "secret/data/services/production/consul",
		},
		{
			name:     "custom mount staging authentik",
			mount:    "kv",
			env:      EnvironmentStaging,
			svc:      ServiceAuthentik,
			expected: "kv/data/services/staging/authentik",
		},
		{
			name:     "default mount development bionicgpt",
			mount:    "",
			env:      EnvironmentDevelopment,
			svc:      ServiceBionicGPT,
			expected: "secret/data/services/development/bionicgpt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecretDataPath(tt.mount, tt.env, tt.svc)
			if result != tt.expected {
				t.Errorf("SecretDataPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSecretMetadataPath tests the full API metadata path construction
func TestSecretMetadataPath(t *testing.T) {
	tests := []struct {
		name     string
		mount    string
		env      Environment
		svc      Service
		expected string
	}{
		{
			name:     "default mount production consul",
			mount:    "",
			env:      EnvironmentProduction,
			svc:      ServiceConsul,
			expected: "secret/metadata/services/production/consul",
		},
		{
			name:     "custom mount staging authentik",
			mount:    "kv",
			env:      EnvironmentStaging,
			svc:      ServiceAuthentik,
			expected: "kv/metadata/services/staging/authentik",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecretMetadataPath(tt.mount, tt.env, tt.svc)
			if result != tt.expected {
				t.Errorf("SecretMetadataPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSecretListPath tests the environment listing path construction
func TestSecretListPath(t *testing.T) {
	tests := []struct {
		name     string
		mount    string
		env      Environment
		expected string
	}{
		{
			name:     "default mount production",
			mount:    "",
			env:      EnvironmentProduction,
			expected: "secret/metadata/services/production",
		},
		{
			name:     "custom mount staging",
			mount:    "kv",
			env:      EnvironmentStaging,
			expected: "kv/metadata/services/staging",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SecretListPath(tt.mount, tt.env)
			if result != tt.expected {
				t.Errorf("SecretListPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestParseSecretPath tests path parsing and validation
func TestParseSecretPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantEnv     Environment
		wantSvc     Service
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid production consul",
			path:    "services/production/consul",
			wantEnv: EnvironmentProduction,
			wantSvc: ServiceConsul,
			wantErr: false,
		},
		{
			name:    "valid staging authentik",
			path:    "services/staging/authentik",
			wantEnv: EnvironmentStaging,
			wantSvc: ServiceAuthentik,
			wantErr: false,
		},
		{
			name:    "valid with leading slash",
			path:    "/services/production/consul",
			wantEnv: EnvironmentProduction,
			wantSvc: ServiceConsul,
			wantErr: false,
		},
		{
			name:        "invalid too few parts",
			path:        "services/production",
			wantErr:     true,
			errContains: "expected 3 parts",
		},
		{
			name:        "invalid too many parts",
			path:        "services/production/consul/extra",
			wantErr:     true,
			errContains: "expected 3 parts",
		},
		{
			name:        "invalid prefix",
			path:        "wrong/production/consul",
			wantErr:     true,
			errContains: "must start with 'services'",
		},
		{
			name:        "invalid environment",
			path:        "services/invalid-env/consul",
			wantErr:     true,
			errContains: "invalid environment",
		},
		{
			name:        "invalid service",
			path:        "services/production/invalid-service",
			wantErr:     true,
			errContains: "invalid service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEnv, gotSvc, err := ParseSecretPath(tt.path)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSecretPath() expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("ParseSecretPath() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSecretPath() unexpected error = %v", err)
				return
			}

			if gotEnv != tt.wantEnv {
				t.Errorf("ParseSecretPath() env = %v, want %v", gotEnv, tt.wantEnv)
			}

			if gotSvc != tt.wantSvc {
				t.Errorf("ParseSecretPath() service = %v, want %v", gotSvc, tt.wantSvc)
			}
		})
	}
}

// TestValidateEnvironment tests environment validation
func TestValidateEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		wantErr bool
	}{
		{name: "valid production", env: "production", wantErr: false},
		{name: "valid staging", env: "staging", wantErr: false},
		{name: "valid development", env: "development", wantErr: false},
		{name: "valid review", env: "review", wantErr: false},
		{name: "invalid empty", env: "", wantErr: true},
		{name: "invalid unknown", env: "unknown", wantErr: true},
		{name: "invalid mixed case", env: "Production", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEnvironment(tt.env)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnvironment() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateService tests service validation
func TestValidateService(t *testing.T) {
	tests := []struct {
		name    string
		svc     string
		wantErr bool
	}{
		{name: "valid consul", svc: "consul", wantErr: false},
		{name: "valid authentik", svc: "authentik", wantErr: false},
		{name: "valid bionicgpt", svc: "bionicgpt", wantErr: false},
		{name: "valid wazuh", svc: "wazuh", wantErr: false},
		{name: "valid hecate", svc: "hecate", wantErr: false},
		{name: "valid helen", svc: "helen", wantErr: false},
		{name: "invalid empty", svc: "", wantErr: true},
		{name: "invalid unknown", svc: "unknown", wantErr: true},
		{name: "invalid mixed case", svc: "Consul", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateService(tt.svc)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateService() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAllServices tests the AllServices helper
func TestAllServices(t *testing.T) {
	services := AllServices()

	if len(services) < 4 {
		t.Errorf("AllServices() returned %d services, expected at least 4", len(services))
	}

	// Check that known services are present
	expectedServices := []Service{ServiceConsul, ServiceAuthentik, ServiceBionicGPT, ServiceWazuh}
	for _, expected := range expectedServices {
		found := false
		for _, svc := range services {
			if svc == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllServices() missing expected service: %v", expected)
		}
	}
}

// TestAllEnvironments tests the AllEnvironments helper
func TestAllEnvironments(t *testing.T) {
	envs := AllEnvironments()

	expectedEnvs := []Environment{
		EnvironmentProduction,
		EnvironmentStaging,
		EnvironmentDevelopment,
		EnvironmentReview,
	}

	if len(envs) != len(expectedEnvs) {
		t.Errorf("AllEnvironments() returned %d environments, expected %d", len(envs), len(expectedEnvs))
	}

	for _, expected := range expectedEnvs {
		found := false
		for _, env := range envs {
			if env == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllEnvironments() missing expected environment: %v", expected)
		}
	}
}

// TestCLIPath tests the CLI path helper (should be identical to SecretPath)
func TestCLIPath(t *testing.T) {
	env := EnvironmentProduction
	svc := ServiceConsul

	cliPath := CLIPath(env, svc)
	secretPath := SecretPath(env, svc)

	if cliPath != secretPath {
		t.Errorf("CLIPath() = %v, SecretPath() = %v, expected them to be identical", cliPath, secretPath)
	}
}

// TestLegacyPaths tests backward compatibility helpers
func TestLegacyPaths(t *testing.T) {
	tests := []struct {
		name     string
		function func() string
		expected string
	}{
		{
			name:     "legacy consul bootstrap token",
			function: func() string { return LegacyConsulPath("bootstrap-token") },
			expected: "consul/bootstrap-token",
		},
		{
			name:     "legacy bionicgpt oauth",
			function: func() string { return LegacyBionicGPTPath("oauth") },
			expected: "secret/bionicgpt/oauth",
		},
		{
			name:     "legacy hecate postgres password",
			function: func() string { return LegacyHecatePath("postgres", "password") },
			expected: "secret/hecate/postgres/password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function()
			if result != tt.expected {
				t.Errorf("Legacy path function = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestEnvironmentString tests the String() method on Environment
func TestEnvironmentString(t *testing.T) {
	env := EnvironmentProduction
	if env.String() != "production" {
		t.Errorf("Environment.String() = %v, want %v", env.String(), "production")
	}
}

// TestServiceString tests the String() method on Service
func TestServiceString(t *testing.T) {
	svc := ServiceConsul
	if svc.String() != "consul" {
		t.Errorf("Service.String() = %v, want %v", svc.String(), "consul")
	}
}

// TestPathConsistency verifies that paths constructed via different methods are consistent
func TestPathConsistency(t *testing.T) {
	env := EnvironmentProduction
	svc := ServiceConsul

	// All these should produce paths that include the same base path
	basePath := SecretPath(env, svc)
	dataPath := SecretDataPath("", env, svc)
	metadataPath := SecretMetadataPath("", env, svc)
	listPath := SecretListPath("", env)

	// Data path should contain base path
	if !contains(dataPath, basePath) {
		t.Errorf("SecretDataPath() = %v does not contain base path %v", dataPath, basePath)
	}

	// Metadata path should contain base path
	if !contains(metadataPath, basePath) {
		t.Errorf("SecretMetadataPath() = %v does not contain base path %v", metadataPath, basePath)
	}

	// List path should contain the environment portion
	expectedListBase := "services/" + string(env)
	if !contains(listPath, expectedListBase) {
		t.Errorf("SecretListPath() = %v does not contain expected base %v", listPath, expectedListBase)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
