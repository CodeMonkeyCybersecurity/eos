// pkg/shared/delphi_services_test.go

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDelphiServiceRegistry_GetService(t *testing.T) {
	registry := GetDelphiServiceRegistry()

	tests := []struct {
		name            string
		serviceName     string
		shouldExist     bool
		expectedService DelphiServiceDefinition
	}{
		{
			name:        "get delphi-listener service",
			serviceName: "delphi-listener",
			shouldExist: true,
			expectedService: DelphiServiceDefinition{
				Name:          "delphi-listener",
				WorkerScript:  "/opt/stackstorm/packs/delphi/delphi-listener.py",
				ServiceFile:   "/etc/systemd/system/delphi-listener.service",
				Description:   "Webhook listener for Wazuh alerts - Pipeline entry point (includes alert-to-db dependency)",
				PipelineStage: "ingestion",
				User:          "stanley",
				Group:         "stanley",
				Permissions:   "0750",
			},
		},
		{
			name:        "get alert-to-db service (merged into delphi-listener)",
			serviceName: "alert-to-db",
			shouldExist: false, // Service was consolidated into delphi-listener
		},
		{
			name:        "get prompt-ab-tester service",
			serviceName: "prompt-ab-tester",
			shouldExist: true,
			expectedService: DelphiServiceDefinition{
				Name:          "prompt-ab-tester",
				WorkerScript:  "/usr/local/bin/prompt-ab-tester.py",
				ServiceFile:   "/etc/systemd/system/prompt-ab-tester.service",
				Description:   "A/B testing coordinator for prompt optimization - Assigns prompt variants and tracks experiments",
				PipelineStage: "analysis", 
				User:          "stanley",
				Group:         "stanley",
				Permissions:   "0750",
			},
		},
		{
			name:        "get non-existent service",
			serviceName: "non-existent-service",
			shouldExist: false,
		},
		{
			name:        "get empty service name",
			serviceName: "",
			shouldExist: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, exists := registry.GetService(tt.serviceName)

			assert.Equal(t, tt.shouldExist, exists)

			if tt.shouldExist {
				assert.Equal(t, tt.expectedService.Name, service.Name)
				assert.Equal(t, tt.expectedService.WorkerScript, service.WorkerScript)
				assert.Equal(t, tt.expectedService.ServiceFile, service.ServiceFile)
				assert.Equal(t, tt.expectedService.Description, service.Description)
				assert.Equal(t, tt.expectedService.PipelineStage, service.PipelineStage)
				assert.Equal(t, tt.expectedService.User, service.User)
				assert.Equal(t, tt.expectedService.Group, service.Group)
				assert.Equal(t, tt.expectedService.Permissions, service.Permissions)

				// Validate required fields are not empty
				assert.NotEmpty(t, service.SourceWorker)
				assert.NotEmpty(t, service.SourceService)
				assert.NotEmpty(t, service.Dependencies)
				assert.NotEmpty(t, service.Categories)
			}
		})
	}
}

func TestDelphiServiceRegistry_GetActiveServices(t *testing.T) {
	registry := GetDelphiServiceRegistry()

	services := registry.GetActiveServices()

	// Should have all the core services we expect
	assert.NotEmpty(t, services)

	// Convert to map for easier testing
	serviceMap := make(map[string]DelphiServiceDefinition)
	for _, service := range services {
		serviceMap[service.Name] = service
	}

	// Check that critical services from the crash are present
	criticalServices := []string{
		"delphi-listener",
		"delphi-agent-enricher", 
		"prompt-ab-tester",
		"llm-worker",
		"delphi-emailer",
	}

	for _, serviceName := range criticalServices {
		service, found := serviceMap[serviceName]
		assert.True(t, found, "Critical service %s not found", serviceName)

		// Validate service has required fields
		assert.NotEmpty(t, service.Name)
		assert.NotEmpty(t, service.WorkerScript)
		assert.NotEmpty(t, service.ServiceFile)
		assert.NotEmpty(t, service.SourceWorker)
		assert.NotEmpty(t, service.SourceService)
		assert.NotEmpty(t, service.Description)
		assert.NotEmpty(t, service.PipelineStage)
		assert.NotEmpty(t, service.User)
		assert.NotEmpty(t, service.Group)
		assert.NotEmpty(t, service.Permissions)
		assert.NotEmpty(t, service.Dependencies)
		assert.NotEmpty(t, service.Categories)
	}
}

func TestDelphiServiceRegistry_GetActiveServiceNames(t *testing.T) {
	registry := GetDelphiServiceRegistry()

	serviceNames := registry.GetActiveServiceNames()

	// Should not be empty
	assert.NotEmpty(t, serviceNames)

	// Check for duplicates
	nameSet := make(map[string]bool)
	for _, name := range serviceNames {
		assert.False(t, nameSet[name], "Duplicate service name found: %s", name)
		nameSet[name] = true
		assert.NotEmpty(t, name, "Empty service name found")
	}

	// Check that critical services are present
	criticalServices := []string{
		"alert-to-db",
		"ab-test-analyzer",
	}

	for _, criticalService := range criticalServices {
		assert.Contains(t, serviceNames, criticalService,
			"Critical service %s missing from active service names", criticalService)
	}
}

func TestDelphiServiceRegistry_ValidateService(t *testing.T) {
	registry := GetDelphiServiceRegistry()

	tests := []struct {
		name        string
		serviceName string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid service - delphi-listener",
			serviceName: "delphi-listener",
			expectError: false,
		},
		{
			name:        "valid service - alert-to-db",
			serviceName: "alert-to-db",
			expectError: false,
		},
		{
			name:        "valid service - ab-test-analyzer",
			serviceName: "ab-test-analyzer",
			expectError: false,
		},
		{
			name:        "invalid service",
			serviceName: "non-existent-service",
			expectError: true,
			errorMsg:    "service not found",
		},
		{
			name:        "empty service name",
			serviceName: "",
			expectError: true,
			errorMsg:    "service name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.ValidateService(tt.serviceName)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDelphiServiceRegistry_GetPipelineOrder(t *testing.T) {
	registry := GetDelphiServiceRegistry()

	pipelineOrder := registry.GetPipelineOrder()

	// Should not be empty
	assert.NotEmpty(t, pipelineOrder)

	// Check for duplicates
	orderSet := make(map[string]bool)
	for _, stage := range pipelineOrder {
		assert.False(t, orderSet[stage], "Duplicate pipeline stage found: %s", stage)
		orderSet[stage] = true
		assert.NotEmpty(t, stage, "Empty pipeline stage found")
	}

	// Check expected pipeline stages are present
	expectedStages := []string{
		"ingestion",
		"enrichment",
		"processing",
		"analysis",
	}

	for _, expectedStage := range expectedStages {
		assert.Contains(t, pipelineOrder, expectedStage,
			"Expected pipeline stage %s not found", expectedStage)
	}
}

func TestDelphiServiceRegistry_GetServicePipelineStage(t *testing.T) {
	registry := GetDelphiServiceRegistry()

	tests := []struct {
		name          string
		serviceName   string
		expectedStage string
		shouldExist   bool
	}{
		{
			name:          "delphi-listener stage",
			serviceName:   "delphi-listener",
			expectedStage: "ingestion",
			shouldExist:   true,
		},
		{
			name:          "alert-to-db stage (service merged)",
			serviceName:   "alert-to-db",
			expectedStage: "",
			shouldExist:   false, // Service was consolidated into delphi-listener
		},
		{
			name:          "prompt-ab-tester stage",
			serviceName:   "prompt-ab-tester",
			expectedStage: "analysis",
			shouldExist:   true,
		},
		{
			name:        "non-existent service",
			serviceName: "non-existent-service",
			shouldExist: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, exists := registry.GetService(tt.serviceName)

			assert.Equal(t, tt.shouldExist, exists)

			if tt.shouldExist {
				assert.Equal(t, tt.expectedStage, service.PipelineStage)
			}
		})
	}
}

func TestServiceCategory(t *testing.T) {
	// Test that all expected categories are defined
	expectedCategories := []ServiceCategory{
		CategoryIngestion,
		CategoryEnrichment,
		CategoryProcessing,
		CategoryAnalysis,
		CategoryFormatting,
		CategoryDelivery,
		CategoryMonitoring,
		CategoryTesting,
		CategoryDeprecated,
	}

	for _, category := range expectedCategories {
		assert.NotEmpty(t, string(category), "Category should not be empty")
	}

	// Test specific category values
	assert.Equal(t, "ingestion", string(CategoryIngestion))
	assert.Equal(t, "enrichment", string(CategoryEnrichment))
	assert.Equal(t, "processing", string(CategoryProcessing))
	assert.Equal(t, "analysis", string(CategoryAnalysis))
	assert.Equal(t, "formatting", string(CategoryFormatting))
	assert.Equal(t, "delivery", string(CategoryDelivery))
	assert.Equal(t, "monitoring", string(CategoryMonitoring))
	assert.Equal(t, "testing", string(CategoryTesting))
	assert.Equal(t, "deprecated", string(CategoryDeprecated))
}

func TestDelphiServiceDefinition_Structure(t *testing.T) {
	registry := GetDelphiServiceRegistry()
	services := registry.GetActiveServices()

	for _, service := range services {
		t.Run("validate_"+service.Name, func(t *testing.T) {
			// Required fields should not be empty
			assert.NotEmpty(t, service.Name)
			assert.NotEmpty(t, service.WorkerScript)
			assert.NotEmpty(t, service.ServiceFile)
			assert.NotEmpty(t, service.SourceWorker)
			assert.NotEmpty(t, service.SourceService)
			assert.NotEmpty(t, service.Description)
			assert.NotEmpty(t, service.PipelineStage)
			assert.NotEmpty(t, service.User)
			assert.NotEmpty(t, service.Group)
			assert.NotEmpty(t, service.Permissions)

			// Dependencies should be a non-empty slice
			assert.NotEmpty(t, service.Dependencies)
			for _, dep := range service.Dependencies {
				assert.NotEmpty(t, dep, "Dependency should not be empty for service %s", service.Name)
			}

			// Categories should be a non-empty slice
			assert.NotEmpty(t, service.Categories)
			for _, category := range service.Categories {
				assert.NotEmpty(t, string(category), "Category should not be empty for service %s", service.Name)
			}

			// Config files should have valid structure if present
			for _, configFile := range service.ConfigFiles {
				assert.NotEmpty(t, configFile.Path, "Config file path should not be empty for service %s", service.Name)
				assert.NotEmpty(t, configFile.Description, "Config file description should not be empty for service %s", service.Name)
			}

			// Environment vars should not be empty strings if present
			for _, envVar := range service.EnvironmentVars {
				assert.NotEmpty(t, envVar, "Environment variable should not be empty for service %s", service.Name)
			}

			// Paths should be absolute paths
			assert.True(t, service.WorkerScript[0] == '/', "Worker script should be absolute path for %s", service.Name)
			assert.True(t, service.ServiceFile[0] == '/', "Service file should be absolute path for %s", service.Name)
			assert.True(t, service.SourceWorker[0] == '/', "Source worker should be absolute path for %s", service.Name)
			assert.True(t, service.SourceService[0] == '/', "Source service should be absolute path for %s", service.Name)

			// User and group should be stanley for security services
			assert.Equal(t, "stanley", service.User)
			assert.Equal(t, "stanley", service.Group)

			// Permissions should be valid octal
			assert.Contains(t, []string{"0750", "0755", "0644"}, service.Permissions)
		})
	}
}

func TestGlobalServiceRegistryConsistency(t *testing.T) {
	// Test that the global registry functions return consistent data
	globalRegistry := GetGlobalDelphiServiceRegistry()
	newRegistry := GetDelphiServiceRegistry()

	// Both should return the same services
	globalServices := globalRegistry.GetActiveServices()
	newServices := newRegistry.GetActiveServices()

	assert.Equal(t, len(globalServices), len(newServices))

	// Convert to maps for comparison
	globalMap := make(map[string]DelphiServiceDefinition)
	newMap := make(map[string]DelphiServiceDefinition)

	for _, service := range globalServices {
		globalMap[service.Name] = service
	}

	for _, service := range newServices {
		newMap[service.Name] = service
	}

	// Compare each service
	for name, globalService := range globalMap {
		newService, exists := newMap[name]
		assert.True(t, exists, "Service %s exists in global but not in new registry", name)

		if exists {
			assert.Equal(t, globalService.Name, newService.Name)
			assert.Equal(t, globalService.WorkerScript, newService.WorkerScript)
			assert.Equal(t, globalService.ServiceFile, newService.ServiceFile)
			assert.Equal(t, globalService.Description, newService.Description)
		}
	}
}

// Benchmark service registry operations
func BenchmarkGetActiveServices(b *testing.B) {
	registry := GetDelphiServiceRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.GetActiveServices()
	}
}

func BenchmarkGetService(b *testing.B) {
	registry := GetDelphiServiceRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.GetService("delphi-listener")
	}
}

func BenchmarkValidateService(b *testing.B) {
	registry := GetDelphiServiceRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = registry.ValidateService("delphi-listener")
	}
}
