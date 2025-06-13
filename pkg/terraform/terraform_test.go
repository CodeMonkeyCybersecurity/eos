// pkg/terraform/terraform_test.go

package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestNewManager(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	
	manager := NewManager(rc, "/tmp/test-terraform")
	
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
	
	if manager.Config == nil {
		t.Fatal("Config is nil")
	}
	
	if manager.Config.WorkingDir != "/tmp/test-terraform" {
		t.Errorf("Expected working dir '/tmp/test-terraform', got '%s'", manager.Config.WorkingDir)
	}
	
	if manager.Config.Variables == nil {
		t.Error("Variables map is nil")
	}
	
	if manager.Config.BackendConfig == nil {
		t.Error("BackendConfig map is nil")
	}
	
	if manager.Config.Providers == nil {
		t.Error("Providers slice is nil")
	}
}

func TestSetVariable(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	
	manager := NewManager(rc, "/tmp/test")
	
	manager.SetVariable("test_key", "test_value")
	manager.SetVariable("test_number", 123)
	
	if val, exists := manager.Config.Variables["test_key"]; !exists {
		t.Error("test_key not found in variables")
	} else if val != "test_value" {
		t.Errorf("Expected 'test_value', got '%v'", val)
	}
	
	if val, exists := manager.Config.Variables["test_number"]; !exists {
		t.Error("test_number not found in variables")
	} else if val != 123 {
		t.Errorf("Expected 123, got %v", val)
	}
}

func TestSetBackendConfig(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	
	manager := NewManager(rc, "/tmp/test")
	
	manager.SetBackendConfig("bucket", "my-tf-state")
	manager.SetBackendConfig("key", "terraform.tfstate")
	
	if val, exists := manager.Config.BackendConfig["bucket"]; !exists {
		t.Error("bucket not found in backend config")
	} else if val != "my-tf-state" {
		t.Errorf("Expected 'my-tf-state', got '%s'", val)
	}
	
	if val, exists := manager.Config.BackendConfig["key"]; !exists {
		t.Error("key not found in backend config")
	} else if val != "terraform.tfstate" {
		t.Errorf("Expected 'terraform.tfstate', got '%s'", val)
	}
}

func TestAddProvider(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	
	manager := NewManager(rc, "/tmp/test")
	
	manager.AddProvider("aws")
	manager.AddProvider("hcloud")
	
	if len(manager.Config.Providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(manager.Config.Providers))
	}
	
	expected := []string{"aws", "hcloud"}
	for i, provider := range expected {
		if manager.Config.Providers[i] != provider {
			t.Errorf("Expected provider '%s' at index %d, got '%s'", provider, i, manager.Config.Providers[i])
		}
	}
}

func TestGenerateFromString(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{Ctx: ctx}
	
	// Create temporary directory
	tmpDir := t.TempDir()
	
	manager := NewManager(rc, tmpDir)
	
	templateStr := `resource "test_resource" "example" {
  name = "{{.Name}}"
  type = "{{.Type}}"
}`
	
	data := struct {
		Name string
		Type string
	}{
		Name: "test-resource",
		Type: "example",
	}
	
	err := manager.GenerateFromString(templateStr, "test.tf", data)
	if err != nil {
		t.Fatalf("GenerateFromString failed: %v", err)
	}
	
	// Check if file was created
	outputFile := filepath.Join(tmpDir, "test.tf")
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatal("Output file was not created")
	}
	
	// Read and check content
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}
	
	expectedContent := `resource "test_resource" "example" {
  name = "test-resource"
  type = "example"
}`
	
	if string(content) != expectedContent {
		t.Errorf("Content mismatch.\nExpected:\n%s\nGot:\n%s", expectedContent, string(content))
	}
}

func TestCheckTerraformInstalled(t *testing.T) {
	// This test will pass if terraform is installed, skip if not
	err := CheckTerraformInstalled()
	if err != nil {
		t.Skipf("Terraform not installed: %v", err)
	}
}

func TestK3sConfigStruct(t *testing.T) {
	config := K3sConfig{
		ServerName:   "test-server",
		ServerType:   "cx11",
		Location:     "nbg1",
		SSHKeyName:   "my-key",
		K3sRole:      "server",
		K3sServerURL: "",
		K3sToken:     "",
	}
	
	if config.ServerName != "test-server" {
		t.Errorf("Expected ServerName 'test-server', got '%s'", config.ServerName)
	}
	
	if config.K3sRole != "server" {
		t.Errorf("Expected K3sRole 'server', got '%s'", config.K3sRole)
	}
}

func TestDockerComposeConfigStruct(t *testing.T) {
	config := DockerComposeConfig{
		ProjectName: "test-project",
		ComposeFile: "docker-compose.yml",
		Services: []DockerService{
			{
				Name:        "web",
				Image:       "nginx:latest",
				ProjectName: "test-project",
				Ports: []DockerPort{
					{Internal: 80, External: 8080, Protocol: "tcp"},
				},
			},
		},
		UseHetzner: false,
	}
	
	if config.ProjectName != "test-project" {
		t.Errorf("Expected ProjectName 'test-project', got '%s'", config.ProjectName)
	}
	
	if len(config.Services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(config.Services))
	}
	
	service := config.Services[0]
	if service.Name != "web" {
		t.Errorf("Expected service name 'web', got '%s'", service.Name)
	}
	
	if len(service.Ports) != 1 {
		t.Errorf("Expected 1 port, got %d", len(service.Ports))
	}
}

func TestHetznerInfraConfigStruct(t *testing.T) {
	config := HetznerInfraConfig{
		ProjectName: "test-infra",
		SSHKeyName:  "my-key",
		Servers: []HetznerServer{
			{
				Name:     "web-server",
				Image:    "ubuntu-22.04",
				Type:     "cx11",
				Location: "nbg1",
				Role:     "web",
			},
		},
		Networks: []HetznerNetwork{
			{
				Name:        "internal",
				IPRange:     "10.0.0.0/16",
				Zone:        "eu-central",
				SubnetRange: "10.0.1.0/24",
			},
		},
	}
	
	if config.ProjectName != "test-infra" {
		t.Errorf("Expected ProjectName 'test-infra', got '%s'", config.ProjectName)
	}
	
	if len(config.Servers) != 1 {
		t.Errorf("Expected 1 server, got %d", len(config.Servers))
	}
	
	if len(config.Networks) != 1 {
		t.Errorf("Expected 1 network, got %d", len(config.Networks))
	}
}