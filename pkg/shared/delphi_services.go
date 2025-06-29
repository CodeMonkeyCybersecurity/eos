// pkg/shared/delphi_services.go

package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DelphiServiceDefinition represents a complete service definition
type DelphiServiceDefinition struct {
	Name            string            `json:"name"`
	WorkerScript    string            `json:"worker_script"`
	ServiceFile     string            `json:"service_file"`
	SourceWorker    string            `json:"source_worker"`    // Source path in assets/
	SourceService   string            `json:"source_service"`   // Source service file in assets/
	Description     string            `json:"description"`
	PipelineStage   string            `json:"pipeline_stage"`
	Dependencies    []string          `json:"dependencies"`
	ConfigFiles     []ConfigFile      `json:"config_files"`
	EnvironmentVars []string          `json:"environment_vars"`
	Ports           []int             `json:"ports,omitempty"`
	User            string            `json:"user"`
	Group           string            `json:"group"`
	Permissions     string            `json:"permissions"`
	ABTestEnabled   bool              `json:"ab_test_enabled"`
	Deprecated      bool              `json:"deprecated"`
	ReplacedBy      string            `json:"replaced_by,omitempty"`
	Categories      []ServiceCategory `json:"categories"`
}

// ConfigFile represents a configuration file requirement
type ConfigFile struct {
	Path        string `json:"path"`
	Template    string `json:"template,omitempty"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// ServiceCategory for organizing services
type ServiceCategory string

const (
	CategoryIngestion   ServiceCategory = "ingestion"
	CategoryEnrichment  ServiceCategory = "enrichment"
	CategoryProcessing  ServiceCategory = "processing"
	CategoryAnalysis    ServiceCategory = "analysis"
	CategoryFormatting  ServiceCategory = "formatting"
	CategoryDelivery    ServiceCategory = "delivery"
	CategoryMonitoring  ServiceCategory = "monitoring"
	CategoryTesting     ServiceCategory = "testing"
	CategoryDeprecated  ServiceCategory = "deprecated"
)

// ServiceInstallationStatus represents the installation state of a service
type ServiceInstallationStatus struct {
	ServiceName       string `json:"service_name"`
	WorkerInstalled   bool   `json:"worker_installed"`
	ServiceInstalled  bool   `json:"service_installed"`
	ServiceEnabled    bool   `json:"service_enabled"`
	ServiceActive     bool   `json:"service_active"`
	WorkerPath        string `json:"worker_path"`
	ServicePath       string `json:"service_path"`
	SourceWorkerPath  string `json:"source_worker_path"`
	SourceServicePath string `json:"source_service_path"`
}

// DelphiServiceRegistry provides centralized service management
type DelphiServiceRegistry struct {
	services map[string]DelphiServiceDefinition
}

// GetDelphiServiceRegistry returns the global service registry
func GetDelphiServiceRegistry() *DelphiServiceRegistry {
	registry := &DelphiServiceRegistry{
		services: make(map[string]DelphiServiceDefinition),
	}
	
	// Core pipeline services - centralized definitions
	registry.registerService(DelphiServiceDefinition{
		Name:          "delphi-listener",
		WorkerScript:  "/opt/stackstorm/packs/delphi/delphi-listener.py",
		ServiceFile:   "/etc/systemd/system/delphi-listener.service",
		SourceWorker:  "/opt/eos/assets/python_workers/delphi-listener.py",
		SourceService: "/opt/eos/assets/services/delphi-listener.service",
		Description:   "Webhook listener for Wazuh alerts - Pipeline entry point",
		PipelineStage: "ingestion",
		Dependencies:  []string{"python3", "requests", "psycopg2", "python-dotenv"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database and webhook configuration"},
		},
		EnvironmentVars: []string{"PG_DSN", "WEBHOOK_PORT"},
		Ports:          []int{8080},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryIngestion},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "delphi-agent-enricher",
		WorkerScript:  "/opt/stackstorm/packs/delphi/delphi-agent-enricher.py",
		ServiceFile:   "/etc/systemd/system/delphi-agent-enricher.service",
		SourceWorker:  "/opt/eos/assets/python_workers/delphi-agent-enricher.py",
		SourceService: "/opt/eos/assets/services/delphi-agent-enricher.service",
		Description:   "Agent metadata enrichment service - Adds agent context to alerts",
		PipelineStage: "enrichment",
		Dependencies:  []string{"python3", "requests", "psycopg2", "python-dotenv"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
		},
		EnvironmentVars: []string{"PG_DSN"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryEnrichment},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "alert-to-db",
		WorkerScript:  "/opt/stackstorm/packs/delphi/alert-to-db.py",
		ServiceFile:   "/etc/systemd/system/alert-to-db.service",
		SourceWorker:  "/opt/eos/assets/python_workers/alert-to-db.py",
		SourceService: "/opt/eos/assets/services/alert-to-db.service",
		Description:   "Database operations for alerts - Handles alert persistence and state transitions",
		PipelineStage: "processing",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
		},
		EnvironmentVars: []string{"PG_DSN"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryProcessing},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "prompt-ab-tester",
		WorkerScript:  "/usr/local/bin/prompt-ab-tester.py",
		ServiceFile:   "/etc/systemd/system/prompt-ab-tester.service",
		SourceWorker:  "/opt/eos/assets/python_workers/prompt-ab-tester.py",
		SourceService: "/opt/eos/assets/services/prompt-ab-tester.service",
		Description:   "A/B testing coordinator for prompt optimization - Assigns prompt variants and tracks experiments",
		PipelineStage: "analysis",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
			{Path: "/opt/delphi/ab-test-config.json", Required: true, Description: "A/B testing experiment configuration"},
			{Path: "/opt/stackstorm/packs/delphi/prompts/", Required: true, Description: "Prompt template directory"},
		},
		EnvironmentVars: []string{"PG_DSN", "EXPERIMENT_CONFIG_FILE", "PROMPTS_BASE_DIR"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		ABTestEnabled:  true,
		Categories:     []ServiceCategory{CategoryTesting, CategoryAnalysis},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "llm-worker",
		WorkerScript:  "/opt/stackstorm/packs/delphi/llm-worker.py",
		ServiceFile:   "/etc/systemd/system/llm-worker.service",
		SourceWorker:  "/opt/eos/assets/python_workers/llm-worker.py",
		SourceService: "/opt/eos/assets/services/llm-worker.service",
		Description:   "LLM processing service - Analyzes alerts using OpenAI API with prompt-aware parsing",
		PipelineStage: "analysis",
		Dependencies:  []string{"python3", "requests", "psycopg2", "openai", "python-dotenv"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database and OpenAI configuration"},
			{Path: "/srv/eos/system-prompts/default.txt", Required: true, Description: "Default system prompt"},
		},
		EnvironmentVars: []string{"PG_DSN", "OPENAI_API_KEY", "DEFAULT_PROMPT_TYPE"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		ABTestEnabled:  true,
		Categories:     []ServiceCategory{CategoryAnalysis, CategoryProcessing},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "ab-test-analyzer",
		WorkerScript:  "/usr/local/bin/ab-test-analyzer.py",
		ServiceFile:   "/etc/systemd/system/ab-test-analyzer.service",
		SourceWorker:  "/opt/eos/assets/python_workers/ab-test-analyzer.py",
		SourceService: "/opt/eos/assets/services/ab-test-analyzer.service",
		Description:   "A/B test results analyzer - Evaluates experiment performance and provides insights",
		PipelineStage: "analysis",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv", "numpy", "scipy"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
			{Path: "/opt/delphi/ab-test-config.json", Required: true, Description: "A/B testing configuration"},
		},
		EnvironmentVars: []string{"PG_DSN", "EXPERIMENT_CONFIG_FILE"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		ABTestEnabled:  true,
		Categories:     []ServiceCategory{CategoryTesting, CategoryAnalysis},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "email-structurer",
		WorkerScript:  "/usr/local/bin/email-structurer.py",
		ServiceFile:   "/etc/systemd/system/email-structurer.service",
		SourceWorker:  "/opt/eos/assets/python_workers/email-structurer.py",
		SourceService: "/opt/eos/assets/services/email-structurer.service",
		Description:   "Email structuring service - Converts analyzed alerts to structured email data",
		PipelineStage: "formatting",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
		},
		EnvironmentVars: []string{"PG_DSN"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryFormatting},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "email-formatter",
		WorkerScript:  "/usr/local/bin/email-formatter.py",
		ServiceFile:   "/etc/systemd/system/email-formatter.service",
		SourceWorker:  "/opt/eos/assets/python_workers/email-formatter.py",
		SourceService: "/opt/eos/assets/services/email-formatter.service",
		Description:   "Email formatting service - Renders structured data into HTML/text email templates",
		PipelineStage: "formatting",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv", "jinja2"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
			{Path: "/opt/stackstorm/packs/delphi/email.html", Required: true, Description: "Email HTML template"},
		},
		EnvironmentVars: []string{"PG_DSN", "EMAIL_TEMPLATE_PATH"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryFormatting},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "email-sender",
		WorkerScript:  "/usr/local/bin/email-sender.py",
		ServiceFile:   "/etc/systemd/system/email-sender.service",
		SourceWorker:  "/opt/eos/assets/python_workers/email-sender.py",
		SourceService: "/opt/eos/assets/services/email-sender.service",
		Description:   "Email delivery service - Sends formatted emails via SMTP with delivery tracking",
		PipelineStage: "delivery",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv", "smtplib"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database and SMTP configuration"},
		},
		EnvironmentVars: []string{"PG_DSN", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryDelivery},
	})
	
	registry.registerService(DelphiServiceDefinition{
		Name:          "parser-monitor",
		WorkerScript:  "/usr/local/bin/parser-monitor.py",
		ServiceFile:   "/etc/systemd/system/parser-monitor.service",
		SourceWorker:  "/opt/eos/assets/python_workers/parser-monitor.py",
		SourceService: "/opt/eos/assets/services/parser-monitor.service",
		Description:   "Parser health monitoring service - Provides observability for prompt-aware parsing system",
		PipelineStage: "monitoring",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv", "tabulate"},
		ConfigFiles: []ConfigFile{
			{Path: "/opt/stackstorm/packs/delphi/.env", Required: true, Description: "Database configuration"},
		},
		EnvironmentVars: []string{"PG_DSN"},
		User:           "stanley",
		Group:          "stanley",
		Permissions:    "0750",
		Categories:     []ServiceCategory{CategoryMonitoring},
	})
	
	// Deprecated services
	registry.registerService(DelphiServiceDefinition{
		Name:          "delphi-emailer",
		WorkerScript:  "/usr/local/bin/delphi-emailer.py",
		ServiceFile:   "/etc/systemd/system/delphi-emailer.service",
		SourceWorker:  "/opt/eos/assets/python_workers/delphi-emailer.py",
		SourceService: "/opt/eos/assets/services/delphi-emailer.service",
		Description:   "Legacy email service - DEPRECATED: Use email-structurer, email-formatter, email-sender instead",
		PipelineStage: "deprecated",
		Dependencies:  []string{"python3", "psycopg2", "python-dotenv"},
		User:          "stanley",
		Group:         "stanley",
		Permissions:   "0750",
		Deprecated:    true,
		ReplacedBy:    "email-structurer + email-formatter + email-sender",
		Categories:    []ServiceCategory{CategoryDeprecated},
	})
	
	return registry
}

// registerService adds a service to the registry
func (r *DelphiServiceRegistry) registerService(service DelphiServiceDefinition) {
	r.services[service.Name] = service
}

// GetService retrieves a service by name
func (r *DelphiServiceRegistry) GetService(name string) (DelphiServiceDefinition, bool) {
	service, exists := r.services[name]
	return service, exists
}

// GetAllServices returns all services
func (r *DelphiServiceRegistry) GetAllServices() map[string]DelphiServiceDefinition {
	return r.services
}

// GetActiveServices returns non-deprecated services
func (r *DelphiServiceRegistry) GetActiveServices() map[string]DelphiServiceDefinition {
	active := make(map[string]DelphiServiceDefinition)
	for name, service := range r.services {
		if !service.Deprecated {
			active[name] = service
		}
	}
	return active
}

// GetServiceNames returns a list of all service names
func (r *DelphiServiceRegistry) GetServiceNames() []string {
	var names []string
	for name := range r.services {
		names = append(names, name)
	}
	return names
}

// GetActiveServiceNames returns names of non-deprecated services only
func (r *DelphiServiceRegistry) GetActiveServiceNames() []string {
	var names []string
	for name, service := range r.services {
		if !service.Deprecated {
			names = append(names, name)
		}
	}
	return names
}

// CheckServiceInstallationStatus checks the installation status of a service
func (r *DelphiServiceRegistry) CheckServiceInstallationStatus(serviceName string) (ServiceInstallationStatus, error) {
	service, exists := r.GetService(serviceName)
	if !exists {
		return ServiceInstallationStatus{}, fmt.Errorf("service %s not found in registry", serviceName)
	}
	
	status := ServiceInstallationStatus{
		ServiceName:       serviceName,
		WorkerPath:        service.WorkerScript,
		ServicePath:       service.ServiceFile,
		SourceWorkerPath:  service.SourceWorker,
		SourceServicePath: service.SourceService,
	}
	
	// Check if worker file exists
	if _, err := os.Stat(service.WorkerScript); err == nil {
		status.WorkerInstalled = true
	}
	
	// Check if service file exists
	if _, err := os.Stat(service.ServiceFile); err == nil {
		status.ServiceInstalled = true
	}
	
	// Check if service is enabled and active (would require systemctl calls)
	// This is handled by eos_unix.ServiceExists and eos_unix.CheckServiceStatus
	
	return status, nil
}

// GetServicesRequiringInstallation returns services that need installation
func (r *DelphiServiceRegistry) GetServicesRequiringInstallation() ([]string, error) {
	var needingInstallation []string
	
	for serviceName := range r.GetActiveServices() {
		status, err := r.CheckServiceInstallationStatus(serviceName)
		if err != nil {
			continue
		}
		
		if !status.WorkerInstalled || !status.ServiceInstalled {
			needingInstallation = append(needingInstallation, serviceName)
		}
	}
	
	return needingInstallation, nil
}

// ValidateService checks if a service name is valid and provides helpful feedback
func (r *DelphiServiceRegistry) ValidateService(name string) error {
	if service, exists := r.services[name]; exists {
		if service.Deprecated {
			replacement := service.ReplacedBy
			if replacement == "" {
				replacement = "newer modular services"
			}
			return fmt.Errorf("service %s is deprecated and replaced by %s", name, replacement)
		}
		return nil
	}
	
	var suggestions []string
	for serviceName := range r.services {
		if strings.Contains(serviceName, name) || strings.Contains(name, serviceName) {
			suggestions = append(suggestions, serviceName)
		}
	}
	
	if len(suggestions) > 0 {
		return fmt.Errorf("service %s not found. Did you mean: %s", name, strings.Join(suggestions, ", "))
	}
	
	return fmt.Errorf("service %s not found. Use 'eos delphi services list' to see available services", name)
}

// GetPipelineOrder returns services in pipeline execution order
func (r *DelphiServiceRegistry) GetPipelineOrder() []string {
	stageOrder := []string{"ingestion", "enrichment", "processing", "analysis", "formatting", "delivery"}
	var orderedServices []string
	
	for _, stage := range stageOrder {
		for name, service := range r.services {
			if service.PipelineStage == stage && !service.Deprecated {
				orderedServices = append(orderedServices, name)
			}
		}
	}
	
	return orderedServices
}

// GetMissingServices returns services that exist in python_workers but not deployed
func (r *DelphiServiceRegistry) GetMissingServices(pythonWorkersPath string) ([]string, error) {
	var missing []string
	
	files, err := filepath.Glob(filepath.Join(pythonWorkersPath, "*.py"))
	if err != nil {
		return nil, fmt.Errorf("failed to read python workers directory: %w", err)
	}
	
	for _, file := range files {
		workerName := strings.TrimSuffix(filepath.Base(file), ".py")
		// Skip test files
		if strings.HasPrefix(workerName, "test_") {
			continue
		}
		
		if _, exists := r.GetService(workerName); !exists {
			missing = append(missing, workerName)
		}
	}
	
	return missing, nil
}

// Global registry instance
var globalDelphiServiceRegistry = GetDelphiServiceRegistry()

// GetGlobalDelphiServiceRegistry returns the global service registry
func GetGlobalDelphiServiceRegistry() *DelphiServiceRegistry {
	return globalDelphiServiceRegistry
}