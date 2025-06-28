// cmd/delphi/services/service_registry.go
package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServiceMetadata represents comprehensive service information
type ServiceMetadata struct {
	Name            string            `json:"name"`
	WorkerScript    string            `json:"worker_script"`
	ServiceFile     string            `json:"service_file"`
	Description     string            `json:"description"`
	PipelineStage   string            `json:"pipeline_stage"`
	Dependencies    []string          `json:"dependencies"`
	ConfigFiles     []ConfigFile      `json:"config_files"`
	EnvironmentVars []string          `json:"environment_vars"`
	Ports           []int             `json:"ports,omitempty"`
	User            string            `json:"user"`
	Group           string            `json:"group"`
	Permissions     string            `json:"permissions"`
	Status          ServiceState      `json:"status,omitempty"`
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

// ServiceState represents current service state (renamed to avoid conflict)
type ServiceState struct {
	Active      string `json:"active"`       // active, inactive, failed
	Enabled     string `json:"enabled"`      // enabled, disabled  
	Installed   bool   `json:"installed"`    // worker and service files exist
	Healthy     bool   `json:"healthy"`      // passing health checks
	LastChecked string `json:"last_checked"` // timestamp of last status check
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

// ServiceRegistry provides a single source of truth for all Delphi services
type ServiceRegistry struct {
	services map[string]ServiceMetadata
}

// NewServiceRegistry creates a registry with all known Delphi services
func NewServiceRegistry() *ServiceRegistry {
	registry := &ServiceRegistry{
		services: make(map[string]ServiceMetadata),
	}
	
	// Core pipeline services - aligned with assets/python_workers/*
	registry.registerService(ServiceMetadata{
		Name:          "delphi-listener",
		WorkerScript:  "/usr/local/bin/delphi-listener.py",
		ServiceFile:   "/etc/systemd/system/delphi-listener.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "delphi-agent-enricher",
		WorkerScript:  "/usr/local/bin/delphi-agent-enricher.py",
		ServiceFile:   "/etc/systemd/system/delphi-agent-enricher.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "alert-to-db",
		WorkerScript:  "/usr/local/bin/alert-to-db.py",
		ServiceFile:   "/etc/systemd/system/alert-to-db.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "prompt-ab-tester",
		WorkerScript:  "/usr/local/bin/prompt-ab-tester.py",
		ServiceFile:   "/etc/systemd/system/prompt-ab-tester.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "llm-worker",
		WorkerScript:  "/usr/local/bin/llm-worker.py",
		ServiceFile:   "/etc/systemd/system/llm-worker.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "ab-test-analyzer",
		WorkerScript:  "/usr/local/bin/ab-test-analyzer.py",
		ServiceFile:   "/etc/systemd/system/ab-test-analyzer.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "email-structurer",
		WorkerScript:  "/usr/local/bin/email-structurer.py",
		ServiceFile:   "/etc/systemd/system/email-structurer.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "email-formatter",
		WorkerScript:  "/usr/local/bin/email-formatter.py",
		ServiceFile:   "/etc/systemd/system/email-formatter.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "email-sender",
		WorkerScript:  "/usr/local/bin/email-sender.py",
		ServiceFile:   "/etc/systemd/system/email-sender.service",
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
	
	registry.registerService(ServiceMetadata{
		Name:          "parser-monitor",
		WorkerScript:  "/usr/local/bin/parser-monitor.py",
		ServiceFile:   "/etc/systemd/system/parser-monitor.service",
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
	registry.registerService(ServiceMetadata{
		Name:          "delphi-emailer",
		WorkerScript:  "/usr/local/bin/delphi-emailer.py",
		ServiceFile:   "/etc/systemd/system/delphi-emailer.service",
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
func (r *ServiceRegistry) registerService(service ServiceMetadata) {
	r.services[service.Name] = service
}

// GetService retrieves a service by name
func (r *ServiceRegistry) GetService(name string) (ServiceMetadata, bool) {
	service, exists := r.services[name]
	return service, exists
}

// GetAllServices returns all services
func (r *ServiceRegistry) GetAllServices() map[string]ServiceMetadata {
	return r.services
}

// GetActiveServices returns non-deprecated services
func (r *ServiceRegistry) GetActiveServices() map[string]ServiceMetadata {
	active := make(map[string]ServiceMetadata)
	for name, service := range r.services {
		if !service.Deprecated {
			active[name] = service
		}
	}
	return active
}

// GetServicesByCategory returns services in a specific category
func (r *ServiceRegistry) GetServicesByCategory(category ServiceCategory) map[string]ServiceMetadata {
	filtered := make(map[string]ServiceMetadata)
	for name, service := range r.services {
		for _, cat := range service.Categories {
			if cat == category {
				filtered[name] = service
				break
			}
		}
	}
	return filtered
}

// GetServiceNames returns a list of all service names (for command validation)
func (r *ServiceRegistry) GetServiceNames() []string {
	var names []string
	for name := range r.services {
		names = append(names, name)
	}
	return names
}

// GetActiveServiceNames returns names of non-deprecated services only
func (r *ServiceRegistry) GetActiveServiceNames() []string {
	var names []string
	for name, service := range r.services {
		if !service.Deprecated {
			names = append(names, name)
		}
	}
	return names
}

// ValidateService checks if a service name is valid and provides helpful feedback
func (r *ServiceRegistry) ValidateService(name string) error {
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
func (r *ServiceRegistry) GetPipelineOrder() []string {
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

// CheckServiceFilesExist checks if worker and service files exist for a service
func (r *ServiceRegistry) CheckServiceFilesExist(name string) (bool, bool, error) {
	service, exists := r.GetService(name)
	if !exists {
		return false, false, fmt.Errorf("service %s not found", name)
	}
	
	workerExists := false
	serviceExists := false
	
	if _, err := os.Stat(service.WorkerScript); err == nil {
		workerExists = true
	}
	
	if _, err := os.Stat(service.ServiceFile); err == nil {
		serviceExists = true
	}
	
	return workerExists, serviceExists, nil
}

// GetMissingServices returns services that exist in python_workers but not deployed
func (r *ServiceRegistry) GetMissingServices(pythonWorkersPath string) ([]string, error) {
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
var globalRegistry = NewServiceRegistry()

// GetGlobalRegistry returns the global service registry
func GetGlobalRegistry() *ServiceRegistry {
	return globalRegistry
}

// Legacy compatibility functions for existing code
func GetDelphiServicesFromRegistry() []string {
	return globalRegistry.GetActiveServiceNames()
}

func GetServiceConfigurationsFromRegistry() map[string]ServiceConfiguration {
	// Convert new ServiceMetadata to legacy ServiceConfiguration for backward compatibility
	configs := make(map[string]ServiceConfiguration)
	
	for name, meta := range globalRegistry.GetActiveServices() {
		var configPaths []string
		for _, cf := range meta.ConfigFiles {
			configPaths = append(configPaths, cf.Path)
		}
		
		configs[name] = ServiceConfiguration{
			Name:         meta.Name,
			ServiceFile:  meta.ServiceFile,
			WorkerFile:   meta.WorkerScript,
			Description:  meta.Description,
			Dependencies: meta.Dependencies,
			ConfigFiles:  configPaths,
		}
	}
	
	return configs
}

// Updated DelphiServices for backward compatibility - now sourced from registry
var DelphiServicesFromRegistry = GetDelphiServicesFromRegistry()