package strategy

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator"
	orchNomad "github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator/nomad"
	orchTerraform "github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator/terraform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployerFactory creates appropriate deployers based on strategy and environment
type DeployerFactory struct {
	rc              *eos_io.RuntimeContext
	logger          otelzap.LoggerWithCtx
	Client          orchestrator.Orchestrator
	terraformClient orchestrator.TerraformProvider
	nomadClient     orchestrator.NomadClient
}

// NewDeployerFactory creates a new deployer factory
func NewDeployerFactory(rc *eos_io.RuntimeContext) *DeployerFactory {
	return &DeployerFactory{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// CreateDeployer creates a deployer for the specified strategy
func (f *DeployerFactory) CreateDeployer(strategy DeploymentStrategy) (Deployer, error) {
	// Initialize clients based on strategy requirements
	if err := f.initializeClients(strategy); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}

	switch strategy {
	case DirectStrategy:
		return NewDirectDeployer(f.rc), nil

	case Strategy:
		if f.Client == nil {
			return nil, fmt.Errorf(" client required for  strategy")
		}
		return nil, fmt.Errorf(" strategy deprecated - use Nomad strategy for HashiCorp migration")

	case NomadStrategy:
		return nil, fmt.Errorf("+Nomad strategy not yet implemented")

	case FullStackStrategy:
		return nil, fmt.Errorf("Full stack strategy not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported deployment strategy: %s", strategy)
	}
}

// CreateDeployerForComponent creates the best deployer for a component
func (f *DeployerFactory) CreateDeployerForComponent(component *Component) (Deployer, error) {
	strategy := f.selectStrategy(component)

	f.logger.Info("Selected deployment strategy",
		zap.String("component", component.Name),
		zap.String("strategy", string(strategy)),
		zap.String("environment", component.Environment))

	return f.CreateDeployer(strategy)
}

// selectStrategy determines the best strategy for a component
func (f *DeployerFactory) selectStrategy(component *Component) DeploymentStrategy {
	// Check if strategy is explicitly set
	if component.Strategy != "" {
		return component.Strategy
	}

	// Check environment variables for global strategy override
	if envStrategy := os.Getenv("EOS_DEPLOYMENT_STRATEGY"); envStrategy != "" {
		switch DeploymentStrategy(envStrategy) {
		case DirectStrategy, Strategy, NomadStrategy, FullStackStrategy:
			return DeploymentStrategy(envStrategy)
		}
	}

	// Use default strategy selection based on component and environment
	return GetDefaultStrategy(component.Type, component.Environment)
}

// initializeClients initializes the required clients for a strategy
func (f *DeployerFactory) initializeClients(strategy DeploymentStrategy) error {
	capabilities := GetCapabilities(strategy)

	// Initialize  client if required
	if capabilities.Requires && f.Client == nil {
		f.logger.Debug(" client deprecated - migrating to HashiCorp stack")
		return fmt.Errorf(" client deprecated - use Nomad orchestration for HashiCorp migration")
	}

	// Initialize Terraform client if required
	if capabilities.RequiresTerraform && f.terraformClient == nil {
		f.logger.Debug("Initializing Terraform client")

		terraformConfig := orchTerraform.Config{
			WorkspaceDir: "/var/lib/eos/terraform",
			StateBackend: "consul",
			BackendConfig: map[string]string{
				"address": fmt.Sprintf("localhost:%d", shared.PortConsul),
				"path":    "terraform/state",
			},
			AutoApprove: false,
			Parallelism: 10,
		}

		client := orchTerraform.NewProvider(f.rc, terraformConfig)
		if err := f.validateTerraformClient(client); err != nil {
			return fmt.Errorf("Terraform client validation failed: %w", err)
		}
		f.terraformClient = client
	}

	// Initialize Nomad client if required
	if capabilities.RequiresNomad && f.nomadClient == nil {
		f.logger.Debug("Initializing Nomad client")

		nomadConfig := orchNomad.Config{
			Address:   f.getNomadAddress(),
			Region:    "global",
			Namespace: "default",
			Timeout:   30,
		}

		client, err := orchNomad.NewClient(f.rc, nomadConfig)
		if err != nil {
			return fmt.Errorf("failed to create Nomad client: %w", err)
		}

		if err := f.validateNomadClient(client); err != nil {
			return fmt.Errorf("Nomad client validation failed: %w", err)
		}
		f.nomadClient = client
	}

	return nil
}

// getNomadAddress returns the Nomad server address
func (f *DeployerFactory) getNomadAddress() string {
	// Check environment variable first
	if addr := os.Getenv("NOMAD_ADDR"); addr != "" {
		return addr
	}

	// Default to localhost
	return "http://localhost:4646"
}

// validateClient validates the  client connection
func (f *DeployerFactory) validateClient(client orchestrator.Orchestrator) error {
	// TODO: implement proper  validation
	f.logger.Debug(" client validation passed")
	return nil
}

// validateTerraformClient validates the Terraform client
func (f *DeployerFactory) validateTerraformClient(client orchestrator.TerraformProvider) error {
	// Basic validation - TODO: implement proper validation
	f.logger.Debug("Terraform client validation passed")

	return nil
}

// validateNomadClient validates the Nomad client connection
func (f *DeployerFactory) validateNomadClient(client orchestrator.NomadClient) error {
	// TODO: implement proper Nomad validation
	f.logger.Debug("Nomad client validation passed")
	return nil
}

// DeploymentRecommendation provides strategy recommendations
type DeploymentRecommendation struct {
	RecommendedStrategy DeploymentStrategy `json:"recommended_strategy"`
	Reasoning           string             `json:"reasoning"`
	Alternatives        []StrategyOption   `json:"alternatives"`
	Warnings            []string           `json:"warnings"`
}

// StrategyOption represents an alternative deployment strategy
type StrategyOption struct {
	Strategy    DeploymentStrategy `json:"strategy"`
	Description string             `json:"description"`
	Pros        []string           `json:"pros"`
	Cons        []string           `json:"cons"`
}

// GetRecommendation provides deployment strategy recommendations
func (f *DeployerFactory) GetRecommendation(component *Component) *DeploymentRecommendation {
	recommendation := &DeploymentRecommendation{
		RecommendedStrategy: f.selectStrategy(component),
		Alternatives:        make([]StrategyOption, 0),
		Warnings:            make([]string, 0),
	}

	// Determine reasoning based on component and environment
	switch {
	case component.Environment == "dev" || component.Environment == "test":
		recommendation.Reasoning = "Development/test environment - direct deployment provides fastest iteration"
		recommendation.Alternatives = []StrategyOption{
			{
				Strategy:    Strategy,
				Description: "Use  for configuration management",
				Pros:        []string{"Better state management", "Reproducible deployments"},
				Cons:        []string{"Slower deployment", "Additional complexity"},
			},
		}

	case component.Type == InfrastructureType:
		recommendation.Reasoning = "Infrastructure component -  provides declarative configuration management"
		recommendation.Alternatives = []StrategyOption{
			{
				Strategy:    DirectStrategy,
				Description: "Direct deployment for simplicity",
				Pros:        []string{"Faster deployment", "Less dependencies"},
				Cons:        []string{"Limited rollback", "No state management"},
			},
			{
				Strategy:    FullStackStrategy,
				Description: "Full orchestration stack",
				Pros:        []string{"Complete automation", "Infrastructure as code"},
				Cons:        []string{"High complexity", "More failure points"},
			},
		}

	case component.Type == ServiceType:
		recommendation.Reasoning = "Service component - +Nomad provides container orchestration with configuration management"
		recommendation.Alternatives = []StrategyOption{
			{
				Strategy:    Strategy,
				Description: "-only deployment",
				Pros:        []string{"Simpler than full stack", "Good configuration management"},
				Cons:        []string{"No container orchestration", "Limited scaling"},
			},
			{
				Strategy:    FullStackStrategy,
				Description: "Full orchestration stack",
				Pros:        []string{"Complete automation", "Infrastructure as code"},
				Cons:        []string{"High complexity", "Overkill for simple services"},
			},
		}

	default:
		recommendation.Reasoning = "Default strategy based on component type and environment"
	}

	// Add warnings based on strategy capabilities
	capabilities := GetCapabilities(recommendation.RecommendedStrategy)
	if !capabilities.SupportsRollback {
		recommendation.Warnings = append(recommendation.Warnings,
			"Selected strategy has limited rollback capabilities")
	}

	if capabilities.Requires && !f.isHashiCorpClusterReady() {
		recommendation.Warnings = append(recommendation.Warnings,
			"HashiCorp cluster not ready - verify Consul/Nomad installation")
	}

	return recommendation
}

// ValidateStrategy validates if a strategy can be used
func (f *DeployerFactory) ValidateStrategy(strategy DeploymentStrategy) error {
	capabilities := GetCapabilities(strategy)

	if capabilities.Requires {
		if err := f.validateAvailability(); err != nil {
			return fmt.Errorf(" not available: %w", err)
		}
	}

	if capabilities.RequiresTerraform {
		if err := f.validateTerraformAvailability(); err != nil {
			return fmt.Errorf("Terraform not available: %w", err)
		}
	}

	if capabilities.RequiresNomad {
		if err := f.validateNomadAvailability(); err != nil {
			return fmt.Errorf("Nomad not available: %w", err)
		}
	}

	return nil
}

// validateAvailability checks if  is available
func (f *DeployerFactory) validateAvailability() error {
	// Check if -call binary exists
	if _, err := os.Stat("/usr/bin/-call"); os.IsNotExist(err) {
		return fmt.Errorf("-call binary not found")
	}

	// Check if  configuration exists
	if _, err := os.Stat("/etc//minion"); os.IsNotExist(err) {
		return fmt.Errorf(" minion configuration not found")
	}

	return nil
}

// validateTerraformAvailability checks if Terraform is available
func (f *DeployerFactory) validateTerraformAvailability() error {
	// Check if terraform binary exists
	if _, err := os.Stat("/usr/bin/terraform"); os.IsNotExist(err) {
		return fmt.Errorf("terraform binary not found")
	}

	return nil
}

// validateNomadAvailability checks if Nomad is available
func (f *DeployerFactory) validateNomadAvailability() error {
	// Check if nomad binary exists
	if _, err := os.Stat("/usr/bin/nomad"); os.IsNotExist(err) {
		return fmt.Errorf("nomad binary not found")
	}

	return nil
}

// GetAvailableStrategies returns all available deployment strategies
func (f *DeployerFactory) GetAvailableStrategies() []DeploymentStrategy {
	strategies := []DeploymentStrategy{DirectStrategy}

	if f.validateAvailability() == nil {
		strategies = append(strategies, Strategy)

		if f.validateNomadAvailability() == nil {
			strategies = append(strategies, NomadStrategy)

			if f.validateTerraformAvailability() == nil {
				strategies = append(strategies, FullStackStrategy)
			}
		}
	}

	return strategies
}

// DeploymentPlanRequest represents a request for deployment planning
type DeploymentPlanRequest struct {
	Components   []Component         `json:"components"`
	Environment  string              `json:"environment"`
	Strategy     *DeploymentStrategy `json:"strategy,omitempty"`
	Dependencies map[string][]string `json:"dependencies,omitempty"`
}

// CreateDeploymentPlan creates a deployment plan for multiple components
func (f *DeployerFactory) CreateDeploymentPlan(request *DeploymentPlanRequest) (*DeploymentPlan, error) {
	plan := &DeploymentPlan{
		ID:           fmt.Sprintf("plan-%d", time.Now().Unix()),
		Components:   request.Components,
		Dependencies: request.Dependencies,
		Order:        make([]string, 0),
	}

	// Determine strategy for the plan
	if request.Strategy != nil {
		plan.Strategy = *request.Strategy
	} else {
		// Use the most appropriate strategy for the component mix
		plan.Strategy = f.selectPlanStrategy(request.Components, request.Environment)
	}

	// Calculate deployment order based on dependencies
	order, err := f.calculateDeploymentOrder(request.Components, request.Dependencies)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate deployment order: %w", err)
	}
	plan.Order = order

	// Validate the plan
	if err := f.validateDeploymentPlan(plan); err != nil {
		return nil, fmt.Errorf("deployment plan validation failed: %w", err)
	}

	return plan, nil
}

// selectPlanStrategy selects the best strategy for a multi-component plan
func (f *DeployerFactory) selectPlanStrategy(components []Component, environment string) DeploymentStrategy {
	// If all components are infrastructure, use full stack
	allInfrastructure := true
	hasServices := false

	for _, component := range components {
		if component.Type != InfrastructureType {
			allInfrastructure = false
		}
		if component.Type == ServiceType {
			hasServices = true
		}
	}

	// Production environment with mixed components
	if environment == "prod" || environment == "production" {
		if allInfrastructure {
			return FullStackStrategy
		}
		if hasServices {
			return NomadStrategy
		}
		return Strategy
	}

	// Development/test environments
	if environment == "dev" || environment == "test" {
		return DirectStrategy
	}

	// Default to  strategy
	return Strategy
}

// calculateDeploymentOrder calculates the order of deployment based on dependencies
func (f *DeployerFactory) calculateDeploymentOrder(components []Component, dependencies map[string][]string) ([]string, error) {
	// Simple topological sort implementation
	order := make([]string, 0)
	visited := make(map[string]bool)
	inProgress := make(map[string]bool)

	var visit func(string) error
	visit = func(component string) error {
		if inProgress[component] {
			return fmt.Errorf("circular dependency detected for component: %s", component)
		}
		if visited[component] {
			return nil
		}

		inProgress[component] = true

		// Visit dependencies first
		if deps, exists := dependencies[component]; exists {
			for _, dep := range deps {
				if err := visit(dep); err != nil {
					return err
				}
			}
		}

		inProgress[component] = false
		visited[component] = true
		order = append(order, component)

		return nil
	}

	// Visit all components
	for _, component := range components {
		if err := visit(component.Name); err != nil {
			return nil, err
		}
	}

	return order, nil
}

// validateDeploymentPlan validates a deployment plan
func (f *DeployerFactory) validateDeploymentPlan(plan *DeploymentPlan) error {
	// Validate strategy is available
	if err := f.ValidateStrategy(plan.Strategy); err != nil {
		return fmt.Errorf("strategy validation failed: %w", err)
	}

	// Validate all components in the plan
	for _, component := range plan.Components {
		if err := f.validateComponentForStrategy(&component, plan.Strategy); err != nil {
			return fmt.Errorf("component %s validation failed: %w", component.Name, err)
		}
	}

	// Validate deployment order
	if len(plan.Order) != len(plan.Components) {
		return fmt.Errorf("deployment order length mismatch")
	}

	return nil
}

// validateComponentForStrategy validates a component for a specific strategy
func (f *DeployerFactory) validateComponentForStrategy(component *Component, strategy DeploymentStrategy) error {
	// Create a temporary deployer to validate
	deployer, err := f.CreateDeployer(strategy)
	if err != nil {
		return err
	}

	// Set the component strategy
	component.Strategy = strategy

	// Validate the component
	return deployer.Validate(context.Background(), component)
}

// GetStrategyCapabilities returns capabilities for all strategies
func (f *DeployerFactory) GetStrategyCapabilities() map[DeploymentStrategy]StrategyCapabilities {
	return map[DeploymentStrategy]StrategyCapabilities{
		DirectStrategy:    GetCapabilities(DirectStrategy),
		Strategy:          GetCapabilities(Strategy),
		NomadStrategy:     GetCapabilities(NomadStrategy),
		FullStackStrategy: GetCapabilities(FullStackStrategy),
	}
}

// isHashiCorpClusterReady checks if HashiCorp cluster (Consul/Nomad) is ready
func (f *DeployerFactory) isHashiCorpClusterReady() bool {
	// TODO: Implement actual HashiCorp cluster health checks
	// This should check:
	// - Consul cluster health
	// - Nomad cluster health
	// - Vault availability

	f.logger.Debug("Checking HashiCorp cluster readiness")

	// For now, assume cluster is ready if we have clients configured
	// In a real implementation, this would make actual health check calls
	return f.nomadClient != nil && f.Client != nil
}
