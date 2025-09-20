package sizing

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceProfileType represents different types of Eos service deployments
type ServiceProfileType string

const (
	ServiceProfileTypeHecate      ServiceProfileType = "hecate"
	ServiceProfileTypeVault       ServiceProfileType = "vault"
	ServiceProfileTypeConsul      ServiceProfileType = "consul"
	ServiceProfileTypeNomad       ServiceProfileType = "nomad"
	ServiceProfileTypeMinIO       ServiceProfileType = "minio"
	ServiceProfileTypeDatabase    ServiceProfileType = "database"
	ServiceProfileTypeMonitoring  ServiceProfileType = "monitoring"
)

// ServiceProfile represents a deployable Eos service with its components and requirements
type ServiceProfile struct {
	Name            string                    `json:"name"`
	Type            ServiceProfileType        `json:"type"`
	Description     string                    `json:"description"`
	Components      []string                  `json:"components"`
	Dependencies    []ServiceProfileType      `json:"dependencies,omitempty"`
	Variants        map[string]ServiceVariant `json:"variants"`
	DefaultVariant  string                    `json:"default_variant"`
	Documentation   string                    `json:"documentation,omitempty"`
}

// ServiceVariant represents different deployment sizes/configurations for a service
type ServiceVariant struct {
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	WorkloadType       WorkloadType              `json:"workload_type"`
	Environment        string                    `json:"environment"`
	ExpectedUsers      int                       `json:"expected_users"`
	ExpectedRPS        int                       `json:"expected_rps"`
	ExpectedDataGrowth float64                   `json:"expected_data_growth_gb"`
	CustomFactors      map[string]ScalingFactors `json:"custom_factors,omitempty"`
	Notes              string                    `json:"notes,omitempty"`
}

// ServiceProfileRegistry contains all registered service profiles
var ServiceProfileRegistry = map[ServiceProfileType]ServiceProfile{
	ServiceProfileTypeHecate: {
		Name:        "Hecate Reverse Proxy & SSO",
		Type:        ServiceProfileTypeHecate,
		Description: "Complete reverse proxy solution with Authentik SSO, PostgreSQL, and Redis",
		Components: []string{
			"ubuntu_server_24.04",
			"caddy_reverse_proxy",
			"postgresql_16",
			"redis_7",
			"authentik_sso",
		},
		Variants: map[string]ServiceVariant{
			"development": {
				Name:               "Development",
				Description:        "Single-node development environment",
				WorkloadType:       WorkloadDevelopment,
				Environment:        "development",
				ExpectedUsers:      10,
				ExpectedRPS:        5,
				ExpectedDataGrowth: 1.0,
			},
			"small": {
				Name:               "Small Production",
				Description:        "Small production deployment (up to 50 users)",
				WorkloadType:       WorkloadSmall,
				Environment:        "production",
				ExpectedUsers:      50,
				ExpectedRPS:        25,
				ExpectedDataGrowth: 10.0,
			},
			"medium": {
				Name:               "Medium Production",
				Description:        "Medium production deployment (up to 200 users)",
				WorkloadType:       WorkloadMedium,
				Environment:        "production",
				ExpectedUsers:      200,
				ExpectedRPS:        100,
				ExpectedDataGrowth: 50.0,
			},
			"large": {
				Name:               "Large Production",
				Description:        "Large production deployment (500+ users)",
				WorkloadType:       WorkloadLarge,
				Environment:        "production",
				ExpectedUsers:      500,
				ExpectedRPS:        250,
				ExpectedDataGrowth: 200.0,
			},
		},
		DefaultVariant: "small",
		Documentation:  "Hecate provides reverse proxy and SSO capabilities for secure service access",
	},

	ServiceProfileTypeVault: {
		Name:        "HashiCorp Vault Cluster",
		Type:        ServiceProfileTypeVault,
		Description: "HashiCorp Vault secrets management with integrated storage",
		Components: []string{
			"ubuntu_server_24.04",
			"vault_cluster",
		},
		Variants: map[string]ServiceVariant{
			"development": {
				Name:               "Development",
				Description:        "Single-node Vault for development",
				WorkloadType:       WorkloadDevelopment,
				Environment:        "development",
				ExpectedUsers:      5,
				ExpectedRPS:        1,
				ExpectedDataGrowth: 0.1,
			},
			"production": {
				Name:               "Production HA",
				Description:        "High-availability Vault cluster",
				WorkloadType:       WorkloadProduction,
				Environment:        "production",
				ExpectedUsers:      100,
				ExpectedRPS:        10,
				ExpectedDataGrowth: 5.0,
				CustomFactors: map[string]ScalingFactors{
					"vault_cluster": {
						SafetyMargin: 2.0, // Higher safety margin for secrets
					},
				},
			},
		},
		DefaultVariant: "production",
		Documentation:  "Vault provides centralized secrets management and cryptographic services",
	},

	ServiceProfileTypeConsul: {
		Name:        "HashiCorp Consul Cluster",
		Type:        ServiceProfileTypeConsul,
		Description: "HashiCorp Consul service discovery and configuration",
		Components: []string{
			"ubuntu_server_24.04",
			"consul_cluster",
		},
		Variants: map[string]ServiceVariant{
			"small": {
				Name:               "Small Cluster",
				Description:        "3-node Consul cluster for small environments",
				WorkloadType:       WorkloadSmall,
				Environment:        "production",
				ExpectedUsers:      50,
				ExpectedRPS:        20,
				ExpectedDataGrowth: 1.0,
			},
			"medium": {
				Name:               "Medium Cluster",
				Description:        "5-node Consul cluster for medium environments",
				WorkloadType:       WorkloadMedium,
				Environment:        "production",
				ExpectedUsers:      200,
				ExpectedRPS:        100,
				ExpectedDataGrowth: 5.0,
			},
		},
		DefaultVariant: "small",
		Documentation:  "Consul provides service discovery, configuration, and segmentation",
	},

	ServiceProfileTypeNomad: {
		Name:        "HashiCorp Nomad Cluster",
		Type:        ServiceProfileTypeNomad,
		Description: "HashiCorp Nomad job scheduler and orchestrator",
		Components: []string{
			"ubuntu_server_24.04",
			"nomad_cluster",
		},
		Dependencies: []ServiceProfileType{ServiceProfileTypeConsul},
		Variants: map[string]ServiceVariant{
			"small": {
				Name:               "Small Cluster",
				Description:        "Small Nomad cluster for container orchestration",
				WorkloadType:       WorkloadSmall,
				Environment:        "production",
				ExpectedUsers:      20,
				ExpectedRPS:        10,
				ExpectedDataGrowth: 2.0,
			},
			"large": {
				Name:               "Large Cluster",
				Description:        "Large Nomad cluster for enterprise workloads",
				WorkloadType:       WorkloadLarge,
				Environment:        "production",
				ExpectedUsers:      200,
				ExpectedRPS:        100,
				ExpectedDataGrowth: 50.0,
			},
		},
		DefaultVariant: "small",
		Documentation:  "Nomad provides flexible job scheduling and container orchestration",
	},

	ServiceProfileTypeDatabase: {
		Name:        "PostgreSQL Database Cluster",
		Type:        ServiceProfileTypeDatabase,
		Description: "PostgreSQL database with replication and backup",
		Components: []string{
			"ubuntu_server_24.04",
			"postgresql_16",
		},
		Variants: map[string]ServiceVariant{
			"small": {
				Name:               "Small Database",
				Description:        "Single PostgreSQL instance for small applications",
				WorkloadType:       WorkloadSmall,
				Environment:        "production",
				ExpectedUsers:      50,
				ExpectedRPS:        25,
				ExpectedDataGrowth: 20.0,
			},
			"large": {
				Name:               "Large Database",
				Description:        "PostgreSQL with read replicas for high-load applications",
				WorkloadType:       WorkloadLarge,
				Environment:        "production",
				ExpectedUsers:      1000,
				ExpectedRPS:        500,
				ExpectedDataGrowth: 500.0,
				CustomFactors: map[string]ScalingFactors{
					"postgresql_16": {
						UserScaling:    0.02,
						RequestScaling: 0.005,
						LoadMultiplier: 3.0,
						SafetyMargin:   2.0,
					},
				},
			},
		},
		DefaultVariant: "small",
		Documentation:  "PostgreSQL provides reliable relational database services",
	},
}

// CalculateServiceRequirements calculates requirements for any registered service
func CalculateServiceRequirements(rc *eos_io.RuntimeContext, serviceType ServiceProfileType, variant string) (*CalculationBreakdown, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	profile, exists := ServiceProfileRegistry[serviceType]
	if !exists {
		return nil, fmt.Errorf("service profile %s not found", serviceType)
	}

	if variant == "" {
		variant = profile.DefaultVariant
	}

	serviceVariant, exists := profile.Variants[variant]
	if !exists {
		return nil, fmt.Errorf("variant %s not found for service %s", variant, serviceType)
	}

	logger.Info("Calculating service requirements",
		zap.String("service", string(serviceType)),
		zap.String("variant", variant),
		zap.String("description", serviceVariant.Description),
		zap.Int("expected_users", serviceVariant.ExpectedUsers))

	// Create calculator
	calc := NewCalculatorV2(serviceVariant.WorkloadType, serviceVariant.Environment)

	// Add components
	for _, component := range profile.Components {
		if err := calc.AddComponent(component); err != nil {
			return nil, fmt.Errorf("failed to add component %s: %w", component, err)
		}
	}

	// Apply custom scaling factors if provided
	for component, factors := range serviceVariant.CustomFactors {
		calc.SetCustomScalingFactors(component, factors)
		logger.Debug("Applied custom scaling factors",
			zap.String("component", component),
			zap.Float64("safety_margin", factors.SafetyMargin))
	}

	// Create workload characteristics
	workload := WorkloadCharacteristics{
		ConcurrentUsers:   serviceVariant.ExpectedUsers,
		RequestsPerSecond: serviceVariant.ExpectedRPS,
		DataGrowthGB:      serviceVariant.ExpectedDataGrowth,
		PeakMultiplier:    getPeakMultiplierForWorkload(serviceVariant.WorkloadType),
		Type:              serviceVariant.WorkloadType,
	}

	// Perform calculation
	result, err := calc.Calculate(rc, workload)
	if err != nil {
		return nil, fmt.Errorf("calculation failed: %w", err)
	}

	logger.Info("Service requirements calculation completed",
		zap.String("service", string(serviceType)),
		zap.String("variant", variant),
		zap.Float64("total_cpu_cores", result.FinalRequirements.CPU),
		zap.Float64("total_memory_gb", result.FinalRequirements.Memory),
		zap.Int("recommended_nodes", result.NodeRecommendation.RecommendedNodes))

	return result, nil
}

// GetServiceProfile returns a service profile by type
func GetServiceProfile(serviceType ServiceProfileType) (ServiceProfile, bool) {
	profile, exists := ServiceProfileRegistry[serviceType]
	return profile, exists
}

// GetAllServiceTypes returns all available service types
func GetAllServiceTypes() []ServiceProfileType {
	types := make([]ServiceProfileType, 0, len(ServiceProfileRegistry))
	for serviceType := range ServiceProfileRegistry {
		types = append(types, serviceType)
	}
	return types
}

// GetServiceVariants returns all variants for a service type
func GetServiceVariants(serviceType ServiceProfileType) (map[string]ServiceVariant, error) {
	profile, exists := ServiceProfileRegistry[serviceType]
	if !exists {
		return nil, fmt.Errorf("service profile %s not found", serviceType)
	}
	return profile.Variants, nil
}

// ValidateServiceDependencies checks if required dependencies are met
func ValidateServiceDependencies(serviceType ServiceProfileType, availableServices []ServiceProfileType) []ValidationError {
	var errors []ValidationError
	
	profile, exists := ServiceProfileRegistry[serviceType]
	if !exists {
		errors = append(errors, ValidationError{
			Field:   "service_type",
			Message: fmt.Sprintf("Service profile %s not found", serviceType),
		})
		return errors
	}

	// Check dependencies
	for _, dependency := range profile.Dependencies {
		found := false
		for _, available := range availableServices {
			if available == dependency {
				found = true
				break
			}
		}
		if !found {
			errors = append(errors, ValidationError{
				Field:   "dependencies",
				Message: fmt.Sprintf("Required dependency %s is not available", dependency),
			})
		}
	}

	return errors
}

// GenerateServiceReport creates a comprehensive report for a service deployment
func GenerateServiceReport(rc *eos_io.RuntimeContext, serviceType ServiceProfileType, variant string) (string, error) {
	breakdown, err := CalculateServiceRequirements(rc, serviceType, variant)
	if err != nil {
		return "", fmt.Errorf("failed to calculate requirements: %w", err)
	}

	profile, _ := ServiceProfileRegistry[serviceType]
	serviceVariant := profile.Variants[variant]

	calc := &CalculatorV2{
		workloadType: serviceVariant.WorkloadType,
		environment:  serviceVariant.Environment,
		calculation:  breakdown,
	}

	report := fmt.Sprintf("=== %s DEPLOYMENT RECOMMENDATION ===\n\n", profile.Name)
	report += fmt.Sprintf("Service: %s\n", profile.Name)
	report += fmt.Sprintf("Type: %s\n", serviceType)
	report += fmt.Sprintf("Variant: %s\n", variant)
	report += fmt.Sprintf("Description: %s\n", serviceVariant.Description)
	report += fmt.Sprintf("Target Users: %d\n", serviceVariant.ExpectedUsers)
	report += fmt.Sprintf("Target RPS: %d\n", serviceVariant.ExpectedRPS)
	report += fmt.Sprintf("Environment: %s\n\n", serviceVariant.Environment)

	if len(profile.Dependencies) > 0 {
		report += "DEPENDENCIES:\n"
		for _, dep := range profile.Dependencies {
			report += fmt.Sprintf("• %s\n", dep)
		}
		report += "\n"
	}

	report += calc.GenerateHumanReadableReport()

	if profile.Documentation != "" {
		report += "\n=== SERVICE INFORMATION ===\n\n"
		report += profile.Documentation + "\n"
	}

	if serviceVariant.Notes != "" {
		report += "\n=== VARIANT NOTES ===\n\n"
		report += serviceVariant.Notes + "\n"
	}

	return report, nil
}

// RegisterCustomServiceProfile allows adding new service profiles at runtime
func RegisterCustomServiceProfile(serviceType ServiceProfileType, profile ServiceProfile) {
	ServiceProfileRegistry[serviceType] = profile
}