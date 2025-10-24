package sizing

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HecateDeploymentProfile represents common Hecate deployment scenarios
type HecateDeploymentProfile struct {
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	Components         []string                  `json:"components"`
	WorkloadType       WorkloadType              `json:"workload_type"`
	Environment        string                    `json:"environment"`
	ExpectedUsers      int                       `json:"expected_users"`
	ExpectedRPS        int                       `json:"expected_rps"`
	ExpectedDataGrowth float64                   `json:"expected_data_growth_gb"`
	CustomFactors      map[string]ScalingFactors `json:"custom_factors,omitempty"`
}

// Predefined Hecate deployment profiles
var HecateProfiles = map[string]HecateDeploymentProfile{
	"development": {
		Name:        "Hecate Development",
		Description: "Development environment for testing and development work",
		Components: []string{
			"ubuntu_server_24.04",
			"caddy_reverse_proxy",
			"authentik_sso", // Includes PostgreSQL + Redis dependencies
		},
		WorkloadType:       WorkloadDevelopment,
		Environment:        "development",
		ExpectedUsers:      10,
		ExpectedRPS:        5,
		ExpectedDataGrowth: 1.0,
	},
	"small_production": {
		Name:        "Hecate Small Production",
		Description: "Small production deployment for teams up to 50 users",
		Components: []string{
			"ubuntu_server_24.04",
			"caddy_reverse_proxy",
			"authentik_sso", // Includes PostgreSQL + Redis dependencies
		},
		WorkloadType:       WorkloadSmall,
		Environment:        "production",
		ExpectedUsers:      50,
		ExpectedRPS:        25,
		ExpectedDataGrowth: 10.0,
	},
	"medium_production": {
		Name:        "Hecate Medium Production",
		Description: "Medium production deployment for teams up to 200 users",
		Components: []string{
			"ubuntu_server_24.04",
			"caddy_reverse_proxy",
			"authentik_sso", // Includes PostgreSQL + Redis dependencies
		},
		WorkloadType:       WorkloadMedium,
		Environment:        "production",
		ExpectedUsers:      200,
		ExpectedRPS:        100,
		ExpectedDataGrowth: 50.0,
	},
	"large_production": {
		Name:        "Hecate Large Production",
		Description: "Large production deployment for organizations with 500+ users",
		Components: []string{
			"ubuntu_server_24.04",
			"caddy_reverse_proxy",
			"authentik_sso", // Includes PostgreSQL + Redis dependencies
			"consul_cluster",
			"vault_cluster",
		},
		WorkloadType:       WorkloadLarge,
		Environment:        "production",
		ExpectedUsers:      500,
		ExpectedRPS:        250,
		ExpectedDataGrowth: 200.0,
		CustomFactors: map[string]ScalingFactors{
			"authentik_sso": {
				UserScaling:    0.015, // Higher scaling for large deployments
				RequestScaling: 0.002,
				DataScaling:    1.0,
				LoadMultiplier: 2.5, // Higher load multiplier for production
				SafetyMargin:   1.8, // Higher safety margin
			},
		},
	},
}

// CalculateHecateRequirements performs systematic calculation for Hecate deployments
func CalculateHecateRequirements(rc *eos_io.RuntimeContext, profileName string) (*CalculationBreakdown, error) {
	logger := otelzap.Ctx(rc.Ctx)

	profile, exists := HecateProfiles[profileName]
	if !exists {
		return nil, fmt.Errorf("Hecate profile %s not found", profileName)
	}

	logger.Info("Calculating Hecate requirements",
		zap.String("profile", profileName),
		zap.String("description", profile.Description),
		zap.Int("expected_users", profile.ExpectedUsers),
		zap.String("environment", profile.Environment))

	// Create calculator
	calc := NewCalculatorV2(profile.WorkloadType, profile.Environment)

	// Add components
	for _, component := range profile.Components {
		if err := calc.AddComponent(component); err != nil {
			return nil, fmt.Errorf("failed to add component %s: %w", component, err)
		}
	}

	// Apply custom scaling factors if provided
	for component, factors := range profile.CustomFactors {
		calc.SetCustomScalingFactors(component, factors)
		logger.Debug("Applied custom scaling factors",
			zap.String("component", component),
			zap.Float64("safety_margin", factors.SafetyMargin))
	}

	// Create workload characteristics
	workload := WorkloadCharacteristics{
		ConcurrentUsers:   profile.ExpectedUsers,
		RequestsPerSecond: profile.ExpectedRPS,
		DataGrowthGB:      profile.ExpectedDataGrowth,
		PeakMultiplier:    getPeakMultiplierForWorkload(profile.WorkloadType),
		Type:              profile.WorkloadType,
	}

	// Perform calculation
	result, err := calc.Calculate(rc, workload)
	if err != nil {
		return nil, fmt.Errorf("calculation failed: %w", err)
	}

	logger.Info("Hecate requirements calculation completed",
		zap.String("profile", profileName),
		zap.Float64("total_cpu_cores", result.FinalRequirements.CPU),
		zap.Float64("total_memory_gb", result.FinalRequirements.Memory),
		zap.Float64("total_storage_gb", result.FinalRequirements.Storage),
		zap.Int("recommended_nodes", result.NodeRecommendation.RecommendedNodes),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// ValidateHecateRequirements validates that current system meets Hecate requirements
func ValidateHecateRequirements(rc *eos_io.RuntimeContext, profileName string, currentSpecs NodeSpecification) ([]ValidationError, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Calculate required specifications
	breakdown, err := CalculateHecateRequirements(rc, profileName)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate requirements: %w", err)
	}

	var errors []ValidationError
	required := breakdown.NodeRecommendation.NodeSpecs
	recommendedNodes := breakdown.NodeRecommendation.RecommendedNodes

	// Validate CPU
	totalRequiredCPU := float64(required.CPUCores * recommendedNodes)
	totalAvailableCPU := float64(currentSpecs.CPUCores)

	if totalAvailableCPU < totalRequiredCPU {
		errors = append(errors, ValidationError{
			Field: "cpu_cores",
			Message: fmt.Sprintf("Insufficient CPU: have %.0f cores, need %.0f cores (%.0f cores × %d nodes)",
				totalAvailableCPU, totalRequiredCPU, float64(required.CPUCores), recommendedNodes),
		})
	}

	// Validate Memory
	totalRequiredMemory := float64(required.MemoryGB * recommendedNodes)
	totalAvailableMemory := float64(currentSpecs.MemoryGB)

	if totalAvailableMemory < totalRequiredMemory {
		errors = append(errors, ValidationError{
			Field: "memory_gb",
			Message: fmt.Sprintf("Insufficient memory: have %.0f GB, need %.0f GB (%.0f GB × %d nodes)",
				totalAvailableMemory, totalRequiredMemory, float64(required.MemoryGB), recommendedNodes),
		})
	}

	// Validate Storage
	totalRequiredStorage := float64(required.DiskGB * recommendedNodes)
	totalAvailableStorage := float64(currentSpecs.DiskGB)

	if totalAvailableStorage < totalRequiredStorage {
		errors = append(errors, ValidationError{
			Field: "disk_gb",
			Message: fmt.Sprintf("Insufficient storage: have %.0f GB, need %.0f GB (%.0f GB × %d nodes)",
				totalAvailableStorage, totalRequiredStorage, float64(required.DiskGB), recommendedNodes),
		})
	}

	// Validate storage type
	if currentSpecs.DiskType != "ssd" && currentSpecs.DiskType != "nvme" {
		errors = append(errors, ValidationError{
			Field:   "disk_type",
			Message: "SSD or NVMe storage required for Hecate production deployment",
		})
	}

	// Log validation results
	if len(errors) > 0 {
		logger.Warn("Hecate requirements validation failed",
			zap.String("profile", profileName),
			zap.Int("validation_errors", len(errors)))
		for _, err := range errors {
			logger.Warn("Validation error",
				zap.String("field", err.Field),
				zap.String("message", err.Message))
		}
	} else {
		logger.Info("Hecate requirements validation passed",
			zap.String("profile", profileName),
			zap.Float64("available_cpu", totalAvailableCPU),
			zap.Float64("required_cpu", totalRequiredCPU),
			zap.Float64("available_memory", totalAvailableMemory),
			zap.Float64("required_memory", totalRequiredMemory))
	}

	return errors, nil
}

// GetHecateProfileNames returns all available Hecate profile names
func GetHecateProfileNames() []string {
	names := make([]string, 0, len(HecateProfiles))
	for name := range HecateProfiles {
		names = append(names, name)
	}
	return names
}

// GetHecateProfile returns a specific Hecate profile
func GetHecateProfile(name string) (HecateDeploymentProfile, bool) {
	profile, exists := HecateProfiles[name]
	return profile, exists
}

// GenerateHecateRecommendationReport creates a human-readable report for Hecate deployment
func GenerateHecateRecommendationReport(rc *eos_io.RuntimeContext, profileName string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	breakdown, err := CalculateHecateRequirements(rc, profileName)
	if err != nil {
		return "", fmt.Errorf("failed to calculate requirements: %w", err)
	}

	profile := HecateProfiles[profileName]
	calc := &CalculatorV2{
		workloadType: profile.WorkloadType,
		environment:  profile.Environment,
		calculation:  breakdown,
	}

	report := "=== HECATE DEPLOYMENT RECOMMENDATION ===\n\n"
	report += fmt.Sprintf("Profile: %s\n", profile.Name)
	report += fmt.Sprintf("Description: %s\n", profile.Description)
	report += fmt.Sprintf("Target Users: %d\n", profile.ExpectedUsers)
	report += fmt.Sprintf("Target RPS: %d\n", profile.ExpectedRPS)
	report += fmt.Sprintf("Environment: %s\n\n", profile.Environment)

	report += calc.GenerateHumanReadableReport()

	// Add Hecate-specific recommendations
	report += "\n=== HECATE-SPECIFIC RECOMMENDATIONS ===\n\n"

	if profile.Environment == "production" {
		report += "PRODUCTION DEPLOYMENT:\n"
		report += "• Use TLS/SSL for all connections\n"
		report += "• Configure regular database backups\n"
		report += "• Set up monitoring for all services\n"
		report += "• Implement log aggregation\n"
		report += "• Configure firewall rules\n"
		report += "• Use secrets management (Vault if included)\n\n"
	}

	report += "AUTHENTIK SSO CONSIDERATIONS:\n"
	report += "• Configure OIDC/SAML providers as needed\n"
	report += "• Set up user directory integration (LDAP/AD)\n"
	report += "• Configure session timeout policies\n"
	report += "• Enable audit logging\n\n"

	report += "DATABASE OPTIMIZATION:\n"
	report += "• Configure PostgreSQL connection pooling\n"
	report += "• Set appropriate shared_buffers (25% of RAM)\n"
	report += "• Enable query logging for troubleshooting\n"
	report += "• Set up automated vacuum and analyze\n\n"

	logger.Info("Generated Hecate recommendation report",
		zap.String("profile", profileName),
		zap.Int("report_length", len(report)))

	return report, nil
}

// Helper function to get peak multiplier based on workload type
func getPeakMultiplierForWorkload(workloadType WorkloadType) float64 {
	switch workloadType {
	case WorkloadDevelopment:
		return 1.5 // Development has lower peak variation
	case WorkloadSmall:
		return 2.0 // Small workloads can have higher peaks
	case WorkloadMedium:
		return 2.5 // Medium workloads need buffer for growth
	case WorkloadLarge:
		return 3.0 // Large workloads need significant peak handling
	case WorkloadProduction:
		return 2.5 // General production peak handling
	default:
		return 2.0 // Default peak multiplier
	}
}

// CreateCustomHecateProfile creates a custom Hecate profile
func CreateCustomHecateProfile(name, description string, users, rps int, dataGrowth float64, environment string, workloadType WorkloadType) HecateDeploymentProfile {
	baseComponents := []string{
		"ubuntu_server_24.04",
		"caddy_reverse_proxy",
		"postgresql_16",
		"redis_7",
		"authentik_sso",
	}

	// Add HashiCorp stack for larger deployments
	if users > 100 {
		baseComponents = append(baseComponents, "consul_cluster", "vault_cluster")
	}

	// Add Nomad for very large deployments
	if users > 300 {
		baseComponents = append(baseComponents, "nomad_cluster")
	}

	return HecateDeploymentProfile{
		Name:               name,
		Description:        description,
		Components:         baseComponents,
		WorkloadType:       workloadType,
		Environment:        environment,
		ExpectedUsers:      users,
		ExpectedRPS:        rps,
		ExpectedDataGrowth: dataGrowth,
	}
}
