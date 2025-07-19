package sizing

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExampleHecateCalculation demonstrates how to use the new systematic calculator for Hecate
func ExampleHecateCalculation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== HECATE DEPLOYMENT SIZING EXAMPLE ===")
	
	// Calculate requirements for different Hecate profiles
	profiles := []string{"development", "small_production", "medium_production", "large_production"}
	
	for _, profile := range profiles {
		logger.Info("Calculating requirements", zap.String("profile", profile))
		
		breakdown, err := CalculateHecateRequirements(rc, profile)
		if err != nil {
			logger.Error("Calculation failed", zap.String("profile", profile), zap.Error(err))
			continue
		}
		
		// Log summary
		final := breakdown.FinalRequirements
		nodes := breakdown.NodeRecommendation
		
		logger.Info("Requirements calculated",
			zap.String("profile", profile),
			zap.Float64("total_cpu_cores", final.CPU),
			zap.Float64("total_memory_gb", final.Memory),
			zap.Float64("total_storage_gb", final.Storage),
			zap.Int("recommended_nodes", nodes.RecommendedNodes),
			zap.Int("per_node_cpu", nodes.NodeSpecs.CPUCores),
			zap.Int("per_node_memory", nodes.NodeSpecs.MemoryGB),
			zap.Int("warnings", len(breakdown.Warnings)))
		
		// Log any warnings
		for _, warning := range breakdown.Warnings {
			logger.Warn("Deployment warning", zap.String("profile", profile), zap.String("warning", warning))
		}
		
		// Generate human-readable report
		report, err := GenerateHecateRecommendationReport(rc, profile)
		if err != nil {
			logger.Error("Failed to generate report", zap.String("profile", profile), zap.Error(err))
			continue
		}
		
		logger.Info("Generated recommendation report",
			zap.String("profile", profile),
			zap.Int("report_length", len(report)))
	}
	
	return nil
}

// ExampleCustomServiceCalculation demonstrates how to calculate requirements for custom services
func ExampleCustomServiceCalculation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== CUSTOM SERVICE SIZING EXAMPLE ===")
	
	// Example: Calculate requirements for a standalone Vault deployment
	logger.Info("Calculating Vault standalone deployment")
	
	breakdown, err := CalculateServiceRequirements(rc, ServiceProfileTypeVault, "production")
	if err != nil {
		return fmt.Errorf("failed to calculate Vault requirements: %w", err)
	}
	
	final := breakdown.FinalRequirements
	logger.Info("Vault requirements calculated",
		zap.Float64("cpu_cores", final.CPU),
		zap.Float64("memory_gb", final.Memory),
		zap.Float64("storage_gb", final.Storage),
		zap.Int("recommended_nodes", breakdown.NodeRecommendation.RecommendedNodes))
	
	// Example: Calculate requirements for a database cluster
	logger.Info("Calculating database cluster deployment")
	
	breakdown, err = CalculateServiceRequirements(rc, ServiceProfileTypeDatabase, "large")
	if err != nil {
		return fmt.Errorf("failed to calculate database requirements: %w", err)
	}
	
	final = breakdown.FinalRequirements
	logger.Info("Database requirements calculated",
		zap.Float64("cpu_cores", final.CPU),
		zap.Float64("memory_gb", final.Memory),
		zap.Float64("storage_gb", final.Storage),
		zap.Int("recommended_nodes", breakdown.NodeRecommendation.RecommendedNodes))
	
	return nil
}

// ExampleSystemValidation demonstrates how to validate current system against requirements
func ExampleSystemValidation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== SYSTEM VALIDATION EXAMPLE ===")
	
	// Example current system specs
	currentSystem := NodeSpecification{
		CPUCores:    8,
		MemoryGB:    32,
		DiskGB:      500,
		DiskType:    "ssd",
		NetworkGbps: 10,
	}
	
	logger.Info("Current system specs",
		zap.Int("cpu_cores", currentSystem.CPUCores),
		zap.Int("memory_gb", currentSystem.MemoryGB),
		zap.Int("disk_gb", currentSystem.DiskGB),
		zap.String("disk_type", currentSystem.DiskType))
	
	// Validate against small production Hecate
	errors, err := ValidateHecateRequirements(rc, "small_production", currentSystem)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	
	if len(errors) == 0 {
		logger.Info("System meets Hecate small production requirements")
	} else {
		logger.Warn("System does not meet requirements",
			zap.Int("validation_errors", len(errors)))
		for _, validationErr := range errors {
			logger.Warn("Validation error",
				zap.String("field", validationErr.Field),
				zap.String("message", validationErr.Message))
		}
	}
	
	// Validate against large production Hecate
	errors, err = ValidateHecateRequirements(rc, "large_production", currentSystem)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	
	if len(errors) == 0 {
		logger.Info("System meets Hecate large production requirements")
	} else {
		logger.Warn("System does not meet large production requirements",
			zap.Int("validation_errors", len(errors)))
	}
	
	return nil
}

// ExampleCustomCalculation demonstrates how to create a completely custom calculation
func ExampleCustomCalculation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== CUSTOM CALCULATION EXAMPLE ===")
	
	// Create a custom calculator for a specific workload
	calc := NewCalculatorV2(WorkloadMedium, "production")
	
	// Add OS baseline
	if err := calc.AddComponent("ubuntu_server_24.04"); err != nil {
		return fmt.Errorf("failed to add OS baseline: %w", err)
	}
	
	// Add specific components for a monitoring stack
	components := []string{
		"caddy_reverse_proxy", // For external access
		"postgresql_16",       // For metrics storage
		"redis_7",            // For caching
	}
	
	for _, component := range components {
		if err := calc.AddComponent(component); err != nil {
			return fmt.Errorf("failed to add component %s: %w", component, err)
		}
	}
	
	// Apply custom scaling factors for monitoring workload
	calc.SetCustomScalingFactors("postgresql_16", ScalingFactors{
		UserScaling:    0.005, // Less user scaling for monitoring
		RequestScaling: 0.002, // More request scaling for metrics
		DataScaling:    2.0,   // More data scaling for long retention
		LoadMultiplier: 1.8,   // Moderate load multiplier
		SafetyMargin:   1.6,   // Higher safety margin for reliability
	})
	
	// Define workload characteristics
	workload := WorkloadCharacteristics{
		ConcurrentUsers:   100,  // Monitoring users
		RequestsPerSecond: 50,   // Metrics collection rate
		DataGrowthGB:      100,  // Metrics data growth
		PeakMultiplier:    2.5,  // Peak monitoring load
		Type:              WorkloadMedium,
	}
	
	// Calculate requirements
	breakdown, err := calc.Calculate(rc, workload)
	if err != nil {
		return fmt.Errorf("calculation failed: %w", err)
	}
	
	final := breakdown.FinalRequirements
	logger.Info("Custom monitoring stack requirements",
		zap.Float64("cpu_cores", final.CPU),
		zap.Float64("memory_gb", final.Memory),
		zap.Float64("storage_gb", final.Storage),
		zap.Int("recommended_nodes", breakdown.NodeRecommendation.RecommendedNodes))
	
	// Generate human-readable report
	report := calc.GenerateHumanReadableReport()
	logger.Info("Generated custom calculation report",
		zap.Int("report_length", len(report)),
		zap.Int("calculation_steps", len(breakdown.CalculationSteps)),
		zap.Int("warnings", len(breakdown.Warnings)))
	
	return nil
}

// ExampleCompareProfiles demonstrates how to compare different deployment profiles
func ExampleCompareProfiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== PROFILE COMPARISON EXAMPLE ===")
	
	profiles := []string{"small_production", "medium_production", "large_production"}
	results := make(map[string]*CalculationBreakdown)
	
	// Calculate all profiles
	for _, profile := range profiles {
		breakdown, err := CalculateHecateRequirements(rc, profile)
		if err != nil {
			logger.Error("Failed to calculate profile", zap.String("profile", profile), zap.Error(err))
			continue
		}
		results[profile] = breakdown
	}
	
	// Compare results
	logger.Info("Profile comparison results:")
	for profile, breakdown := range results {
		final := breakdown.FinalRequirements
		nodes := breakdown.NodeRecommendation
		
		logger.Info("Profile summary",
			zap.String("profile", profile),
			zap.Float64("total_cpu", final.CPU),
			zap.Float64("total_memory", final.Memory),
			zap.Float64("total_storage", final.Storage),
			zap.Int("nodes", nodes.RecommendedNodes),
			zap.String("node_size", fmt.Sprintf("%d cores, %d GB", nodes.NodeSpecs.CPUCores, nodes.NodeSpecs.MemoryGB)))
	}
	
	// Find the most cost-effective option for specific requirements
	targetUsers := 150
	logger.Info("Finding best profile for target users", zap.Int("target_users", targetUsers))
	
	bestProfile := ""
	minResources := float64(999999)
	
	for profile, breakdown := range results {
		hecateProfile := HecateProfiles[profile]
		if hecateProfile.ExpectedUsers >= targetUsers {
			totalResources := breakdown.FinalRequirements.CPU + breakdown.FinalRequirements.Memory/10 // Simple scoring
			if totalResources < minResources {
				minResources = totalResources
				bestProfile = profile
			}
		}
	}
	
	if bestProfile != "" {
		logger.Info("Recommended profile for target users",
			zap.String("recommended_profile", bestProfile),
			zap.Int("target_users", targetUsers))
	} else {
		logger.Warn("No suitable profile found for target users", zap.Int("target_users", targetUsers))
	}
	
	return nil
}

// RunAllExamples runs all sizing examples
func RunAllExamples(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Running all sizing calculation examples")
	
	examples := []struct {
		name string
		fn   func(*eos_io.RuntimeContext) error
	}{
		{"Hecate Calculation", ExampleHecateCalculation},
		{"Custom Service Calculation", ExampleCustomServiceCalculation},
		{"System Validation", ExampleSystemValidation},
		{"Custom Calculation", ExampleCustomCalculation},
		{"Profile Comparison", ExampleCompareProfiles},
	}
	
	for _, example := range examples {
		logger.Info("Running example", zap.String("example", example.name))
		if err := example.fn(rc); err != nil {
			logger.Error("Example failed", zap.String("example", example.name), zap.Error(err))
			return fmt.Errorf("example %s failed: %w", example.name, err)
		}
		logger.Info("Example completed successfully", zap.String("example", example.name))
	}
	
	logger.Info("All sizing examples completed successfully")
	return nil
}