package sizing

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExampleBasicUsage demonstrates basic usage of the sizing calculator
func ExampleBasicUsage(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running basic sizing example")

	// Create a calculator with production config and medium workload
	config := EnvironmentConfigs["production"]
	workload := DefaultWorkloadProfiles["medium"]
	
	calc := NewCalculator(config, workload)
	
	// Add services for a typical web application
	services := []ServiceType{
		ServiceTypeProxy,
		ServiceTypeWebServer,
		ServiceTypeDatabase,
		ServiceTypeCache,
		ServiceTypeQueue,
		ServiceTypeWorker,
		ServiceTypeMonitoring,
		ServiceTypeLogging,
	}
	
	for _, service := range services {
		if err := calc.AddService(service); err != nil {
			return fmt.Errorf("failed to add service %s: %w", service, err)
		}
	}
	
	// Calculate infrastructure requirements
	result, err := calc.Calculate(rc)
	if err != nil {
		return fmt.Errorf("failed to calculate sizing: %w", err)
	}
	
	// Create a validator
	validator := NewValidator(result)
	
	// Generate and log the report
	report := validator.GenerateReport(rc)
	logger.Info("Sizing report generated", zap.String("report", report))
	
	// Also output as JSON for programmatic use
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result to JSON: %w", err)
	}
	logger.Info("Sizing result as JSON", zap.String("json", string(jsonData)))
	
	return nil
}

// ExampleCustomService demonstrates adding a custom service definition
func ExampleCustomService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running custom service sizing example")

	config := EnvironmentConfigs["staging"]
	workload := DefaultWorkloadProfiles["small"]
	
	calc := NewCalculator(config, workload)
	
	// Define a custom ML inference service
	mlService := ServiceDefinition{
		Name: "ML Inference Service",
		Type: ServiceType("ml_inference"),
		BaseRequirements: ResourceRequirements{
			CPU: CPURequirements{
				Cores: 8,
				Type:  "compute",
			},
			Memory: MemoryRequirements{
				GB:   32,
				Type: "high-performance",
			},
			Disk: DiskRequirements{
				GB:   200,
				Type: "nvme",
				IOPS: 20000,
			},
			Network: NetworkRequirements{
				BandwidthMbps: 1000,
				Latency:       "low",
				PublicIP:      true,
			},
		},
		ScalingFactor:    0.01,  // Scale with load
		LoadFactor:       1.8,   // Higher load factor for ML workloads
		RedundancyFactor: 2,     // At least 2 instances for HA
		Description:      "Custom ML inference service with GPU requirements",
		Ports:            []int{8080, 8081},
	}
	
	// Add the custom service
	calc.AddCustomService(mlService)
	
	// Add the custom service along with supporting services
	if err := calc.AddService(ServiceType("ml_inference")); err != nil {
		return fmt.Errorf("failed to add ML service: %w", err)
	}
	if err := calc.AddService(ServiceTypeProxy); err != nil {
		return fmt.Errorf("failed to add proxy: %w", err)
	}
	if err := calc.AddService(ServiceTypeMonitoring); err != nil {
		return fmt.Errorf("failed to add monitoring: %w", err)
	}
	
	// Calculate requirements
	result, err := calc.Calculate(rc)
	if err != nil {
		return fmt.Errorf("failed to calculate sizing: %w", err)
	}
	
	logger.Info("Custom service sizing completed",
		zap.Float64("total_cpu", result.TotalCPUCores),
		zap.Float64("total_memory_gb", result.TotalMemoryGB),
		zap.Int("node_count", result.NodeCount))
	
	return nil
}

// ExampleValidation demonstrates validating actual infrastructure against requirements
func ExampleValidation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running infrastructure validation example")

	// First, calculate requirements
	config := EnvironmentConfigs["production"]
	workload := DefaultWorkloadProfiles["large"]
	
	calc := NewCalculator(config, workload)
	calc.AddService(ServiceTypeWebServer)
	calc.AddService(ServiceTypeDatabase)
	calc.AddService(ServiceTypeCache)
	
	result, err := calc.Calculate(rc)
	if err != nil {
		return fmt.Errorf("failed to calculate sizing: %w", err)
	}
	
	validator := NewValidator(result)
	
	// Validate a potential node configuration
	proposedNode := NodeSpecification{
		CPUCores:    16,
		MemoryGB:    64,
		DiskGB:      1000,
		DiskType:    "nvme",
		NetworkGbps: 10,
	}
	
	validationErrors, err := validator.ValidateNodeCapacity(rc, proposedNode)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	
	if len(validationErrors) > 0 {
		logger.Warn("Node validation found issues", zap.Int("error_count", len(validationErrors)))
		for _, ve := range validationErrors {
			logger.Warn("Validation error",
				zap.String("field", ve.Field),
				zap.String("message", ve.Message))
		}
	} else {
		logger.Info("Proposed node meets all requirements")
	}
	
	// Validate a cluster configuration
	cluster := []NodeSpecification{
		proposedNode,
		proposedNode,
		proposedNode,
	}
	
	if err := validator.ValidateClusterCapacity(rc, cluster); err != nil {
		logger.Error("Cluster validation failed", zap.Error(err))
		return err
	}
	
	logger.Info("Cluster configuration validated successfully")
	
	// Validate service placement
	placements := map[string][]string{
		string(ServiceTypeWebServer): {"node1", "node2", "node3"},
		string(ServiceTypeDatabase):  {"node1", "node2", "node3"},
		string(ServiceTypeCache):     {"node1", "node2"},
	}
	
	if err := validator.ValidateServiceDistribution(rc, placements); err != nil {
		logger.Error("Service distribution validation failed", zap.Error(err))
		return err
	}
	
	logger.Info("Service distribution validated successfully")
	
	return nil
}

// ExampleCostOptimization demonstrates using the sizing calculator for cost optimization
func ExampleCostOptimization(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running cost optimization example")

	workload := DefaultWorkloadProfiles["medium"]
	services := []ServiceType{
		ServiceTypeWebServer,
		ServiceTypeDatabase,
		ServiceTypeCache,
		ServiceTypeQueue,
		ServiceTypeWorker,
	}
	
	// Compare costs across different environments and providers
	environments := []string{"development", "staging", "production"}
	providers := []string{"aws", "hetzner", "digitalocean"}
	
	type CostComparison struct {
		Environment string
		Provider    string
		NodeCount   int
		MonthlyCost float64
		YearlyCost  float64
	}
	
	var comparisons []CostComparison
	
	for _, env := range environments {
		for _, provider := range providers {
			config := EnvironmentConfigs[env]
			config.Provider = provider
			
			calc := NewCalculator(config, workload)
			
			// Add all services
			for _, service := range services {
				if err := calc.AddService(service); err != nil {
					return fmt.Errorf("failed to add service: %w", err)
				}
			}
			
			// Calculate sizing
			result, err := calc.Calculate(rc)
			if err != nil {
				return fmt.Errorf("failed to calculate sizing: %w", err)
			}
			
			comparison := CostComparison{
				Environment: env,
				Provider:    provider,
				NodeCount:   result.NodeCount,
				MonthlyCost: result.EstimatedCost.Monthly,
				YearlyCost:  result.EstimatedCost.Yearly,
			}
			comparisons = append(comparisons, comparison)
			
			logger.Info("Cost calculation completed",
				zap.String("environment", env),
				zap.String("provider", provider),
				zap.Float64("monthly_cost", result.EstimatedCost.Monthly),
				zap.Int("node_count", result.NodeCount))
		}
	}
	
	// Find the most cost-effective option for production
	var bestOption *CostComparison
	for i := range comparisons {
		if comparisons[i].Environment == "production" {
			if bestOption == nil || comparisons[i].MonthlyCost < bestOption.MonthlyCost {
				bestOption = &comparisons[i]
			}
		}
	}
	
	if bestOption != nil {
		logger.Info("Most cost-effective production option",
			zap.String("provider", bestOption.Provider),
			zap.Float64("monthly_cost", bestOption.MonthlyCost),
			zap.Float64("yearly_cost", bestOption.YearlyCost),
			zap.Int("node_count", bestOption.NodeCount))
	}
	
	return nil
}