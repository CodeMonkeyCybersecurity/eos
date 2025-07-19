package sizing

// Example integration with Eos commands
//
// This file demonstrates how the sizing package can be integrated into Eos commands
// for infrastructure planning and validation.
//
// The new integration.go provides a simpler way to add sizing checks to create commands.

/*
Example command implementation:

// cmd/read_sizing.go
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/sizing"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var readSizingCmd = &cobra.Command{
	Use:   "sizing",
	Short: "Calculate infrastructure sizing requirements",
	Long: `Calculate infrastructure sizing requirements based on workload profiles
and service requirements. This helps determine optimal node counts, resource
allocations, and validates existing infrastructure.`,
	RunE: eos_cli.Wrap(runReadSizing),
}

var (
	sizingEnvironment string
	sizingWorkload    string
	sizingServices    []string
	sizingOutputJSON  bool
	sizingProvider    string
)

func init() {
	readCmd.AddCommand(readSizingCmd)

	readSizingCmd.Flags().StringVar(&sizingEnvironment, "environment", "production",
		"Environment profile: development, staging, production")
	readSizingCmd.Flags().StringVar(&sizingWorkload, "workload", "medium",
		"Workload profile: small, medium, large")
	readSizingCmd.Flags().StringSliceVar(&sizingServices, "services", 
		[]string{"web_server", "database", "cache"},
		"Services to include in sizing calculation")
	readSizingCmd.Flags().BoolVar(&sizingOutputJSON, "json", false,
		"Output results as JSON")
	readSizingCmd.Flags().StringVar(&sizingProvider, "provider", "",
		"Cloud provider for cost estimation: aws, hetzner, digitalocean")
}

func runReadSizing(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get configuration
	config, exists := sizing.EnvironmentConfigs[sizingEnvironment]
	if !exists {
		return fmt.Errorf("unknown environment: %s", sizingEnvironment)
	}

	workload, exists := sizing.DefaultWorkloadProfiles[sizingWorkload]
	if !exists {
		return fmt.Errorf("unknown workload profile: %s", sizingWorkload)
	}

	// Set provider if specified
	if sizingProvider != "" {
		config.Provider = sizingProvider
	}

	// Create calculator
	calc := sizing.NewCalculator(config, workload)

	// Add services
	for _, svc := range sizingServices {
		serviceType := sizing.ServiceType(svc)
		if err := calc.AddService(serviceType); err != nil {
			logger.Warn("Failed to add service",
				"service", svc,
				"error", err)
			continue
		}
	}

	// Calculate sizing
	result, err := calc.Calculate(rc)
	if err != nil {
		return fmt.Errorf("sizing calculation failed: %w", err)
	}

	// Output results
	if sizingOutputJSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Create validator for report generation
		validator := sizing.NewValidator(result)
		report := validator.GenerateReport(rc)
		fmt.Println(report)
	}

	return nil
}
*/

/*
Example validation command:

// cmd/read_validate_sizing.go
package cmd

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/sizing"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var readValidateSizingCmd = &cobra.Command{
	Use:   "validate-sizing",
	Short: "Validate current infrastructure against sizing requirements",
	Long: `Validate that the current infrastructure meets the calculated sizing
requirements. This checks node capacity, service distribution, and cluster capacity.`,
	RunE: eos_cli.Wrap(runReadValidateSizing),
}

func init() {
	readCmd.AddCommand(readValidateSizingCmd)

	// Add flags for specifying current infrastructure
	// This is simplified - in reality would read from inventory/API
}

func runReadValidateSizing(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// First calculate requirements (simplified - might load from file)
	config := sizing.EnvironmentConfigs["production"]
	workload := sizing.DefaultWorkloadProfiles["medium"]
	
	calc := sizing.NewCalculator(config, workload)
	calc.AddService(sizing.ServiceTypeWebServer)
	calc.AddService(sizing.ServiceTypeDatabase)
	calc.AddService(sizing.ServiceTypeCache)
	
	result, err := calc.Calculate(rc)
	if err != nil {
		return fmt.Errorf("failed to calculate requirements: %w", err)
	}

	validator := sizing.NewValidator(result)

	// Get current infrastructure (simplified example)
	currentNodes := []sizing.NodeSpecification{
		{CPUCores: 16, MemoryGB: 64, DiskGB: 500, DiskType: "ssd", NetworkGbps: 10},
		{CPUCores: 16, MemoryGB: 64, DiskGB: 500, DiskType: "ssd", NetworkGbps: 10},
		{CPUCores: 8, MemoryGB: 32, DiskGB: 250, DiskType: "ssd", NetworkGbps: 10},
	}

	// Validate cluster capacity
	if err := validator.ValidateClusterCapacity(rc, currentNodes); err != nil {
		logger.Error("Cluster validation failed", "error", err)
		return err
	}

	// Validate individual nodes
	for i, node := range currentNodes {
		validationErrors, err := validator.ValidateNodeCapacity(rc, node)
		if err != nil {
			return fmt.Errorf("node %d validation error: %w", i+1, err)
		}

		if len(validationErrors) > 0 {
			logger.Warn("Node validation issues found",
				"node", i+1,
				"errors", len(validationErrors))
			for _, ve := range validationErrors {
				fmt.Printf("Node %d - %s: %s\n", i+1, ve.Field, ve.Message)
			}
		}
	}

	logger.Info("Infrastructure validation completed successfully")
	return nil
}
*/

/*
NEW: Simple integration using RunWithSizingChecks:

// In cmd/create/nomad.go - Add sizing checks with one function call
func runCreateNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse configuration as before
	config := parseNomadConfig(cmd)
	
	// Wrap your deployment logic with sizing checks
	return sizing.RunWithSizingChecks(rc, "nomad", func(rc *eos_io.RuntimeContext) error {
		// Your existing deployment logic stays exactly the same
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Nomad installation with SaltStack")
		
		if err := nomad.CheckPrerequisites(rc); err != nil {
			return err
		}
		
		if err := nomad.InstallWithSaltStack(rc, config); err != nil {
			return err
		}
		
		if err := nomad.Configure(rc, config); err != nil {
			return err
		}
		
		return nomad.Verify(rc, config)
	})
}

// In cmd/create/postgres.go - Database with sizing
func runCreatePostgres(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	config := parsePostgresConfig(cmd)
	
	// Database deployments automatically get sizing checks
	return sizing.RunWithSizingChecks(rc, "postgres", func(rc *eos_io.RuntimeContext) error {
		return postgres.Deploy(rc, config)
	})
}

// In cmd/create/custom_service.go - Custom sizing requirements
func runCreateCustomService(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Register a custom service mapping if needed
	sizing.RegisterServiceMapping("myapp", sizing.CreateServiceMapping(
		sizing.ServiceTypeWebServer,
		sizing.WithWorkloadProfile(sizing.WorkloadProfile{
			Name:              "Heavy API",
			ConcurrentUsers:   10000,
			RequestsPerSecond: 5000,
		}),
		sizing.WithRelatedServices(
			sizing.ServiceTypeDatabase,
			sizing.ServiceTypeCache,
			sizing.ServiceTypeQueue,
		),
	))
	
	// Use the registered mapping
	return sizing.RunWithSizingChecks(rc, "myapp", func(rc *eos_io.RuntimeContext) error {
		return deployMyApp(rc)
	})
}

// Optional: Skip sizing for development environments
func runCreateService(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	env, _ := cmd.Flags().GetString("environment")
	
	// Skip sizing in dev environments
	if env == "development" {
		return deployService(rc, config)
	}
	
	// Use sizing for staging/production
	return sizing.RunWithSizingChecks(rc, "service", func(rc *eos_io.RuntimeContext) error {
		return deployService(rc, config)
	})
}
*/

/*
Example integration with deployment commands:

// In cmd/create_infrastructure.go
func validateSizingBeforeDeployment(rc *eos_io.RuntimeContext, services []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Load sizing requirements
	config := sizing.EnvironmentConfigs[deployEnvironment]
	workload := sizing.DefaultWorkloadProfiles[deployWorkloadSize]
	
	calc := sizing.NewCalculator(config, workload)
	
	// Add requested services
	for _, svc := range services {
		if err := calc.AddService(sizing.ServiceType(svc)); err != nil {
			return fmt.Errorf("invalid service %s: %w", svc, err)
		}
	}
	
	// Calculate requirements
	result, err := calc.Calculate(rc)
	if err != nil {
		return fmt.Errorf("sizing calculation failed: %w", err)
	}
	
	// Show requirements to user
	validator := sizing.NewValidator(result)
	report := validator.GenerateReport(rc)
	
	logger.Info("Infrastructure requirements calculated")
	fmt.Println(report)
	
	// Prompt for confirmation
	fmt.Print("\nDo you want to proceed with deployment? (yes/no): ")
	response, err := eos_io.ReadInput(rc)
	if err != nil {
		return err
	}
	
	if response != "yes" {
		return fmt.Errorf("deployment cancelled by user")
	}
	
	// Store sizing requirements for later validation
	sizingData, _ := json.Marshal(result)
	if err := os.WriteFile("/tmp/eos-sizing-requirements.json", sizingData, 0644); err != nil {
		logger.Warn("Failed to save sizing requirements", "error", err)
	}
	
	return nil
}
*/