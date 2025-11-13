package sizing

import (
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceMapping maps Eos command services to sizing service types
type ServiceMapping struct {
	// The sizing service type
	ServiceType ServiceType

	// Optional custom workload profile (if nil, uses default based on environment)
	WorkloadProfile *WorkloadProfile

	// Additional services that should be checked together
	RelatedServices []ServiceType

	// Whether to skip preflight checks (useful for optional services)
	SkipPreflight bool

	// Whether to skip postflight checks
	SkipPostflight bool
}

// CommandServiceMappings provides default mappings for common Eos create commands
var CommandServiceMappings = map[string]ServiceMapping{
	// Infrastructure services
	"nomad": {
		ServiceType: ServiceTypeOrchestrator,
		RelatedServices: []ServiceType{
			ServiceTypeContainer, // Docker runtime
		},
	},
	"consul": {
		ServiceType:     ServiceTypeOrchestrator, // Consul acts as service mesh
		RelatedServices: []ServiceType{},
	},
	"vault": {
		ServiceType:     ServiceTypeVault,
		RelatedServices: []ServiceType{},
	},

	// Container services
	"k3s": {
		ServiceType: ServiceTypeOrchestrator,
		RelatedServices: []ServiceType{
			ServiceTypeContainer,
			ServiceTypeProxy, // Traefik
		},
	},
	"containers": {
		ServiceType:     ServiceTypeContainer,
		RelatedServices: []ServiceType{},
	},

	// Database services
	"postgres": {
		ServiceType:     ServiceTypeDatabase,
		RelatedServices: []ServiceType{},
	},

	// Monitoring stack
	"grafana": {
		ServiceType: ServiceTypeMonitoring,
		RelatedServices: []ServiceType{
			ServiceTypeDatabase, // For storing metrics
		},
	},
	"prometheus": {
		ServiceType:     ServiceTypeMonitoring,
		RelatedServices: []ServiceType{},
	},
	"loki": {
		ServiceType:     ServiceTypeLogging,
		RelatedServices: []ServiceType{},
	},

	// Security services
	"hecate": {
		ServiceType: ServiceTypeProxy,
		RelatedServices: []ServiceType{
			ServiceTypeDatabase, // For configuration storage
		},
	},
	"wazuh": {
		ServiceType: ServiceTypeMonitoring,
		RelatedServices: []ServiceType{
			ServiceTypeDatabase,
			ServiceTypeQueue, // For event processing
		},
	},
	"fail2ban": {
		ServiceType:     ServiceTypeMonitoring,
		RelatedServices: []ServiceType{},
		WorkloadProfile: &WorkloadProfile{
			Name:              "Security Monitoring",
			ConcurrentUsers:   10,
			RequestsPerSecond: 100,
			// Minimal resource requirements
		},
	},

	// Storage services
	"minio": {
		ServiceType:     ServiceTypeStorage,
		RelatedServices: []ServiceType{},
	},
	"storage": {
		ServiceType:     ServiceTypeStorage,
		RelatedServices: []ServiceType{},
	},

	// Web services
	"jenkins": {
		ServiceType: ServiceTypeWebServer,
		RelatedServices: []ServiceType{
			ServiceTypeDatabase,
		},
	},
	"mattermost": {
		ServiceType: ServiceTypeWebServer,
		RelatedServices: []ServiceType{
			ServiceTypeDatabase,
		},
	},
}

// DeploymentFunc represents a function that performs the actual deployment
type DeploymentFunc func(rc *eos_io.RuntimeContext) error

// RunWithSizingChecks wraps a deployment function with preflight and postflight sizing checks
func RunWithSizingChecks(rc *eos_io.RuntimeContext, serviceName string, deployFunc DeploymentFunc) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Look up service mapping
	mapping, exists := CommandServiceMappings[strings.ToLower(serviceName)]
	if !exists {
		// If no mapping exists, run deployment without sizing checks
		logger.Debug("No sizing mapping found for service, proceeding without checks",
			zap.String("service", serviceName))
		return deployFunc(rc)
	}

	logger.Info("Running deployment with sizing checks",
		zap.String("service", serviceName),
		zap.String("service_type", string(mapping.ServiceType)))

	// Collect all services to check
	servicesToCheck := []ServiceType{mapping.ServiceType}
	servicesToCheck = append(servicesToCheck, mapping.RelatedServices...)

	// Determine workload profile
	workload := DefaultWorkloadProfiles["medium"] // Default
	if mapping.WorkloadProfile != nil {
		workload = *mapping.WorkloadProfile
	}

	// Run preflight checks
	if !mapping.SkipPreflight {
		logger.Info("Running preflight resource validation")
		if err := PreflightCheck(rc, servicesToCheck, workload); err != nil {
			// User errors (like choosing not to proceed) should propagate up
			var userErr *eos_err.UserError
			if errors.As(err, &userErr) {
				return err
			}
			// For other errors, give option to continue
			logger.Warn("Preflight checks encountered issues", zap.Error(err))
		}
	}

	// Execute the deployment
	logger.Info("Executing deployment function")
	if err := deployFunc(rc); err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}

	// Run postflight validation
	if !mapping.SkipPostflight {
		logger.Info("Running postflight resource validation")
		if err := PostflightValidation(rc, servicesToCheck); err != nil {
			logger.Warn("Postflight validation detected issues", zap.Error(err))
			// Don't fail the deployment, just warn
		}
	}

	return nil
}

// CreateServiceMapping creates a custom service mapping
func CreateServiceMapping(serviceType ServiceType, opts ...ServiceMappingOption) ServiceMapping {
	mapping := ServiceMapping{
		ServiceType:     serviceType,
		RelatedServices: []ServiceType{},
	}

	for _, opt := range opts {
		opt(&mapping)
	}

	return mapping
}

// ServiceMappingOption configures a ServiceMapping
type ServiceMappingOption func(*ServiceMapping)

// WithWorkloadProfile sets a custom workload profile
func WithWorkloadProfile(profile WorkloadProfile) ServiceMappingOption {
	return func(sm *ServiceMapping) {
		sm.WorkloadProfile = &profile
	}
}

// WithRelatedServices adds related services to check
func WithRelatedServices(services ...ServiceType) ServiceMappingOption {
	return func(sm *ServiceMapping) {
		sm.RelatedServices = append(sm.RelatedServices, services...)
	}
}

// WithoutPreflight disables preflight checks
func WithoutPreflight() ServiceMappingOption {
	return func(sm *ServiceMapping) {
		sm.SkipPreflight = true
	}
}

// WithoutPostflight disables postflight checks
func WithoutPostflight() ServiceMappingOption {
	return func(sm *ServiceMapping) {
		sm.SkipPostflight = true
	}
}

// RegisterServiceMapping registers a custom service mapping
func RegisterServiceMapping(serviceName string, mapping ServiceMapping) {
	CommandServiceMappings[strings.ToLower(serviceName)] = mapping
}

// Example integration patterns for create commands:

/*
Example 1: Basic Integration (using existing mapping)

func runCreateNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Parse configuration
    config := parseNomadConfig(cmd)

    // Run deployment with sizing checks
    return sizing.RunWithSizingChecks(rc, "nomad", func(rc *eos_io.RuntimeContext) error {
        // Your existing deployment logic
        if err := nomad.Install(rc, config); err != nil {
            return err
        }
        if err := nomad.Configure(rc, config); err != nil {
            return err
        }
        return nomad.Verify(rc, config)
    })
}

Example 2: Custom Service Mapping

func runCreateCustomService(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Create custom mapping
    mapping := sizing.CreateServiceMapping(
        sizing.ServiceTypeWebServer,
        sizing.WithWorkloadProfile(sizing.WorkloadProfile{
            Name:              "API Gateway",
            ConcurrentUsers:   5000,
            RequestsPerSecond: 1000,
        }),
        sizing.WithRelatedServices(
            sizing.ServiceTypeDatabase,
            sizing.ServiceTypeCache,
        ),
    )

    // Register it
    sizing.RegisterServiceMapping("custom-api", mapping)

    // Run with checks
    return sizing.RunWithSizingChecks(rc, "custom-api", func(rc *eos_io.RuntimeContext) error {
        // Deployment logic
        return deployCustomAPI(rc)
    })
}

Example 3: Conditional Sizing Checks

func runCreateService(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Check if user wants sizing validation
    skipSizing, _ := cmd.Flags().GetBool("skip-sizing")

    if skipSizing {
        // Direct deployment without checks
        return deployService(rc, config)
    }

    // With sizing checks
    return sizing.RunWithSizingChecks(rc, "service", func(rc *eos_io.RuntimeContext) error {
        return deployService(rc, config)
    })
}

Example 4: Manual Preflight/Postflight

func runCreateComplex(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)

    // Manual preflight for more control
    services := []sizing.ServiceType{
        sizing.ServiceTypeDatabase,
        sizing.ServiceTypeCache,
        sizing.ServiceTypeWebServer,
    }

    workload := sizing.DefaultWorkloadProfiles["large"]

    // Run preflight
    if err := sizing.PreflightCheck(rc, services, workload); err != nil {
        if eos_err.IsUserError(err) {
            return err
        }
        logger.Warn("Proceeding despite preflight warnings", zap.Error(err))
    }

    // Deploy components
    if err := deployDatabase(rc); err != nil {
        return err
    }
    if err := deployCache(rc); err != nil {
        return err
    }
    if err := deployWebServer(rc); err != nil {
        return err
    }

    // Run postflight
    return sizing.PostflightValidation(rc, services)
}
*/
