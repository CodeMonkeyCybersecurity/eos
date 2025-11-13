package sizing

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Validator provides runtime validation of sizing requirements
type Validator struct {
	requirements *SizingResult
}

// NewValidator creates a new sizing validator
func NewValidator(requirements *SizingResult) *Validator {
	return &Validator{
		requirements: requirements,
	}
}

// ValidateNodeCapacity validates if a node meets the sizing requirements
func (v *Validator) ValidateNodeCapacity(rc *eos_io.RuntimeContext, node NodeSpecification) ([]ValidationError, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating node capacity against sizing requirements")

	var errors []ValidationError

	// Check if node meets minimum requirements
	minReq := v.requirements.NodeSpecs

	if node.CPUCores < minReq.CPUCores {
		errors = append(errors, ValidationError{
			Field:   "cpu_cores",
			Message: fmt.Sprintf("Node has %d CPU cores, but %d are required", node.CPUCores, minReq.CPUCores),
		})
	}

	if node.MemoryGB < minReq.MemoryGB {
		errors = append(errors, ValidationError{
			Field:   "memory_gb",
			Message: fmt.Sprintf("Node has %d GB memory, but %d GB are required", node.MemoryGB, minReq.MemoryGB),
		})
	}

	if node.DiskGB < minReq.DiskGB {
		errors = append(errors, ValidationError{
			Field:   "disk_gb",
			Message: fmt.Sprintf("Node has %d GB disk, but %d GB are required", node.DiskGB, minReq.DiskGB),
		})
	}

	// Check disk type compatibility
	if !v.isDiskTypeCompatible(node.DiskType, minReq.DiskType) {
		errors = append(errors, ValidationError{
			Field:   "disk_type",
			Message: fmt.Sprintf("Node has %s disk, but %s or better is required", node.DiskType, minReq.DiskType),
		})
	}

	if node.NetworkGbps < minReq.NetworkGbps {
		errors = append(errors, ValidationError{
			Field:   "network_gbps",
			Message: fmt.Sprintf("Node has %d Gbps network, but %d Gbps is required", node.NetworkGbps, minReq.NetworkGbps),
		})
	}

	if len(errors) > 0 {
		logger.Warn("Node validation failed",
			zap.Int("error_count", len(errors)))
		return errors, nil
	}

	logger.Info("Node meets sizing requirements")
	return nil, nil
}

// ValidateServicePlacement validates if a service can be placed on a node
func (v *Validator) ValidateServicePlacement(rc *eos_io.RuntimeContext, serviceType ServiceType, nodeResources ResourceRequirements) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating service placement on node",
		zap.String("service", string(serviceType)))

	// Get service requirements
	serviceReq, exists := v.requirements.Services[string(serviceType)]
	if !exists {
		return fmt.Errorf("no sizing requirements found for service: %s", serviceType)
	}

	// Check CPU requirements
	if nodeResources.CPU.Cores < serviceReq.PerInstance.CPU.Cores {
		return fmt.Errorf(
			"insufficient CPU: node has %.2f cores available, service requires %.2f cores",
			nodeResources.CPU.Cores, serviceReq.PerInstance.CPU.Cores)
	}

	// Check memory requirements
	if nodeResources.Memory.GB < serviceReq.PerInstance.Memory.GB {
		return fmt.Errorf(
			"insufficient memory: node has %.2f GB available, service requires %.2f GB",
			nodeResources.Memory.GB, serviceReq.PerInstance.Memory.GB)
	}

	// Check disk requirements
	if nodeResources.Disk.GB < serviceReq.PerInstance.Disk.GB {
		return fmt.Errorf(
			"insufficient disk: node has %.2f GB available, service requires %.2f GB",
			nodeResources.Disk.GB, serviceReq.PerInstance.Disk.GB)
	}

	// Check disk IOPS if specified
	if serviceReq.PerInstance.Disk.IOPS > 0 && nodeResources.Disk.IOPS < serviceReq.PerInstance.Disk.IOPS {
		logger.Warn("Node disk IOPS may be insufficient",
			zap.Int("required_iops", serviceReq.PerInstance.Disk.IOPS),
			zap.Int("available_iops", nodeResources.Disk.IOPS))
	}

	// Check network bandwidth if specified
	if serviceReq.PerInstance.Network.BandwidthMbps > 0 &&
		nodeResources.Network.BandwidthMbps < serviceReq.PerInstance.Network.BandwidthMbps {
		return fmt.Errorf(
			"insufficient network bandwidth: node has %d Mbps available, service requires %d Mbps",
			nodeResources.Network.BandwidthMbps, serviceReq.PerInstance.Network.BandwidthMbps)
	}

	logger.Info("Service can be placed on node")
	return nil
}

// ValidateClusterCapacity validates if the entire cluster meets requirements
func (v *Validator) ValidateClusterCapacity(rc *eos_io.RuntimeContext, nodes []NodeSpecification) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating cluster capacity",
		zap.Int("node_count", len(nodes)))

	// Calculate total cluster resources
	var totalCPU, totalMemory, totalDisk float64
	var totalBandwidth int

	for _, node := range nodes {
		totalCPU += float64(node.CPUCores)
		totalMemory += float64(node.MemoryGB)
		totalDisk += float64(node.DiskGB)
		totalBandwidth += node.NetworkGbps * 1000 // Convert to Mbps
	}

	// Check against requirements
	var errors []string

	if totalCPU < v.requirements.TotalCPUCores {
		errors = append(errors, fmt.Sprintf(
			"insufficient CPU: cluster has %.2f cores, but %.2f are required",
			totalCPU, v.requirements.TotalCPUCores))
	}

	if totalMemory < v.requirements.TotalMemoryGB {
		errors = append(errors, fmt.Sprintf(
			"insufficient memory: cluster has %.2f GB, but %.2f GB are required",
			totalMemory, v.requirements.TotalMemoryGB))
	}

	if totalDisk < v.requirements.TotalDiskGB {
		errors = append(errors, fmt.Sprintf(
			"insufficient disk: cluster has %.2f GB, but %.2f GB are required",
			totalDisk, v.requirements.TotalDiskGB))
	}

	if v.requirements.TotalBandwidthMbps > 0 && totalBandwidth < v.requirements.TotalBandwidthMbps {
		errors = append(errors, fmt.Sprintf(
			"insufficient bandwidth: cluster has %d Mbps, but %d Mbps are required",
			totalBandwidth, v.requirements.TotalBandwidthMbps))
	}

	if len(nodes) < v.requirements.NodeCount {
		errors = append(errors, fmt.Sprintf(
			"insufficient nodes: cluster has %d nodes, but %d are recommended",
			len(nodes), v.requirements.NodeCount))
	}

	if len(errors) > 0 {
		return fmt.Errorf(
			"cluster capacity validation failed:\n%s",
			strings.Join(errors, "\n"))
	}

	logger.Info("Cluster meets sizing requirements")
	return nil
}

// ValidateServiceDistribution validates if services are properly distributed
func (v *Validator) ValidateServiceDistribution(rc *eos_io.RuntimeContext, placements map[string][]string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating service distribution across nodes")

	for serviceType, nodes := range placements {
		serviceReq, exists := v.requirements.Services[serviceType]
		if !exists {
			continue
		}

		// Check instance count
		if len(nodes) < serviceReq.InstanceCount {
			logger.Warn("Service has fewer instances than recommended",
				zap.String("service", serviceType),
				zap.Int("actual", len(nodes)),
				zap.Int("recommended", serviceReq.InstanceCount))
		}

		// Check placement strategy
		if err := v.validatePlacementStrategy(serviceReq, nodes); err != nil {
			return fmt.Errorf("placement strategy validation failed for %s: %w", serviceType, err)
		}
	}

	logger.Info("Service distribution validation completed")
	return nil
}

// validatePlacementStrategy validates if placement follows the recommended strategy
func (v *Validator) validatePlacementStrategy(serviceReq ServiceRequirements, nodes []string) error {
	switch serviceReq.PlacementStrategy {
	case "anti-affinity":
		// Check if instances are on different nodes
		nodeSet := make(map[string]bool)
		for _, node := range nodes {
			if nodeSet[node] {
				return fmt.Errorf(
					"service %s requires anti-affinity but multiple instances found on node %s",
					serviceReq.Service.Name, node)
			}
			nodeSet[node] = true
		}

	case "dedicated":
		// Check if service has dedicated nodes (simplified check)
		if len(nodes) > 0 && serviceReq.Service.RedundancyFactor == 1 {
			// For single instance services, warn if sharing nodes with critical services
			// This would require additional context about what else is on the nodes
			// TODO: Implement node sharing checks
			_ = nodes
		}

	case "edge":
		// Edge placement validation would require knowledge of node roles
		// Skip for now

	case "balanced":
		// Balanced placement is the default, no special validation needed
	}

	return nil
}

// isDiskTypeCompatible checks if a disk type meets or exceeds requirements
func (v *Validator) isDiskTypeCompatible(actual, required string) bool {
	// Disk type hierarchy: hdd < ssd < nvme
	hierarchy := map[string]int{
		"hdd":  1,
		"ssd":  2,
		"nvme": 3,
	}

	actualLevel, actualOK := hierarchy[strings.ToLower(actual)]
	requiredLevel, requiredOK := hierarchy[strings.ToLower(required)]

	if !actualOK || !requiredOK {
		// Unknown disk type, assume compatible
		return true
	}

	return actualLevel >= requiredLevel
}

// GenerateReport generates a human-readable validation report
func (v *Validator) GenerateReport(rc *eos_io.RuntimeContext) string {
	var report strings.Builder

	report.WriteString("Infrastructure Sizing Requirements\n")
	report.WriteString("==================================\n\n")

	// Summary
	report.WriteString(fmt.Sprintf("Environment: %s\n", v.requirements.NodeSpecs.Provider))
	report.WriteString(fmt.Sprintf("Total CPU Cores: %.1f\n", v.requirements.TotalCPUCores))
	report.WriteString(fmt.Sprintf("Total Memory: %.1f GB\n", v.requirements.TotalMemoryGB))
	report.WriteString(fmt.Sprintf("Total Disk: %.1f GB\n", v.requirements.TotalDiskGB))
	report.WriteString(fmt.Sprintf("Recommended Nodes: %d\n\n", v.requirements.NodeCount))

	// Node Specifications
	report.WriteString("Recommended Node Specifications:\n")
	report.WriteString("--------------------------------\n")
	report.WriteString(fmt.Sprintf("CPU Cores: %d\n", v.requirements.NodeSpecs.CPUCores))
	report.WriteString(fmt.Sprintf("Memory: %d GB\n", v.requirements.NodeSpecs.MemoryGB))
	report.WriteString(fmt.Sprintf("Disk: %d GB (%s)\n", v.requirements.NodeSpecs.DiskGB, v.requirements.NodeSpecs.DiskType))
	report.WriteString(fmt.Sprintf("Network: %d Gbps\n\n", v.requirements.NodeSpecs.NetworkGbps))

	// Service Requirements
	report.WriteString("Service Requirements:\n")
	report.WriteString("--------------------\n")
	for serviceType, req := range v.requirements.Services {
		report.WriteString(fmt.Sprintf("\n%s (%s):\n", req.Service.Name, serviceType))
		report.WriteString(fmt.Sprintf("  Instances: %d\n", req.InstanceCount))
		report.WriteString(fmt.Sprintf("  CPU per instance: %.2f cores\n", req.PerInstance.CPU.Cores))
		report.WriteString(fmt.Sprintf("  Memory per instance: %.2f GB\n", req.PerInstance.Memory.GB))
		report.WriteString(fmt.Sprintf("  Disk per instance: %.2f GB\n", req.PerInstance.Disk.GB))
		report.WriteString(fmt.Sprintf("  Placement: %s\n", req.PlacementStrategy))
	}

	// Warnings and Recommendations
	if len(v.requirements.Warnings) > 0 {
		report.WriteString("\nWarnings:\n")
		report.WriteString("---------\n")
		for _, warning := range v.requirements.Warnings {
			report.WriteString(fmt.Sprintf("- %s\n", warning))
		}
	}

	if len(v.requirements.Recommendations) > 0 {
		report.WriteString("\nRecommendations:\n")
		report.WriteString("----------------\n")
		for _, rec := range v.requirements.Recommendations {
			report.WriteString(fmt.Sprintf("- %s\n", rec))
		}
	}

	// Cost Estimate
	if v.requirements.EstimatedCost.Monthly > 0 {
		report.WriteString("\nEstimated Cost:\n")
		report.WriteString("---------------\n")
		report.WriteString(fmt.Sprintf("Monthly: $%.2f %s\n", v.requirements.EstimatedCost.Monthly, v.requirements.EstimatedCost.Currency))
		report.WriteString(fmt.Sprintf("Yearly: $%.2f %s\n", v.requirements.EstimatedCost.Yearly, v.requirements.EstimatedCost.Currency))
		if len(v.requirements.EstimatedCost.Breakdown) > 0 {
			report.WriteString("Breakdown:\n")
			for component, cost := range v.requirements.EstimatedCost.Breakdown {
				report.WriteString(fmt.Sprintf("  %s: $%.2f\n", component, cost))
			}
		}
	}

	return report.String()
}
