package sizing

import (
	"fmt"
	"math"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Calculator performs infrastructure sizing calculations
type Calculator struct {
	config          SizingConfig
	workloadProfile WorkloadProfile
	services        []ServiceType
	customServices  map[ServiceType]ServiceDefinition
}

// NewCalculator creates a new sizing calculator
func NewCalculator(config SizingConfig, workload WorkloadProfile) *Calculator {
	return &Calculator{
		config:          config,
		workloadProfile: workload,
		services:        []ServiceType{},
		customServices:  make(map[ServiceType]ServiceDefinition),
	}
}

// AddService adds a service to be sized
func (c *Calculator) AddService(serviceType ServiceType) error {
	if _, exists := ServiceDefinitions[serviceType]; !exists {
		if _, exists := c.customServices[serviceType]; !exists {
			return fmt.Errorf("unknown service type: %s", serviceType)
		}
	}
	c.services = append(c.services, serviceType)
	return nil
}

// AddCustomService adds a custom service definition
func (c *Calculator) AddCustomService(service ServiceDefinition) {
	c.customServices[service.Type] = service
}

// Calculate performs the sizing calculation
func (c *Calculator) Calculate(rc *eos_io.RuntimeContext) (*SizingResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting infrastructure sizing calculation",
		zap.String("environment", c.config.Environment),
		zap.Int("service_count", len(c.services)))

	result := &SizingResult{
		Services:        make(map[string]ServiceRequirements),
		Warnings:        []string{},
		Recommendations: []string{},
	}

	// Calculate requirements for each service
	for _, serviceType := range c.services {
		service := c.getServiceDefinition(serviceType)
		if service == nil {
			continue
		}

		logger.Debug("Calculating requirements for service",
			zap.String("service", string(serviceType)))

		serviceReq := c.calculateServiceRequirements(service)
		result.Services[string(serviceType)] = serviceReq

		// Aggregate totals
		result.TotalCPUCores += serviceReq.TotalResources.CPU.Cores
		result.TotalMemoryGB += serviceReq.TotalResources.Memory.GB
		result.TotalDiskGB += serviceReq.TotalResources.Disk.GB
		if serviceReq.TotalResources.Network.BandwidthMbps > 0 {
			result.TotalBandwidthMbps += serviceReq.TotalResources.Network.BandwidthMbps
		}
	}

	// Apply environment-specific adjustments
	c.applyEnvironmentAdjustments(result)

	// Calculate node requirements
	c.calculateNodeRequirements(result)

	// Add warnings and recommendations
	c.generateWarningsAndRecommendations(result)

	// Estimate costs if provider is specified
	if c.config.Provider != "" {
		c.estimateCosts(result)
	}

	logger.Info("Sizing calculation completed",
		zap.Float64("total_cpu_cores", result.TotalCPUCores),
		zap.Float64("total_memory_gb", result.TotalMemoryGB),
		zap.Float64("total_disk_gb", result.TotalDiskGB),
		zap.Int("node_count", result.NodeCount))

	return result, nil
}

// getServiceDefinition retrieves a service definition
func (c *Calculator) getServiceDefinition(serviceType ServiceType) *ServiceDefinition {
	if service, exists := c.customServices[serviceType]; exists {
		return &service
	}
	if service, exists := ServiceDefinitions[serviceType]; exists {
		return &service
	}
	return nil
}

// calculateServiceRequirements calculates requirements for a single service
func (c *Calculator) calculateServiceRequirements(service *ServiceDefinition) ServiceRequirements {
	// Calculate scaling factor based on workload
	scalingMultiplier := c.calculateScalingMultiplier(service)

	// Calculate resource requirements
	perInstance := ResourceRequirements{
		CPU: CPURequirements{
			Cores:      service.BaseRequirements.CPU.Cores * scalingMultiplier,
			Type:       service.BaseRequirements.CPU.Type,
			BurstRatio: service.BaseRequirements.CPU.BurstRatio,
		},
		Memory: MemoryRequirements{
			GB:        service.BaseRequirements.Memory.GB * scalingMultiplier,
			Type:      service.BaseRequirements.Memory.Type,
			SwapRatio: service.BaseRequirements.Memory.SwapRatio,
		},
		Disk: DiskRequirements{
			GB:         service.BaseRequirements.Disk.GB + c.calculateDiskGrowth(service),
			Type:       service.BaseRequirements.Disk.Type,
			IOPS:       service.BaseRequirements.Disk.IOPS,
			Throughput: service.BaseRequirements.Disk.Throughput,
		},
	}

	// Copy network requirements if present
	if service.BaseRequirements.Network.BandwidthMbps > 0 {
		perInstance.Network = NetworkRequirements{
			BandwidthMbps: int(float64(service.BaseRequirements.Network.BandwidthMbps) * scalingMultiplier),
			Latency:       service.BaseRequirements.Network.Latency,
			PublicIP:      service.BaseRequirements.Network.PublicIP,
		}
	}

	// Apply load factor
	perInstance.CPU.Cores *= service.LoadFactor
	perInstance.Memory.GB *= service.LoadFactor

	// Calculate instance count based on redundancy
	instanceCount := service.RedundancyFactor
	if instanceCount < 1 {
		instanceCount = 1
	}

	// Calculate total resources
	totalResources := ResourceRequirements{
		CPU: CPURequirements{
			Cores:      perInstance.CPU.Cores * float64(instanceCount),
			Type:       perInstance.CPU.Type,
			BurstRatio: perInstance.CPU.BurstRatio,
		},
		Memory: MemoryRequirements{
			GB:        perInstance.Memory.GB * float64(instanceCount),
			Type:      perInstance.Memory.Type,
			SwapRatio: perInstance.Memory.SwapRatio,
		},
		Disk: DiskRequirements{
			GB:         perInstance.Disk.GB * float64(instanceCount),
			Type:       perInstance.Disk.Type,
			IOPS:       perInstance.Disk.IOPS * instanceCount,
			Throughput: perInstance.Disk.Throughput * instanceCount,
		},
	}

	if perInstance.Network.BandwidthMbps > 0 {
		totalResources.Network = NetworkRequirements{
			BandwidthMbps: perInstance.Network.BandwidthMbps * instanceCount,
			Latency:       perInstance.Network.Latency,
			PublicIP:      perInstance.Network.PublicIP,
		}
	}

	// Determine placement strategy
	placementStrategy := c.determinePlacementStrategy(service)

	return ServiceRequirements{
		Service:           *service,
		InstanceCount:     instanceCount,
		TotalResources:    totalResources,
		PerInstance:       perInstance,
		PlacementStrategy: placementStrategy,
	}
}

// calculateScalingMultiplier calculates the scaling multiplier based on workload
func (c *Calculator) calculateScalingMultiplier(service *ServiceDefinition) float64 {
	baseMultiplier := 1.0

	switch service.Type {
	case ServiceTypeWebServer, ServiceTypeProxy:
		baseMultiplier = float64(c.workloadProfile.ConcurrentUsers) * service.ScalingFactor
	case ServiceTypeDatabase:
		baseMultiplier = float64(c.workloadProfile.RequestsPerSecond) * service.ScalingFactor
	case ServiceTypeCache:
		baseMultiplier = float64(c.workloadProfile.ConcurrentUsers) * service.ScalingFactor * c.workloadProfile.ReadWriteRatio
	case ServiceTypeQueue:
		baseMultiplier = float64(c.workloadProfile.RequestsPerSecond) * service.ScalingFactor * (1 - c.workloadProfile.ReadWriteRatio)
	case ServiceTypeWorker:
		baseMultiplier = float64(c.workloadProfile.RequestsPerSecond) * service.ScalingFactor
	case ServiceTypeMonitoring, ServiceTypeLogging:
		baseMultiplier = float64(len(c.services)) * service.ScalingFactor
	case ServiceTypeStorage:
		baseMultiplier = c.workloadProfile.DataGrowthRate * service.ScalingFactor
	default:
		baseMultiplier = float64(c.workloadProfile.ConcurrentUsers) * service.ScalingFactor
	}

	// Apply peak-to-average ratio
	baseMultiplier *= c.workloadProfile.PeakToAverageRatio

	// Ensure minimum multiplier
	if baseMultiplier < 1.0 {
		baseMultiplier = 1.0
	}

	return baseMultiplier
}

// calculateDiskGrowth calculates additional disk space needed for data growth
func (c *Calculator) calculateDiskGrowth(service *ServiceDefinition) float64 {
	if service.Type != ServiceTypeDatabase && service.Type != ServiceTypeStorage && service.Type != ServiceTypeLogging {
		return 0
	}

	// Calculate months of retention
	months := c.workloadProfile.RetentionPeriod.Hours() / (24 * 30)
	
	// Calculate total growth
	totalGrowth := c.workloadProfile.DataGrowthRate * months

	// Apply compression factor for certain services
	if service.Type == ServiceTypeLogging {
		totalGrowth *= 0.3 // Assume 70% compression
	}

	return totalGrowth
}

// applyEnvironmentAdjustments applies environment-specific adjustments
func (c *Calculator) applyEnvironmentAdjustments(result *SizingResult) {
	// Apply overprovision ratio
	result.TotalCPUCores *= c.config.OverprovisionRatio
	result.TotalMemoryGB *= c.config.OverprovisionRatio
	
	// Apply growth buffer
	result.TotalCPUCores *= c.config.GrowthBuffer
	result.TotalMemoryGB *= c.config.GrowthBuffer
	result.TotalDiskGB *= c.config.GrowthBuffer

	// Round up to reasonable values
	result.TotalCPUCores = math.Ceil(result.TotalCPUCores*2) / 2 // Round to nearest 0.5
	result.TotalMemoryGB = math.Ceil(result.TotalMemoryGB)
	result.TotalDiskGB = math.Ceil(result.TotalDiskGB/10) * 10 // Round to nearest 10
}

// calculateNodeRequirements calculates the number and specs of nodes required
func (c *Calculator) calculateNodeRequirements(result *SizingResult) {
	// Determine optimal node size based on requirements
	optimalCPU := math.Min(
		math.Max(result.TotalCPUCores/4, float64(c.config.MinNodeSize.CPUCores)),
		float64(c.config.MaxNodeSize.CPUCores),
	)
	
	optimalMemory := math.Min(
		math.Max(result.TotalMemoryGB/4, float64(c.config.MinNodeSize.MemoryGB)),
		float64(c.config.MaxNodeSize.MemoryGB),
	)

	// Round to standard sizes
	nodeCPU := c.roundToStandardSize(int(optimalCPU), []int{2, 4, 8, 16, 32, 64})
	nodeMemory := c.roundToStandardSize(int(optimalMemory), []int{4, 8, 16, 32, 64, 128, 256})

	// Calculate disk per node
	avgDiskPerNode := result.TotalDiskGB / 4
	nodeDisk := c.roundToStandardSize(int(avgDiskPerNode), []int{50, 100, 200, 500, 1000, 2000})

	// Ensure minimums are met
	if nodeCPU < c.config.MinNodeSize.CPUCores {
		nodeCPU = c.config.MinNodeSize.CPUCores
	}
	if nodeMemory < c.config.MinNodeSize.MemoryGB {
		nodeMemory = c.config.MinNodeSize.MemoryGB
	}
	if nodeDisk < c.config.MinNodeSize.DiskGB {
		nodeDisk = c.config.MinNodeSize.DiskGB
	}

	// Calculate number of nodes needed
	nodesByCPU := int(math.Ceil(result.TotalCPUCores / float64(nodeCPU)))
	nodesByMemory := int(math.Ceil(result.TotalMemoryGB / float64(nodeMemory)))
	nodesByDisk := int(math.Ceil(result.TotalDiskGB / float64(nodeDisk)))

	nodeCount := c.maxInt(nodesByCPU, nodesByMemory, nodesByDisk)
	
	// Ensure minimum node count for HA
	if c.config.Environment == "production" && nodeCount < 3 {
		nodeCount = 3
	} else if c.config.Environment == "staging" && nodeCount < 2 {
		nodeCount = 2
	}

	// Calculate utilization
	cpuUtilization := (result.TotalCPUCores / (float64(nodeCount) * float64(nodeCPU))) * 100
	memUtilization := (result.TotalMemoryGB / (float64(nodeCount) * float64(nodeMemory))) * 100

	// Determine disk type based on requirements
	diskType := "ssd"
	hasHighIOPS := false
	for _, serviceReq := range result.Services {
		if serviceReq.Service.BaseRequirements.Disk.Type == "nvme" {
			diskType = "nvme"
			hasHighIOPS = true
			break
		}
		if serviceReq.Service.BaseRequirements.Disk.IOPS > 5000 {
			hasHighIOPS = true
		}
	}
	if hasHighIOPS && diskType != "nvme" {
		diskType = "ssd"
	}

	// Network speed
	networkGbps := 1
	if result.TotalBandwidthMbps > 1000 {
		networkGbps = 10
	}
	if result.TotalBandwidthMbps > 10000 {
		networkGbps = 40
	}

	result.NodeCount = nodeCount
	result.NodeSpecs = NodeSpecification{
		CPUCores:       nodeCPU,
		MemoryGB:       nodeMemory,
		DiskGB:         nodeDisk,
		DiskType:       diskType,
		NetworkGbps:    networkGbps,
		Provider:       c.config.Provider,
		CPUUtilization: cpuUtilization,
		MemUtilization: memUtilization,
	}
}

// determinePlacementStrategy determines the placement strategy for a service
func (c *Calculator) determinePlacementStrategy(service *ServiceDefinition) string {
	switch service.Type {
	case ServiceTypeDatabase:
		if service.RedundancyFactor > 1 {
			return "anti-affinity" // Spread replicas across nodes
		}
		return "dedicated" // Dedicated node for single instance
	case ServiceTypeCache:
		return "anti-affinity" // Spread for HA
	case ServiceTypeProxy:
		return "edge" // Place on edge nodes
	case ServiceTypeMonitoring, ServiceTypeLogging:
		return "dedicated" // Dedicated monitoring nodes
	default:
		return "balanced" // Default balanced placement
	}
}

// roundToStandardSize rounds a value to the nearest standard size
func (c *Calculator) roundToStandardSize(value int, sizes []int) int {
	for _, size := range sizes {
		if value <= size {
			return size
		}
	}
	return sizes[len(sizes)-1]
}

// maxInt returns the maximum of multiple integers
func (c *Calculator) maxInt(values ...int) int {
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

// generateWarningsAndRecommendations generates warnings and recommendations
func (c *Calculator) generateWarningsAndRecommendations(result *SizingResult) {
	// Check CPU utilization
	if result.NodeSpecs.CPUUtilization > 80 {
		result.Warnings = append(result.Warnings, 
			fmt.Sprintf("High CPU utilization (%.1f%%) - consider adding more nodes", result.NodeSpecs.CPUUtilization))
	}

	// Check memory utilization
	if result.NodeSpecs.MemUtilization > 85 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("High memory utilization (%.1f%%) - consider larger nodes or more nodes", result.NodeSpecs.MemUtilization))
	}

	// Check node count
	if result.NodeCount < 3 && c.config.Environment == "production" {
		result.Recommendations = append(result.Recommendations,
			"Consider at least 3 nodes for production high availability")
	}

	// Check disk type for databases
	for _, serviceReq := range result.Services {
		if serviceReq.Service.Type == ServiceTypeDatabase && result.NodeSpecs.DiskType == "hdd" {
			result.Recommendations = append(result.Recommendations,
				"Consider SSD or NVMe storage for database workloads")
		}
	}

	// Check for monitoring
	hasMonitoring := false
	for _, serviceType := range c.services {
		if serviceType == ServiceTypeMonitoring {
			hasMonitoring = true
			break
		}
	}
	if !hasMonitoring && c.config.Environment == "production" {
		result.Recommendations = append(result.Recommendations,
			"Consider adding monitoring services for production environments")
	}

	// Check bandwidth requirements
	if result.TotalBandwidthMbps > 0 {
		bandwidthPerNode := result.TotalBandwidthMbps / result.NodeCount
		if bandwidthPerNode > result.NodeSpecs.NetworkGbps*1000 {
			result.Warnings = append(result.Warnings,
				"Network bandwidth requirements exceed node capacity")
		}
	}
}

// estimateCosts estimates infrastructure costs based on provider
func (c *Calculator) estimateCosts(result *SizingResult) {
	// Basic cost estimation - would need provider-specific pricing data
	costPerCore := 20.0    // $20/core/month estimate
	costPerGB := 5.0       // $5/GB RAM/month estimate
	costPerTBDisk := 50.0  // $50/TB disk/month estimate

	if c.config.Provider == "hetzner" {
		costPerCore = 15.0
		costPerGB = 3.0
		costPerTBDisk = 40.0
	}

	monthlyCost := (result.TotalCPUCores * costPerCore) +
		(result.TotalMemoryGB * costPerGB) +
		(result.TotalDiskGB / 1000 * costPerTBDisk)

	result.EstimatedCost = CostEstimate{
		Monthly:  monthlyCost,
		Yearly:   monthlyCost * 12,
		Currency: "USD",
		Breakdown: map[string]float64{
			"compute": result.TotalCPUCores * costPerCore,
			"memory":  result.TotalMemoryGB * costPerGB,
			"storage": result.TotalDiskGB / 1000 * costPerTBDisk,
		},
	}
}